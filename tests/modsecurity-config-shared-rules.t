#!/usr/bin/perl

#
# ModSecurity, http://www.modsecurity.org/
# Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
#
# You may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# If any of the files related to licensing are missing or if you have any
# other questions related to licensing please contact Trustwave Holdings, Inc.
# directly using the email address security@modsecurity.org.
#


# Tests for ModSecurity-nginx connector (rules set inheritance).

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    modsecurity on;

    server {
        listen       127.0.0.1:8080;
        server_name  norules;

        location / {
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  rules;

        modsecurity_rules '
            SecRuleEngine On
            SecRule ARGS:what "@streq bad" "id:81,phase:1,deny,status:403"
        ';

        location /inherit {
        }

        location /own {
            modsecurity_rules '
                SecRule ARGS:what "@streq worse" "id:82,phase:1,deny,status:403"
            ';
        }

        location /off {
            modsecurity off;
        }

        location /nested {
            modsecurity_rules '
                SecRule ARGS:what "@streq nested" "id:83,phase:1,deny,status:403"
            ';

            location /nested/deep {
            }
        }
    }
}

EOF

$t->write_file('index.html', 'INDEX');
for my $d (qw(inherit own off nested nested/deep sub ifblk lim)) {
	mkdir($t->testdir() . "/$d");
	$t->write_file("/$d/index.html", 'INDEX');
}
$t->run();
$t->plan(17);

###############################################################################

like(http_get_host('norules', '/index.html?what=bad'), qr/INDEX/, 'enabled without any rules passes');
like(http_get_host('rules', '/inherit/index.html?what=bad'), qr/^HTTP.*403/, 'inherited (shared) server rules block');
like(http_get_host('rules', '/inherit/index.html?what=ok'), qr/INDEX/, 'inherited (shared) server rules pass');
like(http_get_host('rules', '/own/index.html?what=bad'), qr/^HTTP.*403/, 'own set still contains parent rules');
like(http_get_host('rules', '/own/index.html?what=worse'), qr/^HTTP.*403/, 'own set contains own rules');
like(http_get_host('rules', '/own/index.html?what=ok'), qr/INDEX/, 'own set passes clean request');
like(http_get_host('rules', '/off/index.html?what=bad'), qr/INDEX/, 'modsecurity off location passes');
like(http_get_host('rules', '/nested/deep/index.html?what=bad'), qr/^HTTP.*403/, 'deep location shares parent merged set (server rule)');
like(http_get_host('rules', '/nested/deep/index.html?what=nested'), qr/^HTTP.*403/, 'deep location shares parent merged set (location rule)');
like(http_get_host('rules', '/nested/deep/index.html?what=worse'), qr/INDEX/, 'deep location does not see sibling rules');
like(http_get_host('rules', '/nested/deep/index.html?what=ok'), qr/INDEX/, 'deep location passes clean request');

###############################################################################

# Rules at the http level, shared down into blocks that have none of their own,
# including the implicit configurations created by "if" and "limit_except".

$t->stop();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    modsecurity on;
    modsecurity_rules '
        SecRuleEngine On
        SecRule ARGS:what "@streq http" "id:80,phase:1,deny,status:403"
    ';

    server {
        listen       127.0.0.1:8080;
        server_name  norules;

        location / {
        }

        location /sub {
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  rules;

        location /ifblk {
            modsecurity_rules '
                SecRule ARGS:what "@streq ifblk" "id:85,phase:1,deny,status:403"
            ';

            if ($arg_x = "1") {
                add_header X-If "1";
            }
        }

        location /lim {
            modsecurity_rules '
                SecRule ARGS:what "@streq lim" "id:86,phase:1,deny,status:403"
            ';

            limit_except GET {
                allow all;
            }
        }
    }
}

EOF

$t->run();

like(http_get_host('norules', '/index.html?what=http'), qr/^HTTP.*403/, 'http rules shared into a server without rules');
like(http_get_host('norules', '/index.html?what=ok'), qr/INDEX/, 'http rules shared into a server without rules, clean request');
like(http_get_host('norules', '/sub/index.html?what=http'), qr/^HTTP.*403/, 'http rules shared two levels down');
like(http_get_host('rules', '/ifblk/index.html?x=1&what=ifblk'), qr/^HTTP.*403/, 'if block shares the rules of its location');
like(http_post_host('rules', '/lim/index.html?what=lim'), qr/^HTTP.*403/, 'limit_except shares the rules of its location');
like(http_post_host('rules', '/lim/index.html?what=ok'), qr/^HTTP.*405/, 'limit_except passes clean request');

###############################################################################

sub http_get_host {
	my ($host, $url) = @_;
	return http(<<EOF);
GET $url HTTP/1.0
Host: $host

EOF
}

sub http_post_host {
	my ($host, $url) = @_;
	return http(<<EOF);
POST $url HTTP/1.0
Host: $host
Content-Length: 3

x=1
EOF
}

###############################################################################
