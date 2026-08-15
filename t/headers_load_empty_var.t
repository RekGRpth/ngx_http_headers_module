# vi:ft=

use lib 'lib';
use Test::Nginx::Socket 'no_plan';

no_long_string();

run_tests();

__DATA__

=== TEST 1: headers_load with validation configured must deny (fail closed)
when its variable is empty, not silently pass the request through
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /test {
        set $empty "";
        headers_load $empty x-original expected;
        echo hi;
    }
--- request
GET /test
--- error_code: 403
--- response_body_unlike: hi


=== TEST 2: control - without a key/value pattern, an empty variable still
just passes through (no validation was requested)
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /test {
        set $empty "";
        headers_load $empty;
        echo hi;
    }
--- request
GET /test
--- response_body
hi
