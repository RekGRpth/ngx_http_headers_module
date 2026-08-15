# vi:ft=

use lib 'lib';
use Test::Nginx::Socket 'no_plan';

no_long_string();

run_tests();

__DATA__

=== TEST 1: a child location without its own headers_load must still inherit
the parent's key/value validation, not just the variable index
--- main_config
    load_module /etc/nginx/modules/ndk_http_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /outer {
        headers_save $saved x-original;
        headers_load $saved x-original expected;
        location /outer/inner {
            headers_save $saved x-original;
            echo hi;
        }
    }
--- more_headers
X-Original: wrong-value
--- request
GET /outer/inner
--- error_code: 403
--- response_body_unlike: hi


=== TEST 2: same inherited validation lets a matching value through
--- main_config
    load_module /etc/nginx/modules/ndk_http_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /outer {
        headers_save $saved x-original;
        headers_load $saved x-original expected;
        location /outer/inner {
            headers_save $saved x-original;
            echo hi;
        }
    }
--- more_headers
X-Original: expected
--- request
GET /outer/inner
--- response_body
hi
