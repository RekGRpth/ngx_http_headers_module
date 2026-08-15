# vi:ft=

use lib 'lib';
use Test::Nginx::Socket 'no_plan';

no_long_string();

run_tests();

__DATA__

=== TEST 1: headers_load value validation must be case-sensitive, matching
HTTP header value semantics - a differently-cased value must be rejected
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /test {
        headers_save $saved x-original;
        headers_load $saved x-original Secret123;
        echo hi;
    }
--- more_headers
X-Original: SECRET123
--- request
GET /test
--- error_code: 403
--- response_body_unlike: hi


=== TEST 2: an exact-case match still passes
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /test {
        headers_save $saved x-original;
        headers_load $saved x-original Secret123;
        echo hi;
    }
--- more_headers
X-Original: Secret123
--- request
GET /test
--- response_body
hi
