# vi:ft=

use lib 'lib';
use Test::Nginx::Socket 'no_plan';

no_long_string();

run_tests();

__DATA__

=== TEST 1: failed headers_load validation must block the body, not just relabel
the status code
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /test {
        headers_save $saved x-original;
        headers_load $saved x-original wrong-value;
        echo hi;
    }
--- more_headers
X-Original: alpha
--- request
GET /test
--- error_code: 403
--- response_body_unlike: hi


=== TEST 2: matching headers_load validation still lets the response through
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /test {
        headers_save $saved x-original;
        headers_load $saved x-original alpha;
        echo hi;
    }
--- more_headers
X-Original: alpha
--- request
GET /test
--- response_body
hi
