# vi:ft=

use lib 'lib';
use Test::Nginx::Socket 'no_plan';

no_long_string();

run_tests();

__DATA__

=== TEST 1: headers_load with only the 2-arg form (no validation pattern anywhere
in the config) must still enable the filter and inject the saved header
--- main_config
    load_module /etc/nginx/modules/ndk_http_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /test {
        headers_save $saved x-original;
        headers_load $saved;
        echo hi;
        echo $http_x_original;
    }
--- more_headers
X-Original: alpha
--- request
GET /test
--- response_body
hi
alpha, alpha


=== TEST 2: control - without headers_load the header is not duplicated
--- main_config
    load_module /etc/nginx/modules/ndk_http_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /test {
        headers_save $saved x-original;
        echo hi;
        echo $http_x_original;
    }
--- more_headers
X-Original: alpha
--- request
GET /test
--- response_body
hi
alpha
