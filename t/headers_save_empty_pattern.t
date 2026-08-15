# vi:ft=

use lib 'lib';
use Test::Nginx::Socket 'no_plan';

no_long_string();

run_tests();

__DATA__

=== TEST 1: an empty headers_save pattern argument must not crash the worker
(elts[j].data[elts[j].len - 1] used to read one byte before the argument
buffer when elts[j].len == 0) and real patterns still match correctly
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /test {
        headers_save $saved x-original "";
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
