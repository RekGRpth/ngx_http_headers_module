# vi:ft=

use lib 'lib';
use Test::Nginx::Socket 'no_plan';

no_long_string();

run_tests();

__DATA__

=== TEST 1: a saved header value at or above 65536 bytes must round-trip intact
through headers_save/headers_load instead of desyncing the length-prefixed
record parsing
--- main_config
    load_module /etc/nginx/modules/ndk_http_module.so;
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    large_client_header_buffers 4 256k;
    location /test {
        headers_save $saved x-original;
        headers_load $saved;
        echo hi;
        echo $http_x_original;
    }
--- more_headers eval
"X-Original: " . ("A" x 70000)
--- request
GET /test
--- response_body eval
"hi\n" . ("A" x 70000) . ", " . ("A" x 70000) . "\n"
