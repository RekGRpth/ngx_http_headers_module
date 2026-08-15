# vi:ft=
#
# Covers the two bounds-check break points in ngx_http_headers_filter's
# parsing loop that headers_load_malformed.t doesn't reach (that one only
# exercises the value-length check).

use lib 'lib';
use Test::Nginx::Socket 'no_plan';

no_long_string();

run_tests();

__DATA__

=== TEST 1: a claimed key length that exceeds the remaining buffer must
discard the record (not just an oversized value length)
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config eval
my $payload = pack("Q<", 100) . ("A" x 8);
qq{
    location /test {
        set \$x "$payload";
        headers_load \$x;
        echo hi;
        echo "[\$http_x]";
    }
}
--- request
GET /test
--- response_body
hi
[]


=== TEST 2: a key that leaves too little room for even the value's own
length field must discard the record
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config eval
my $payload = pack("Q<", 1) . "x" . ("A" x 4);
qq{
    location /test {
        set \$x "$payload";
        headers_load \$x;
        echo hi;
        echo "[\$http_x]";
    }
}
--- request
GET /test
--- response_body
hi
[]
