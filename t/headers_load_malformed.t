# vi:ft=

use lib 'lib';
use Test::Nginx::Socket 'no_plan';

no_long_string();

run_tests();

__DATA__

=== TEST 1: headers_load reading a claimed record length that exceeds the
actual variable data (e.g. because $x wasn't produced by headers_save) must
discard the record instead of trusting the length for later use
--- main_config
    load_module /etc/nginx/modules/ngx_http_echo_module.so;
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config eval
my $payload = pack("Q<", 1) . "x" . pack("Q<", 10_000_000) . "V";
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
