# vi:ft=
#
# Regression tests for the config-time validation paths in
# ngx_http_headers_save_conf/ngx_http_headers_load_conf, none of which were
# exercised by any other test in this suite.

use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each() * 2 * blocks();

no_shuffle();
run_tests();

__DATA__

=== TEST 1: headers_save without a leading $ on the variable name fails to start
--- main_config
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /t1 { headers_save token x-original; }
--- must_die
--- suppress_stderr
--- error_log
"headers_save" directive invalid variable name


=== TEST 2: headers_load without a leading $ on the variable name fails to start
--- main_config
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /t2 { headers_load token; }
--- must_die
--- suppress_stderr
--- error_log
"headers_load" directive invalid variable name


=== TEST 3: headers_save with an empty variable name ($) fails to start
--- main_config
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /t3 { headers_save $ x-original; }
--- must_die
--- suppress_stderr
--- error_log
invalid variable name "$"


=== TEST 4: headers_load with an empty variable name ($) fails to start
--- main_config
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /t4 { headers_load $; }
--- must_die
--- suppress_stderr
--- error_log
"headers_load" directive invalid variable


=== TEST 5: headers_load with a malformed complex value fails to start
--- main_config
    load_module /etc/nginx/modules/ngx_http_headers_module.so;
--- config
    location /t5 { headers_load $t x-original "${"; }
--- must_die
--- suppress_stderr
--- error_log
"headers_load" directive ngx_http_compile_complex_value != NGX_OK
