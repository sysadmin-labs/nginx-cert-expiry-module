use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: a threshold that is not a time is refused
--- http_config
    cert_expiry_warn fortnight;
--- config
    location = /t { return 200 ok; }
--- must_die
--- error_log
invalid value



=== TEST 2: an interval that is not a time is refused
--- http_config
    cert_expiry_check sometimes;
--- config
    location = /t { return 200 ok; }
--- must_die
--- error_log
invalid value



=== TEST 3: the defaults need no configuration at all
--- config
    location = /t { return 200 ok; }
--- request
GET /t
--- response_body chomp
ok
--- no_error_log
[alert]



=== TEST 4: both directives are accepted
--- http_config
    cert_expiry_warn 30d;
    cert_expiry_check 6h;
--- config
    location = /t { return 200 ok; }
--- request
GET /t
--- response_body chomp
ok
--- no_error_log
[alert]



=== TEST 5: the variable is empty without a handshake
--- config
    location = /t { return 200 "[$ssl_expiry_days]"; }
--- request
GET /t
--- response_body chomp
[]
--- no_error_log
[alert]



=== TEST 6: a server without a certificate is no reason to complain
--- config
    location = /t { return 200 ok; }
--- request
GET /t
--- response_body chomp
ok
--- no_error_log
cert_expiry
