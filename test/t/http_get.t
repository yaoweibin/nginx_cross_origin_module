#
#===============================================================================
#
#         FILE:  sample.t
#
#  DESCRIPTION: test 
#
#        FILES:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Weibin Yao (http://yaoweibin.cn/), yaoweibin@gmail.com
#      COMPANY:  
#      VERSION:  1.0
#      CREATED:  03/02/2010 03:18:28 PM
#     REVISION:  ---
#===============================================================================


# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the first time request
--- http_config
cors on;
cors_max_age     3600;
cors_origin_list unbounded;
cors_method_list unbounded;
cors_header_list unbounded;
cors_expose_header_list AAAA Expires BBB CCC;
cors_support_credential on;
cors_preflight_response "Foo Bar!";

--- config
    location / {
        proxy_set_header Host blog.163.com;
        proxy_pass http://blog.163.com;
    }
--- more_headers
Host: www.ruby-lang.org
--- request
GET /
--- response_headers_like
Foo Bar!
