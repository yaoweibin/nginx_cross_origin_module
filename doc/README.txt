Name
    nginx_cross_origin_module - support cross origin resource sharing
    protocol in Nginx

Status
    This module is at its very early phase of development and considered
    highly experimental. But you're encouraged to test it out on your side
    and report any quirks that you experience.

    We need your help! If you find this module useful and/or interesting,
    please consider joining the development!

Synopsis
  a simple example:
    http {

        cors on;
        cors_max_age     3600;
        cors_origin_list unbounded;
        cors_method_list unbounded;
        cors_header_list unbounded;
        cors_safe_methods GET OPTIONS;

        server {
            listen       80;
            server_name  localhost;

            location / {
                root   html;
                index  index.html index.htm;
            }
        }
    }

Description
    This module can process the cross-origin resource sharing Javascript
    request with this protocol (<http://www.w3.org/TR/cors/>). This module
    follows the protocol version of 20100727.

Directives
  cors
    syntax: *cors on|off;*

    default: *cors off;*

    context: *http, server, location*

    Enable this module

  cors_origin_list
    syntax: *cors_origin_list unbounded|origin_list;*

    default: *none*

    context: *http, server, location*

    You can specify a list of origins consisting of zero or more origins
    that are allowed. The format is like this:

    cors_origin_list http://www.foo.com http://new.bar.net
    http://example.org;

  cors_method_list
    syntax: *cors_method_list unbounded|method_list;*

    default: *none*

    context: *http, server, location*

    You can specify a list of methods consisting of zero or more methods
    that are supported by the resource. It's for the preflight request. The
    format is like this:

    cors_method_list GET POST PUT;

  cors_header_list
    syntax: *cors_header_list unbounded|header_list;*

    default: *none*

    context: *http, server, location*

    You can specify a list of headers consisting of zero or more field names
    that are supported by the resource.

  cors_safe_methods
    syntax: *cors_safe_methods methods;*

    default: *cors_safe_methods GET OPTIONS*

    context: *http, server, location*

    With the Security consideration in section 5.3 of this protocol, only
    GET and OPTIONS methods are allowed by default. It's for the actual
    request. It keeps your site safe when you allow unbounded method. .
    Generally, you can specify the same methods as the cors_method_list.

  cors_expose_header_list
    syntax: *cors_expose_header_list header_list;*

    default: *none*

    context: *http, server, location*

    You can specify a list of headers the resource wants to expose the API
    of the CORS API.

  cors_max_age
    syntax: *cors_max_age time;*

    default: *none*

    context: *http, server, location*

    You can specify the amount of seconds the user agent is allowed to cache
    the result of the request.

  cors_support_credential
    syntax: *cors_support_credential on|off;*

    default: *cors_support_credential off;*

    context: *http, server, location*

    You can specify if the resource supports credentials.

  cors_preflight_response
    syntax: *cors_preflight_response response_body;*

    default: *none*

    context: *http, server, location*

    You can specify the content of preflight response body. It supports
    variable in the string.

  cors_preflight_response_type
    syntax: *cors_preflight_response_type mime_type;*

    default: *cors_preflight_response_type text/plain;*

    context: *http, server, location*

    You can specify the content type of preflight response body.

Installation
    Download the latest version of the release tarball of this module from
    github (<http://github.com/yaoweibin/nginx_cross_origin_module>)

    Grab the nginx source code from nginx.org (<http://nginx.org/>), for
    example, the version 1.0.8 (see nginx compatibility), and then build the
    source with this module:

        $ wget 'http://nginx.org/download/nginx-1.0.8.tar.gz'
        $ tar -xzvf nginx-1.0.8.tar.gz
        $ cd nginx-1.0.8/

        $ ./configure --add-module=/path/to/nginx_cross_origin_module

        $ make
        $ make install

Compatibility
    My test bed 1.0.8.

TODO
Known Issues
    Developing

Changelogs
  v0.1
    first release

Authors
    Weibin Yao(姚伟斌) *yaoweibin AT gmail DOT com*

License
    This README template is from agentzh (<http://github.com/agentzh>).

    This module is licensed under the BSD license.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met:

    Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
    IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
    TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
    PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
    TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

