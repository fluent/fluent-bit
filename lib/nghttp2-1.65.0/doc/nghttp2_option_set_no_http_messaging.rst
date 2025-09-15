
nghttp2_option_set_no_http_messaging
====================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_no_http_messaging(nghttp2_option *option, int val)

    
    By default, nghttp2 library enforces subset of HTTP Messaging rules
    described in `HTTP/2 specification, section 8
    <https://tools.ietf.org/html/rfc7540#section-8>`_.  See
    :ref:`http-messaging` section for details.  For those applications
    who use nghttp2 library as non-HTTP use, give nonzero to *val* to
    disable this enforcement.  Please note that disabling this feature
    does not change the fundamental client and server model of HTTP.
    That is, even if the validation is disabled, only client can send
    requests.
