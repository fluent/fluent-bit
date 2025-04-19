
nghttp2_check_header_value
==========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_check_header_value(const uint8_t *value, size_t len)

    
    Returns nonzero if HTTP header field value *value* of length *len*
    is valid according to
    http://tools.ietf.org/html/rfc7230#section-3.2
    
    This function is considered obsolete, and application should
    consider to use `nghttp2_check_header_value_rfc9113()` instead.
