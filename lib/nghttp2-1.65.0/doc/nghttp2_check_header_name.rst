
nghttp2_check_header_name
=========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_check_header_name(const uint8_t *name, size_t len)

    
    Returns nonzero if HTTP header field name *name* of length *len* is
    valid according to http://tools.ietf.org/html/rfc7230#section-3.2
    
    Because this is a header field name in HTTP2, the upper cased alphabet
    is treated as error.
