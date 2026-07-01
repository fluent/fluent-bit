
nghttp2_check_method
====================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_check_method(const uint8_t *value, size_t len)

    
    Returns nonzero if the *value* which is supposed to be the value of
    the :method header field is valid according to
    https://datatracker.ietf.org/doc/html/rfc7231#section-4 and
    https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.6
