
nghttp2_check_authority
=======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_check_authority(const uint8_t *value, size_t len)

    
    Returns nonzero if the *value* which is supposed to be the value of the
    :authority or host header field is valid according to
    https://tools.ietf.org/html/rfc3986#section-3.2
    
    *value* is valid if it merely consists of the allowed characters.
    In particular, it does not check whether *value* follows the syntax
    of authority.
