
nghttp2_check_path
==================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_check_path(const uint8_t *value, size_t len)

    
    Returns nonzero if the *value* which is supposed to be the value of
    the :path header field is valid according to
    https://datatracker.ietf.org/doc/html/rfc7540#section-8.1.2.3
    
    *value* is valid if it merely consists of the allowed characters.
    In particular, it does not check whether *value* follows the syntax
    of path.  The allowed characters are all characters valid by
    `nghttp2_check_header_value` minus SPC and HT.
