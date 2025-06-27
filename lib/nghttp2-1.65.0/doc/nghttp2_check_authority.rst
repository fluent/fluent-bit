
nghttp2_check_authority
=======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_check_authority(const uint8_t *value, size_t len)

    
    Returns nonzero if the *value* which is supposed to be the value of the
    :authority or host header field is valid according to
    https://tools.ietf.org/html/rfc3986#section-3.2
    
    Note that :authority and host field values are not authority.  They
    do not include userinfo in RFC 3986, see
    https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.2, that
    is, it does not include '@'.  This function treats '@' as a valid
    character.
    
    *value* is valid if it merely consists of the allowed characters.
    In particular, it does not check whether *value* follows the syntax
    of authority.
