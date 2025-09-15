
nghttp2_extpri_parse_priority
=============================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_extpri_parse_priority(nghttp2_extpri *extpri, const uint8_t *value, size_t len)

    
    Parses Priority header field value pointed by *value* of length
    *len*, and stores the result in the object pointed by *extpri*.
    Priority header field is defined in :rfc:`9218`.
    
    This function does not initialize the object pointed by *extpri*
    before storing the result.  It only assigns the values that the
    parser correctly extracted to fields.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        Failed to parse the header field value.
