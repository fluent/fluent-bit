
nghttp2_submit_altsvc
=====================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_altsvc(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *origin, size_t origin_len, const uint8_t *field_value, size_t field_value_len)

    
    Submits ALTSVC frame.
    
    ALTSVC frame is a non-critical extension to HTTP/2, and defined in
    `RFC 7383 <https://tools.ietf.org/html/rfc7838#section-4>`_.
    
    The *flags* is currently ignored and should be
    :enum:`nghttp2_flag.NGHTTP2_FLAG_NONE`.
    
    The *origin* points to the origin this alternative service is
    associated with.  The *origin_len* is the length of the origin.  If
    *stream_id* is 0, the origin must be specified.  If *stream_id* is
    not zero, the origin must be empty (in other words, *origin_len*
    must be 0).
    
    The ALTSVC frame is only usable from server side.  If this function
    is invoked with client side session, this function returns
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`
        The function is called from client side session
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The sum of *origin_len* and *field_value_len* is larger than
        16382; or *origin_len* is 0 while *stream_id* is 0; or
        *origin_len* is not 0 while *stream_id* is not 0.
