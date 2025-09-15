
nghttp2_submit_origin
=====================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_origin(nghttp2_session *session, uint8_t flags, const nghttp2_origin_entry *ov, size_t nov)

    
    Submits ORIGIN frame.
    
    ORIGIN frame is a non-critical extension to HTTP/2 and defined by
    `RFC 8336 <https://tools.ietf.org/html/rfc8336>`_.
    
    The *flags* is currently ignored and should be
    :enum:`nghttp2_flag.NGHTTP2_FLAG_NONE`.
    
    The *ov* points to the array of origins.  The *nov* specifies the
    number of origins included in *ov*.  This function creates copies
    of all elements in *ov*.
    
    The ORIGIN frame is only usable by a server.  If this function is
    invoked with client side session, this function returns
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`.
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`
        The function is called from client side session.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        There are too many origins, or an origin is too large to fit
        into a default frame payload.
