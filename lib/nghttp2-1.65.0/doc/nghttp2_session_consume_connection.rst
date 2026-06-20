
nghttp2_session_consume_connection
==================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_consume_connection(nghttp2_session *session, size_t size)

    
    Like `nghttp2_session_consume()`, but this only tells library that
    *size* bytes were consumed only for connection level.  Note that
    HTTP/2 maintains connection and stream level flow control windows
    independently.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`
        Automatic WINDOW_UPDATE is not disabled.
