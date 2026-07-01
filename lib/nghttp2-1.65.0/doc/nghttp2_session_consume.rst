
nghttp2_session_consume
=======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_consume(nghttp2_session *session, int32_t stream_id, size_t size)

    
    Tells the *session* that *size* bytes for a stream denoted by
    *stream_id* were consumed by application and are ready to
    WINDOW_UPDATE.  The consumed bytes are counted towards both
    connection and stream level WINDOW_UPDATE (see
    `nghttp2_session_consume_connection()` and
    `nghttp2_session_consume_stream()` to update consumption
    independently).  This function is intended to be used without
    automatic window update (see
    `nghttp2_option_set_no_auto_window_update()`).
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *stream_id* is 0.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`
        Automatic WINDOW_UPDATE is not disabled.
