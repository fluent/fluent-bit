
nghttp2_submit_goaway
=====================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_goaway(nghttp2_session *session, uint8_t flags, int32_t last_stream_id, uint32_t error_code, const uint8_t *opaque_data, size_t opaque_data_len)

    
    Submits GOAWAY frame with the last stream ID *last_stream_id* and
    the error code *error_code*.
    
    The pre-defined error code is one of :enum:`nghttp2_error_code`.
    
    The *flags* is currently ignored and should be
    :enum:`nghttp2_flag.NGHTTP2_FLAG_NONE`.
    
    The *last_stream_id* is peer's stream ID or 0.  So if *session* is
    initialized as client, *last_stream_id* must be even or 0.  If
    *session* is initialized as server, *last_stream_id* must be odd or
    0.
    
    The HTTP/2 specification says last_stream_id must not be increased
    from the value previously sent.  So the actual value sent as
    last_stream_id is the minimum value between the given
    *last_stream_id* and the last_stream_id previously sent to the
    peer.
    
    If the *opaque_data* is not ``NULL`` and *opaque_data_len* is not
    zero, those data will be sent as additional debug data.  The
    library makes a copy of the memory region pointed by *opaque_data*
    with the length *opaque_data_len*, so the caller does not need to
    keep this memory after the return of this function.  If the
    *opaque_data_len* is 0, the *opaque_data* could be ``NULL``.
    
    After successful transmission of GOAWAY, following things happen.
    All incoming streams having strictly more than *last_stream_id* are
    closed.  All incoming HEADERS which starts new stream are simply
    ignored.  After all active streams are handled, both
    `nghttp2_session_want_read()` and `nghttp2_session_want_write()`
    return 0 and the application can close session.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *opaque_data_len* is too large; the *last_stream_id* is
        invalid.
