
nghttp2_session_terminate_session2
==================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_terminate_session2(nghttp2_session *session, int32_t last_stream_id, uint32_t error_code)

    
    Signals the session so that the connection should be terminated.
    
    This function behaves like `nghttp2_session_terminate_session()`,
    but the last stream ID can be specified by the application for fine
    grained control of stream.  The HTTP/2 specification does not allow
    last_stream_id to be increased.  So the actual value sent as
    last_stream_id is the minimum value between the given
    *last_stream_id* and the last_stream_id we have previously sent to
    the peer.
    
    The *last_stream_id* is peer's stream ID or 0.  So if *session* is
    initialized as client, *last_stream_id* must be even or 0.  If
    *session* is initialized as server, *last_stream_id* must be odd or
    0.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *last_stream_id* is invalid.
