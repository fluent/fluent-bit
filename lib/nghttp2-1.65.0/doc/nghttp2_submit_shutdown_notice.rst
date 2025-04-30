
nghttp2_submit_shutdown_notice
==============================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_shutdown_notice(nghttp2_session *session)

    
    Signals to the client that the server started graceful shutdown
    procedure.
    
    This function is only usable for server.  If this function is
    called with client side session, this function returns
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`.
    
    To gracefully shutdown HTTP/2 session, server should call this
    function to send GOAWAY with last_stream_id (1u << 31) - 1.  And
    after some delay (e.g., 1 RTT), send another GOAWAY with the stream
    ID that the server has some processing using
    `nghttp2_submit_goaway()`.  See also
    `nghttp2_session_get_last_proc_stream_id()`.
    
    Unlike `nghttp2_submit_goaway()`, this function just sends GOAWAY
    and does nothing more.  This is a mere indication to the client
    that session shutdown is imminent.  The application should call
    `nghttp2_submit_goaway()` with appropriate last_stream_id after
    this call.
    
    If one or more GOAWAY frame have been already sent by either
    `nghttp2_submit_goaway()` or `nghttp2_session_terminate_session()`,
    this function has no effect.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`
        The *session* is initialized as client.
