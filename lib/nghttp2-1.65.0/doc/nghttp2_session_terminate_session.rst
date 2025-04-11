
nghttp2_session_terminate_session
=================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_terminate_session(nghttp2_session *session, uint32_t error_code)

    
    Signals the session so that the connection should be terminated.
    
    The last stream ID is the minimum value between the stream ID of a
    stream for which :type:`nghttp2_on_frame_recv_callback` was called
    most recently and the last stream ID we have sent to the peer
    previously.
    
    The *error_code* is the error code of this GOAWAY frame.  The
    pre-defined error code is one of :enum:`nghttp2_error_code`.
    
    After the transmission, both `nghttp2_session_want_read()` and
    `nghttp2_session_want_write()` return 0.
    
    This function should be called when the connection should be
    terminated after sending GOAWAY.  If the remaining streams should
    be processed after GOAWAY, use `nghttp2_submit_goaway()` instead.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
