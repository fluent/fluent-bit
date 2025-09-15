
nghttp2_session_get_last_proc_stream_id
=======================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int32_t nghttp2_session_get_last_proc_stream_id(nghttp2_session *session)

    
    Returns the last stream ID of a stream for which
    :type:`nghttp2_on_frame_recv_callback` was invoked most recently.
    The returned value can be used as last_stream_id parameter for
    `nghttp2_submit_goaway()` and
    `nghttp2_session_terminate_session2()`.
    
    This function always succeeds.
