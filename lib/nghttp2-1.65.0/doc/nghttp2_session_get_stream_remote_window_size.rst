
nghttp2_session_get_stream_remote_window_size
=============================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int32_t nghttp2_session_get_stream_remote_window_size( nghttp2_session *session, int32_t stream_id)

    
    Returns the remote window size for a given stream *stream_id*.
    
    This is the amount of flow-controlled payload (e.g., DATA) that the
    local endpoint can send without stream level WINDOW_UPDATE.  There
    is also connection level flow control, so the effective size of
    payload that the local endpoint can actually send is
    min(`nghttp2_session_get_stream_remote_window_size()`,
    `nghttp2_session_get_remote_window_size()`).
    
    This function returns -1 if it fails.
