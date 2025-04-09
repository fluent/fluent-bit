
nghttp2_session_get_stream_local_window_size
============================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int32_t nghttp2_session_get_stream_local_window_size( nghttp2_session *session, int32_t stream_id)

    
    Returns the amount of flow-controlled payload (e.g., DATA) that the
    remote endpoint can send without receiving stream level
    WINDOW_UPDATE frame.  It is also subject to the connection level
    flow control.  So the actual amount of data to send is
    min(`nghttp2_session_get_stream_local_window_size()`,
    `nghttp2_session_get_local_window_size()`).
    
    This function returns -1 if it fails.
