
nghttp2_session_get_local_window_size
=====================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int32_t nghttp2_session_get_local_window_size(nghttp2_session *session)

    
    Returns the amount of flow-controlled payload (e.g., DATA) that the
    remote endpoint can send without receiving connection level
    WINDOW_UPDATE frame.  Note that each stream is still subject to the
    stream level flow control (see
    `nghttp2_session_get_stream_local_window_size()`).
    
    This function returns -1 if it fails.
