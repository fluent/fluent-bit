
nghttp2_session_get_effective_local_window_size
===============================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int32_t nghttp2_session_get_effective_local_window_size(nghttp2_session *session)

    
    Returns the local (receive) window size for a connection.  The
    local window size can be adjusted by
    `nghttp2_submit_window_update()`.  This function takes into account
    that and returns effective window size.
    
    This function does not take into account the amount of received
    data from the remote endpoint.  Use
    `nghttp2_session_get_local_window_size()` to know the amount of
    data the remote endpoint can send without receiving
    connection-level WINDOW_UPDATE frame.  Note that each stream is
    still subject to the stream level flow control.
    
    This function returns -1 if it fails.
