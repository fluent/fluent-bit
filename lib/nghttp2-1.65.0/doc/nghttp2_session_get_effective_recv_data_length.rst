
nghttp2_session_get_effective_recv_data_length
==============================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int32_t nghttp2_session_get_effective_recv_data_length(nghttp2_session *session)

    
    Returns the number of DATA payload in bytes received without
    WINDOW_UPDATE transmission for a connection.  The local (receive)
    window size can be adjusted by `nghttp2_submit_window_update()`.
    This function takes into account that and returns effective data
    length.  In particular, if the local window size is reduced by
    submitting negative window_size_increment with
    `nghttp2_submit_window_update()`, this function returns the number
    of bytes less than actually received.
    
    This function returns -1 if it fails.
