
nghttp2_session_set_local_window_size
=====================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_set_local_window_size(nghttp2_session *session, uint8_t flags, int32_t stream_id, int32_t window_size)

    
    Set local window size (local endpoints's window size) to the given
    *window_size* for the given stream denoted by *stream_id*.  To
    change connection level window size, specify 0 to *stream_id*.  To
    increase window size, this function may submit WINDOW_UPDATE frame
    to transmission queue.
    
    The *flags* is currently ignored and should be
    :enum:`nghttp2_flag.NGHTTP2_FLAG_NONE`.
    
    This sounds similar to `nghttp2_submit_window_update()`, but there
    are 2 differences.  The first difference is that this function
    takes the absolute value of window size to set, rather than the
    delta.  To change the window size, this may be easier to use since
    the application just declares the intended window size, rather than
    calculating delta.  The second difference is that
    `nghttp2_submit_window_update()` affects the received bytes count
    which has not acked yet.  By the specification of
    `nghttp2_submit_window_update()`, to strictly increase the local
    window size, we have to submit delta including all received bytes
    count, which might not be desirable in some cases.  On the other
    hand, this function does not affect the received bytes count.  It
    just sets the local window size to the given value.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *stream_id* is negative.
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
