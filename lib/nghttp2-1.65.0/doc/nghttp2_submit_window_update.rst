
nghttp2_submit_window_update
============================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_window_update(nghttp2_session *session, uint8_t flags, int32_t stream_id, int32_t window_size_increment)

    
    Submits WINDOW_UPDATE frame.
    
    The *flags* is currently ignored and should be
    :enum:`nghttp2_flag.NGHTTP2_FLAG_NONE`.
    
    The *stream_id* is the stream ID to send this WINDOW_UPDATE.  To
    send connection level WINDOW_UPDATE, specify 0 to *stream_id*.
    
    If the *window_size_increment* is positive, the WINDOW_UPDATE with
    that value as window_size_increment is queued.  If the
    *window_size_increment* is larger than the received bytes from the
    remote endpoint, the local window size is increased by that
    difference.  If the sole purpose is to increase the local window
    size, consider to use `nghttp2_session_set_local_window_size()`.
    
    If the *window_size_increment* is negative, the local window size
    is decreased by -*window_size_increment*.  If automatic
    WINDOW_UPDATE is enabled
    (`nghttp2_option_set_no_auto_window_update()`), and the library
    decided that the WINDOW_UPDATE should be submitted, then
    WINDOW_UPDATE is queued with the current received bytes count.  If
    the sole purpose is to decrease the local window size, consider to
    use `nghttp2_session_set_local_window_size()`.
    
    If the *window_size_increment* is 0, the function does nothing and
    returns 0.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_FLOW_CONTROL`
        The local window size overflow or gets negative.
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
