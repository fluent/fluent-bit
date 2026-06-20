
nghttp2_session_callbacks_set_on_invalid_frame_recv_callback
============================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_on_invalid_frame_recv_callback( nghttp2_session_callbacks *cbs, nghttp2_on_invalid_frame_recv_callback on_invalid_frame_recv_callback)

    
    Sets callback function invoked by `nghttp2_session_recv()` and
    `nghttp2_session_mem_recv2()` when an invalid non-DATA frame is
    received.
