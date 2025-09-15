
nghttp2_session_callbacks_set_before_frame_send_callback
========================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_before_frame_send_callback( nghttp2_session_callbacks *cbs, nghttp2_before_frame_send_callback before_frame_send_callback)

    
    Sets callback function invoked before a non-DATA frame is sent.
