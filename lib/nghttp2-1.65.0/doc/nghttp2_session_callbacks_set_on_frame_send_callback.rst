
nghttp2_session_callbacks_set_on_frame_send_callback
====================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_on_frame_send_callback( nghttp2_session_callbacks *cbs, nghttp2_on_frame_send_callback on_frame_send_callback)

    
    Sets callback function invoked after a frame is sent.
