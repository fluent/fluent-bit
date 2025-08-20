
nghttp2_session_callbacks_set_on_begin_frame_callback
=====================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_on_begin_frame_callback( nghttp2_session_callbacks *cbs, nghttp2_on_begin_frame_callback on_begin_frame_callback)

    
    Sets callback function invoked when a frame header is received.
