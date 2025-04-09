
nghttp2_session_callbacks_set_on_stream_close_callback
======================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_on_stream_close_callback( nghttp2_session_callbacks *cbs, nghttp2_on_stream_close_callback on_stream_close_callback)

    
    Sets callback function invoked when the stream is closed.
