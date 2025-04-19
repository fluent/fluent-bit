
nghttp2_session_callbacks_set_on_invalid_header_callback2
=========================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_on_invalid_header_callback2( nghttp2_session_callbacks *cbs, nghttp2_on_invalid_header_callback2 on_invalid_header_callback2)

    
    Sets callback function invoked when a invalid header name/value
    pair is received.
