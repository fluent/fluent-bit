
nghttp2_session_callbacks_set_on_header_callback
================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_on_header_callback( nghttp2_session_callbacks *cbs, nghttp2_on_header_callback on_header_callback)

    
    Sets callback function invoked when a header name/value pair is
    received.  If both
    `nghttp2_session_callbacks_set_on_header_callback()` and
    `nghttp2_session_callbacks_set_on_header_callback2()` are used to
    set callbacks, the latter has the precedence.
