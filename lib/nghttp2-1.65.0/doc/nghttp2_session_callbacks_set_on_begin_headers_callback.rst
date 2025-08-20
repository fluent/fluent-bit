
nghttp2_session_callbacks_set_on_begin_headers_callback
=======================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_on_begin_headers_callback( nghttp2_session_callbacks *cbs, nghttp2_on_begin_headers_callback on_begin_headers_callback)

    
    Sets callback function invoked when the reception of header block
    in HEADERS or PUSH_PROMISE is started.
