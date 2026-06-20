
nghttp2_session_callbacks_set_on_extension_chunk_recv_callback
==============================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_on_extension_chunk_recv_callback( nghttp2_session_callbacks *cbs, nghttp2_on_extension_chunk_recv_callback on_extension_chunk_recv_callback)

    
    Sets callback function invoked when chunk of extension frame
    payload is received.
