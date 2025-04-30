
nghttp2_session_callbacks_set_on_data_chunk_recv_callback
=========================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_on_data_chunk_recv_callback( nghttp2_session_callbacks *cbs, nghttp2_on_data_chunk_recv_callback on_data_chunk_recv_callback)

    
    Sets callback function invoked when a chunk of data in DATA frame
    is received.
