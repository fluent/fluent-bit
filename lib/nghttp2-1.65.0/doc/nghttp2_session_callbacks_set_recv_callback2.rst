
nghttp2_session_callbacks_set_recv_callback2
============================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_recv_callback2( nghttp2_session_callbacks *cbs, nghttp2_recv_callback2 recv_callback)

    
    Sets callback function invoked when the a session wants to receive
    data from the remote peer.  This callback is not necessary if the
    application uses solely `nghttp2_session_mem_recv2()` to process
    received data.
