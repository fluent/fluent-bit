
nghttp2_session_callbacks_set_recv_callback
===========================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_recv_callback( nghttp2_session_callbacks *cbs, nghttp2_recv_callback recv_callback)

    
    .. warning::
    
      Deprecated.  Use `nghttp2_session_callbacks_set_recv_callback2()`
      with :type:`nghttp2_recv_callback2` instead.
    
    Sets callback function invoked when the a session wants to receive
    data from the remote peer.  This callback is not necessary if the
    application uses solely `nghttp2_session_mem_recv()` to process
    received data.
