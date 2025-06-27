
nghttp2_session_callbacks_set_send_callback
===========================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_send_callback( nghttp2_session_callbacks *cbs, nghttp2_send_callback send_callback)

    
    .. warning::
    
      Deprecated.  Use `nghttp2_session_callbacks_set_send_callback2()`
      with :type:`nghttp2_send_callback2` instead.
    
    Sets callback function invoked when a session wants to send data to
    the remote peer.  This callback is not necessary if the application
    uses solely `nghttp2_session_mem_send()` to serialize data to
    transmit.
