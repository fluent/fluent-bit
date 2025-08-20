
nghttp2_session_callbacks_set_send_callback2
============================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_send_callback2( nghttp2_session_callbacks *cbs, nghttp2_send_callback2 send_callback)

    
    Sets callback function invoked when a session wants to send data to
    the remote peer.  This callback is not necessary if the application
    uses solely `nghttp2_session_mem_send2()` to serialize data to
    transmit.
