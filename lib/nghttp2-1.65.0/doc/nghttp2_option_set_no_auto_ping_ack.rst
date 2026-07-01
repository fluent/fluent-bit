
nghttp2_option_set_no_auto_ping_ack
===================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_no_auto_ping_ack(nghttp2_option *option, int val)

    
    This option prevents the library from sending PING frame with ACK
    flag set automatically when PING frame without ACK flag set is
    received.  If this option is set to nonzero, the library won't send
    PING frame with ACK flag set in the response for incoming PING
    frame.  The application can send PING frame with ACK flag set using
    `nghttp2_submit_ping()` with :enum:`nghttp2_flag.NGHTTP2_FLAG_ACK`
    as flags parameter.
