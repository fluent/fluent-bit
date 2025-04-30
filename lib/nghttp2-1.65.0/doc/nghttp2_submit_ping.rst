
nghttp2_submit_ping
===================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_ping(nghttp2_session *session, uint8_t flags, const uint8_t *opaque_data)

    
    Submits PING frame.  You don't have to send PING back when you
    received PING frame.  The library automatically submits PING frame
    in this case.
    
    The *flags* is bitwise OR of 0 or more of the following value.
    
    * :enum:`nghttp2_flag.NGHTTP2_FLAG_ACK`
    
    Unless `nghttp2_option_set_no_auto_ping_ack()` is used, the *flags*
    should be :enum:`nghttp2_flag.NGHTTP2_FLAG_NONE`.
    
    If the *opaque_data* is non ``NULL``, then it should point to the 8
    bytes array of memory to specify opaque data to send with PING
    frame.  If the *opaque_data* is ``NULL``, zero-cleared 8 bytes will
    be sent as opaque data.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
