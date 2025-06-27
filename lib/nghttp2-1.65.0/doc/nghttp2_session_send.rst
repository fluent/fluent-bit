
nghttp2_session_send
====================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_send(nghttp2_session *session)

    
    Sends pending frames to the remote peer.
    
    This function retrieves the highest prioritized frame from the
    outbound queue and sends it to the remote peer.  It does this as
    many times as possible until the user callback
    :type:`nghttp2_send_callback2` returns
    :enum:`nghttp2_error.NGHTTP2_ERR_WOULDBLOCK`, the outbound queue
    becomes empty or flow control is triggered (remote window size
    becomes depleted or maximum number of concurrent streams is
    reached).  This function calls several callback functions which are
    passed when initializing the *session*.  Here is the simple time
    chart which tells when each callback is invoked:
    
    1. Get the next frame to send from outbound queue.
    
    2. Prepare transmission of the frame.
    
    3. If the control frame cannot be sent because some preconditions
       are not met (e.g., request HEADERS cannot be sent after GOAWAY),
       :type:`nghttp2_on_frame_not_send_callback` is invoked.  Abort
       the following steps.
    
    4. If the frame is HEADERS, PUSH_PROMISE or DATA,
       :type:`nghttp2_select_padding_callback` is invoked.
    
    5. If the frame is request HEADERS, the stream is opened here.
    
    6. :type:`nghttp2_before_frame_send_callback` is invoked.
    
    7. If :enum:`nghttp2_error.NGHTTP2_ERR_CANCEL` is returned from
       :type:`nghttp2_before_frame_send_callback`, the current frame
       transmission is canceled, and
       :type:`nghttp2_on_frame_not_send_callback` is invoked.  Abort
       the following steps.
    
    8. :type:`nghttp2_send_callback2` is invoked one or more times to
       send the frame.
    
    9. :type:`nghttp2_on_frame_send_callback` is invoked.
    
    10. If the transmission of the frame triggers closure of the
        stream, the stream is closed and
        :type:`nghttp2_on_stream_close_callback` is invoked.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`
        The callback function failed.
