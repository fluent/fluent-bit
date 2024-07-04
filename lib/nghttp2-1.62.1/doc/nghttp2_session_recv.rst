
nghttp2_session_recv
====================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_recv(nghttp2_session *session)

    
    Receives frames from the remote peer.
    
    This function receives as many frames as possible until the user
    callback :type:`nghttp2_recv_callback` returns
    :enum:`nghttp2_error.NGHTTP2_ERR_WOULDBLOCK`.  This function calls
    several callback functions which are passed when initializing the
    *session*.  Here is the simple time chart which tells when each
    callback is invoked:
    
    1. :type:`nghttp2_recv_callback` is invoked one or more times to
       receive frame header.
    
    2. When frame header is received,
       :type:`nghttp2_on_begin_frame_callback` is invoked.
    
    3. If the frame is DATA frame:
    
       1. :type:`nghttp2_recv_callback` is invoked to receive DATA
          payload. For each chunk of data,
          :type:`nghttp2_on_data_chunk_recv_callback` is invoked.
    
       2. If one DATA frame is completely received,
          :type:`nghttp2_on_frame_recv_callback` is invoked.  If the
          reception of the frame triggers the closure of the stream,
          :type:`nghttp2_on_stream_close_callback` is invoked.
    
    4. If the frame is the control frame:
    
       1. :type:`nghttp2_recv_callback` is invoked one or more times to
          receive whole frame.
    
       2. If the received frame is valid, then following actions are
          taken.  If the frame is either HEADERS or PUSH_PROMISE,
          :type:`nghttp2_on_begin_headers_callback` is invoked.  Then
          :type:`nghttp2_on_header_callback` is invoked for each header
          name/value pair.  For invalid header field,
          :type:`nghttp2_on_invalid_header_callback` is called.  After
          all name/value pairs are emitted successfully,
          :type:`nghttp2_on_frame_recv_callback` is invoked.  For other
          frames, :type:`nghttp2_on_frame_recv_callback` is invoked.
          If the reception of the frame triggers the closure of the
          stream, :type:`nghttp2_on_stream_close_callback` is invoked.
    
       3. If the received frame is unpacked but is interpreted as
          invalid, :type:`nghttp2_on_invalid_frame_recv_callback` is
          invoked.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_EOF`
        The remote peer did shutdown on the connection.
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`
        The callback function failed.
    :enum:`nghttp2_error.NGHTTP2_ERR_BAD_CLIENT_MAGIC`
        Invalid client magic was detected.  This error only returns
        when *session* was configured as server and
        `nghttp2_option_set_no_recv_client_magic()` is not used with
        nonzero value.
    :enum:`nghttp2_error.NGHTTP2_ERR_FLOODED`
        Flooding was detected in this HTTP/2 session, and it must be
        closed.  This is most likely caused by misbehaviour of peer.
