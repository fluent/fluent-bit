
nghttp2_session_upgrade2
========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_upgrade2(nghttp2_session *session, const uint8_t *settings_payload, size_t settings_payloadlen, int head_request, void *stream_user_data)

    
    Performs post-process of HTTP Upgrade request.  This function can
    be called from both client and server, but the behavior is very
    different in each other.
    
    If called from client side, the *settings_payload* must be the
    value sent in ``HTTP2-Settings`` header field and must be decoded
    by base64url decoder.  The *settings_payloadlen* is the length of
    *settings_payload*.  The *settings_payload* is unpacked and its
    setting values will be submitted using `nghttp2_submit_settings()`.
    This means that the client application code does not need to submit
    SETTINGS by itself.  The stream with stream ID=1 is opened and the
    *stream_user_data* is used for its stream_user_data.  The opened
    stream becomes half-closed (local) state.
    
    If called from server side, the *settings_payload* must be the
    value received in ``HTTP2-Settings`` header field and must be
    decoded by base64url decoder.  The *settings_payloadlen* is the
    length of *settings_payload*.  It is treated as if the SETTINGS
    frame with that payload is received.  Thus, callback functions for
    the reception of SETTINGS frame will be invoked.  The stream with
    stream ID=1 is opened.  The *stream_user_data* is ignored.  The
    opened stream becomes half-closed (remote).
    
    If the request method is HEAD, pass nonzero value to
    *head_request*.  Otherwise, pass 0.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *settings_payload* is badly formed.
    :enum:`nghttp2_error.NGHTTP2_ERR_PROTO`
        The stream ID 1 is already used or closed; or is not available.
