
nghttp2_session_check_request_allowed
=====================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_check_request_allowed(nghttp2_session *session)

    
    Returns nonzero if new request can be sent from local endpoint.
    
    This function return 0 if request is not allowed for this session.
    There are several reasons why request is not allowed.  Some of the
    reasons are: session is server; stream ID has been spent; GOAWAY
    has been sent or received.
    
    The application can call `nghttp2_submit_request2()` without
    consulting this function.  In that case,
    `nghttp2_submit_request2()` may return error.  Or, request is
    failed to sent, and :type:`nghttp2_on_stream_close_callback` is
    called.
