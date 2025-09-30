
nghttp2_session_set_next_stream_id
==================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_set_next_stream_id(nghttp2_session *session, int32_t next_stream_id)

    
    Tells the *session* that next stream ID is *next_stream_id*.  The
    *next_stream_id* must be equal or greater than the value returned
    by `nghttp2_session_get_next_stream_id()`.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *next_stream_id* is strictly less than the value
        `nghttp2_session_get_next_stream_id()` returns; or
        *next_stream_id* is invalid (e.g., even integer for client, or
        odd integer for server).
