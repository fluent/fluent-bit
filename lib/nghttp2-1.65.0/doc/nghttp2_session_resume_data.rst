
nghttp2_session_resume_data
===========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_resume_data(nghttp2_session *session, int32_t stream_id)

    
    Puts back previously deferred DATA frame in the stream *stream_id*
    to the outbound queue.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The stream does not exist; or no deferred data exist.
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
