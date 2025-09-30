
nghttp2_session_set_stream_user_data
====================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_set_stream_user_data(nghttp2_session *session, int32_t stream_id, void *stream_user_data)

    
    Sets the *stream_user_data* to the stream denoted by the
    *stream_id*.  If a stream user data is already set to the stream,
    it is replaced with the *stream_user_data*.  It is valid to specify
    ``NULL`` in the *stream_user_data*, which nullifies the associated
    data pointer.
    
    It is valid to set the *stream_user_data* to the stream reserved by
    PUSH_PROMISE frame.
    
    This function returns 0 if it succeeds, or one of following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The stream does not exist
