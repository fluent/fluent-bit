
nghttp2_session_get_extpri_stream_priority
==========================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_get_extpri_stream_priority( nghttp2_session *session, nghttp2_extpri *extpri, int32_t stream_id)

    
    Stores the stream priority of the existing stream denoted by
    *stream_id* in the object pointed by *extpri*.  This function is
    meant to be used by server for :rfc:`9218` extensible
    prioritization scheme.
    
    If *session* is initialized as client, this function returns
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`.
    
    If
    :enum:`nghttp2_settings_id.NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES`
    of value of 1 is not submitted via `nghttp2_submit_settings()`,
    this function does nothing and returns 0.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`
        The *session* is initialized as client.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        *stream_id* is zero; or a stream denoted by *stream_id* is not
        found.
