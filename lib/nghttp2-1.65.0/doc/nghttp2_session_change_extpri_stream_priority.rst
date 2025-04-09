
nghttp2_session_change_extpri_stream_priority
=============================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_change_extpri_stream_priority( nghttp2_session *session, int32_t stream_id, const nghttp2_extpri *extpri, int ignore_client_signal)

    
    Changes the priority of the existing stream denoted by *stream_id*.
    The new priority is *extpri*.  This function is meant to be used by
    server for :rfc:`9218` extensible prioritization scheme.
    
    If *session* is initialized as client, this function returns
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`.  For client, use
    `nghttp2_submit_priority_update()` instead.
    
    If :member:`extpri->urgency <nghttp2_extpri.urgency>` is out of
    bound, it is set to :macro:`NGHTTP2_EXTPRI_URGENCY_LOW`.
    
    If *ignore_client_signal* is nonzero, server starts to ignore
    client priority signals for this stream.
    
    If
    :enum:`nghttp2_settings_id.NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES`
    of value of 1 is not submitted via `nghttp2_submit_settings()`,
    this function does nothing and returns 0.
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`
        The *session* is initialized as client.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        *stream_id* is zero; or a stream denoted by *stream_id* is not
        found.
