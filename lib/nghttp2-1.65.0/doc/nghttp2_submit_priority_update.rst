
nghttp2_submit_priority_update
==============================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_priority_update(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *field_value, size_t field_value_len)

    
    Submits PRIORITY_UPDATE frame.
    
    PRIORITY_UPDATE frame is a non-critical extension to HTTP/2, and
    defined in :rfc:`9218#section-7.1`.
    
    The *flags* is currently ignored and should be
    :enum:`nghttp2_flag.NGHTTP2_FLAG_NONE`.
    
    The *stream_id* is the ID of stream which is prioritized.  The
    *field_value* points to the Priority field value.  The
    *field_value_len* is the length of the Priority field value.
    
    If this function is called by server,
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE` is returned.
    
    If
    :enum:`nghttp2_settings_id.NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES`
    of value of 0 is received by a remote endpoint (or it is omitted),
    this function does nothing and returns 0.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`
        The function is called from server side session
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *field_value_len* is larger than 16380; or *stream_id* is
        0.
