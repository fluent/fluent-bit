
nghttp2_submit_rst_stream
=========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_rst_stream(nghttp2_session *session, uint8_t flags, int32_t stream_id, uint32_t error_code)

    
    Submits RST_STREAM frame to cancel/reject the stream *stream_id*
    with the error code *error_code*.
    
    The pre-defined error code is one of :enum:`nghttp2_error_code`.
    
    The *flags* is currently ignored and should be
    :enum:`nghttp2_flag.NGHTTP2_FLAG_NONE`.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *stream_id* is 0.
