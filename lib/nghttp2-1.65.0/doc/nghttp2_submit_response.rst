
nghttp2_submit_response
=======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_response(nghttp2_session *session, int32_t stream_id, const nghttp2_nv *nva, size_t nvlen, const nghttp2_data_provider *data_prd)

    
    .. warning::
    
      Deprecated.  Use `nghttp2_submit_response2()` instead.
    
    Submits response HEADERS frame and optionally one or more DATA
    frames against the stream *stream_id*.
    
    The *nva* is an array of name/value pair :type:`nghttp2_nv` with
    *nvlen* elements.  The application is responsible to include
    required pseudo-header fields (header field whose name starts with
    ":") in *nva* and must place pseudo-headers before regular header
    fields.
    
    This function creates copies of all name/value pairs in *nva*.  It
    also lower-cases all names in *nva*.  The order of elements in
    *nva* is preserved.  For header fields with
    :enum:`nghttp2_nv_flag.NGHTTP2_NV_FLAG_NO_COPY_NAME` and
    :enum:`nghttp2_nv_flag.NGHTTP2_NV_FLAG_NO_COPY_VALUE` are set,
    header field name and value are not copied respectively.  With
    :enum:`nghttp2_nv_flag.NGHTTP2_NV_FLAG_NO_COPY_NAME`, application
    is responsible to pass header field name in lowercase.  The
    application should maintain the references to them until
    :type:`nghttp2_on_frame_send_callback` or
    :type:`nghttp2_on_frame_not_send_callback` is called.
    
    HTTP/2 specification has requirement about header fields in the
    response HEADERS.  See the specification for more details.
    
    If *data_prd* is not ``NULL``, it provides data which will be sent
    in subsequent DATA frames.  This function does not take ownership
    of the *data_prd*.  The function copies the members of the
    *data_prd*.  If *data_prd* is ``NULL``, HEADERS will have
    END_STREAM flag set.
    
    This method can be used as normal HTTP response and push response.
    When pushing a resource using this function, the *session* must be
    configured using `nghttp2_session_server_new()` or its variants and
    the target stream denoted by the *stream_id* must be reserved using
    `nghttp2_submit_push_promise()`.
    
    To send non-final response headers (e.g., HTTP status 101), don't
    use this function because this function half-closes the outbound
    stream.  Instead, use `nghttp2_submit_headers()` for this purpose.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *stream_id* is 0.
    :enum:`nghttp2_error.NGHTTP2_ERR_DATA_EXIST`
        DATA or HEADERS has been already submitted and not fully
        processed yet.  Normally, this does not happen, but when
        application wrongly calls `nghttp2_submit_response()` twice,
        this may happen.
    :enum:`nghttp2_error.NGHTTP2_ERR_PROTO`
        The *session* is client session.
    
    .. warning::
    
      Calling this function twice for the same stream ID may lead to
      program crash.  It is generally considered to a programming error
      to commit response twice.
