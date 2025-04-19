
nghttp2_submit_trailer
======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_trailer(nghttp2_session *session, int32_t stream_id, const nghttp2_nv *nva, size_t nvlen)

    
    Submits trailer fields HEADERS against the stream *stream_id*.
    
    The *nva* is an array of name/value pair :type:`nghttp2_nv` with
    *nvlen* elements.  The application must not include pseudo-header
    fields (headers whose names starts with ":") in *nva*.
    
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
    
    For server, trailer fields must follow response HEADERS or response
    DATA without END_STREAM flat set.  The library does not enforce
    this requirement, and applications should do this for themselves.
    If `nghttp2_submit_trailer()` is called before any response HEADERS
    submission (usually by `nghttp2_submit_response2()`), the content
    of *nva* will be sent as response headers, which will result in
    error.
    
    This function has the same effect with `nghttp2_submit_headers()`,
    with flags = :enum:`nghttp2_flag.NGHTTP2_FLAG_END_STREAM` and both
    pri_spec and stream_user_data to NULL.
    
    To submit trailer fields after `nghttp2_submit_response2()` is
    called, the application has to specify
    :type:`nghttp2_data_provider2` to `nghttp2_submit_response2()`.
    Inside of :type:`nghttp2_data_source_read_callback2`, when setting
    :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_EOF`, also set
    :enum:`nghttp2_data_flag.NGHTTP2_DATA_FLAG_NO_END_STREAM`.  After
    that, the application can send trailer fields using
    `nghttp2_submit_trailer()`.  `nghttp2_submit_trailer()` can be used
    inside :type:`nghttp2_data_source_read_callback2`.
    
    This function returns 0 if it succeeds and *stream_id* is -1.
    Otherwise, this function returns 0 if it succeeds, or one of the
    following negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *stream_id* is 0.
