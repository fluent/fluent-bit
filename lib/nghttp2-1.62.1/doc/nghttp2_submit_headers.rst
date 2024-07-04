
nghttp2_submit_headers
======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int32_t nghttp2_submit_headers( nghttp2_session *session, uint8_t flags, int32_t stream_id, const nghttp2_priority_spec *pri_spec, const nghttp2_nv *nva, size_t nvlen, void *stream_user_data)

    
    Submits HEADERS frame. The *flags* is bitwise OR of the
    following values:
    
    * :enum:`nghttp2_flag.NGHTTP2_FLAG_END_STREAM`
    
    If *flags* includes :enum:`nghttp2_flag.NGHTTP2_FLAG_END_STREAM`,
    this frame has END_STREAM flag set.
    
    The library handles the CONTINUATION frame internally and it
    correctly sets END_HEADERS to the last sequence of the PUSH_PROMISE
    or CONTINUATION frame.
    
    If the *stream_id* is -1, this frame is assumed as request (i.e.,
    request HEADERS frame which opens new stream).  In this case, the
    assigned stream ID will be returned.  Otherwise, specify stream ID
    in *stream_id*.
    
    The *pri_spec* is a deprecated priority specification of this
    request.  ``NULL`` means the default priority (see
    `nghttp2_priority_spec_default_init()`).  To specify the priority,
    use `nghttp2_priority_spec_init()`.  If *pri_spec* is not ``NULL``,
    this function will copy its data members.  In the future release
    after the end of 2024, this function will ignore *pri_spec* and
    behave as if ``NULL`` is given.
    
    The ``pri_spec->weight`` must be in [:macro:`NGHTTP2_MIN_WEIGHT`,
    :macro:`NGHTTP2_MAX_WEIGHT`], inclusive.  If ``pri_spec->weight``
    is strictly less than :macro:`NGHTTP2_MIN_WEIGHT`, it becomes
    :macro:`NGHTTP2_MIN_WEIGHT`.  If it is strictly greater than
    :macro:`NGHTTP2_MAX_WEIGHT`, it becomes :macro:`NGHTTP2_MAX_WEIGHT`.
    
    If
    :enum:`nghttp2_settings_id.NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES`
    of value of 1 is received by a remote endpoint, *pri_spec* is
    ignored, and treated as if ``NULL`` is specified.
    
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
    
    The *stream_user_data* is a pointer to an arbitrary data which is
    associated to the stream this frame will open.  Therefore it is
    only used if this frame opens streams, in other words, it changes
    stream state from idle or reserved to open.
    
    This function is low-level in a sense that the application code can
    specify flags directly.  For usual HTTP request,
    `nghttp2_submit_request2()` is useful.  Likewise, for HTTP
    response, prefer `nghttp2_submit_response2()`.
    
    This function returns newly assigned stream ID if it succeeds and
    *stream_id* is -1.  Otherwise, this function returns 0 if it
    succeeds, or one of the following negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE`
        No stream ID is available because maximum stream ID was
        reached.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *stream_id* is 0; or trying to depend on itself (stream ID
        equals ``pri_spec->stream_id``).
    :enum:`nghttp2_error.NGHTTP2_ERR_DATA_EXIST`
        DATA or HEADERS has been already submitted and not fully
        processed yet.  This happens if stream denoted by *stream_id*
        is in reserved state.
    :enum:`nghttp2_error.NGHTTP2_ERR_PROTO`
        The *stream_id* is -1, and *session* is server session.
    
    .. warning::
    
      This function returns assigned stream ID if it succeeds and
      *stream_id* is -1.  But that stream is not opened yet.  The
      application must not submit frame to that stream ID before
      :type:`nghttp2_before_frame_send_callback` is called for this
      frame.
    
