
nghttp2_submit_push_promise
===========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int32_t nghttp2_submit_push_promise( nghttp2_session *session, uint8_t flags, int32_t stream_id, const nghttp2_nv *nva, size_t nvlen, void *promised_stream_user_data)

    
    Submits PUSH_PROMISE frame.
    
    The *flags* is currently ignored.  The library handles the
    CONTINUATION frame internally and it correctly sets END_HEADERS to
    the last sequence of the PUSH_PROMISE or CONTINUATION frame.
    
    The *stream_id* must be client initiated stream ID.
    
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
    
    The *promised_stream_user_data* is a pointer to an arbitrary data
    which is associated to the promised stream this frame will open and
    make it in reserved state.  It is available using
    `nghttp2_session_get_stream_user_data()`.  The application can
    access it in :type:`nghttp2_before_frame_send_callback` and
    :type:`nghttp2_on_frame_send_callback` of this frame.
    
    The client side is not allowed to use this function.
    
    To submit response headers and data, use
    `nghttp2_submit_response2()`.
    
    This function returns assigned promised stream ID if it succeeds,
    or one of the following negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_PROTO`
        This function was invoked when *session* is initialized as
        client.
    :enum:`nghttp2_error.NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE`
        No stream ID is available because maximum stream ID was
        reached.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *stream_id* is 0; The *stream_id* does not designate stream
        that peer initiated.
    :enum:`nghttp2_error.NGHTTP2_ERR_STREAM_CLOSED`
        The stream was already closed; or the *stream_id* is invalid.
    
    .. warning::
    
      This function returns assigned promised stream ID if it succeeds.
      As of 1.16.0, stream object for pushed resource is created when
      this function succeeds.  In that case, the application can submit
      push response for the promised frame.
    
      In 1.15.0 or prior versions, pushed stream is not opened yet when
      this function succeeds.  The application must not submit frame to
      that stream ID before :type:`nghttp2_before_frame_send_callback`
      is called for this frame.
    
