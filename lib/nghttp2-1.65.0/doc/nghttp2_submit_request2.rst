
nghttp2_submit_request2
=======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int32_t nghttp2_submit_request2( nghttp2_session *session, const nghttp2_priority_spec *pri_spec, const nghttp2_nv *nva, size_t nvlen, const nghttp2_data_provider2 *data_prd, void *stream_user_data)

    
    Submits HEADERS frame and optionally one or more DATA frames.
    
    The *pri_spec* is ignored.
    
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
    request HEADERS.  See the specification for more details.
    
    If *data_prd* is not ``NULL``, it provides data which will be sent
    in subsequent DATA frames.  In this case, a method that allows
    request message bodies
    (https://tools.ietf.org/html/rfc7231#section-4) must be specified
    with ``:method`` key in *nva* (e.g. ``POST``).  This function does
    not take ownership of the *data_prd*.  The function copies the
    members of the *data_prd*.  If *data_prd* is ``NULL``, HEADERS have
    END_STREAM set.  The *stream_user_data* is data associated to the
    stream opened by this request and can be an arbitrary pointer,
    which can be retrieved later by
    `nghttp2_session_get_stream_user_data()`.
    
    This function returns assigned stream ID if it succeeds, or one of
    the following negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE`
        No stream ID is available because maximum stream ID was
        reached.
    :enum:`nghttp2_error.NGHTTP2_ERR_PROTO`
        The *session* is server session.
    
    .. warning::
    
      This function returns assigned stream ID if it succeeds.  But
      that stream is not created yet.  The application must not submit
      frame to that stream ID before
      :type:`nghttp2_before_frame_send_callback` is called for this
      frame.  This means `nghttp2_session_get_stream_user_data()` does
      not work before the callback.  But
      `nghttp2_session_set_stream_user_data()` handles this situation
      specially, and it can set data to a stream during this period.
    
