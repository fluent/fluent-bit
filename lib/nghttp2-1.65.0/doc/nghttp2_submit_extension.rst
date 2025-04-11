
nghttp2_submit_extension
========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_extension(nghttp2_session *session, uint8_t type, uint8_t flags, int32_t stream_id, void *payload)

    
    Submits extension frame.
    
    Application can pass arbitrary frame flags and stream ID in *flags*
    and *stream_id* respectively.  The *payload* is opaque pointer, and
    it can be accessible though ``frame->ext.payload`` in
    :type:`nghttp2_pack_extension_callback2`.  The library will not own
    passed *payload* pointer.
    
    The application must set :type:`nghttp2_pack_extension_callback2`
    using `nghttp2_session_callbacks_set_pack_extension_callback2()`.
    
    The application should retain the memory pointed by *payload* until
    the transmission of extension frame is done (which is indicated by
    :type:`nghttp2_on_frame_send_callback`), or transmission fails
    (which is indicated by :type:`nghttp2_on_frame_not_send_callback`).
    If application does not touch this memory region after packing it
    into a wire format, application can free it inside
    :type:`nghttp2_pack_extension_callback2`.
    
    The standard HTTP/2 frame cannot be sent with this function, so
    *type* must be strictly grater than 0x9.  Otherwise, this function
    will fail with error code
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`
        If :type:`nghttp2_pack_extension_callback2` is not set.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        If  *type* specifies  standard  HTTP/2 frame  type.  The  frame
        types  in the  rage [0x0,  0x9], both  inclusive, are  standard
        HTTP/2 frame type, and cannot be sent using this function.
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory
