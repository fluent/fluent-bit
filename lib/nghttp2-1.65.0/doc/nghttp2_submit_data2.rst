
nghttp2_submit_data2
====================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_submit_data2(nghttp2_session *session, uint8_t flags, int32_t stream_id, const nghttp2_data_provider2 *data_prd)

    
    Submits one or more DATA frames to the stream *stream_id*.  The
    data to be sent are provided by *data_prd*.  If *flags* contains
    :enum:`nghttp2_flag.NGHTTP2_FLAG_END_STREAM`, the last DATA frame
    has END_STREAM flag set.
    
    This function does not take ownership of the *data_prd*.  The
    function copies the members of the *data_prd*.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_DATA_EXIST`
        DATA or HEADERS has been already submitted and not fully
        processed yet.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_ARGUMENT`
        The *stream_id* is 0.
    :enum:`nghttp2_error.NGHTTP2_ERR_STREAM_CLOSED`
        The stream was already closed; or the *stream_id* is invalid.
    
    .. note::
    
      Currently, only one DATA or HEADERS is allowed for a stream at a
      time.  Submitting these frames more than once before first DATA
      or HEADERS is finished results in
      :enum:`nghttp2_error.NGHTTP2_ERR_DATA_EXIST` error code.  The
      earliest callback which tells that previous frame is done is
      :type:`nghttp2_on_frame_send_callback`.  In side that callback,
      new data can be submitted using `nghttp2_submit_data2()`.  Of
      course, all data except for last one must not have
      :enum:`nghttp2_flag.NGHTTP2_FLAG_END_STREAM` flag set in *flags*.
      This sounds a bit complicated, and we recommend to use
      `nghttp2_submit_request2()` and `nghttp2_submit_response2()` to
      avoid this cascading issue.  The experience shows that for HTTP
      use, these two functions are enough to implement both client and
      server.
