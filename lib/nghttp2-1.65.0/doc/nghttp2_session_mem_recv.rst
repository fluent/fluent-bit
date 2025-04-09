
nghttp2_session_mem_recv
========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: ssize_t nghttp2_session_mem_recv(nghttp2_session *session, const uint8_t *in, size_t inlen)

    
    .. warning::
    
      Deprecated.  Use `nghttp2_session_mem_recv2()` instead.
    
    Processes data *in* as an input from the remote endpoint.  The
    *inlen* indicates the number of bytes to receive in the *in*.
    
    This function behaves like `nghttp2_session_recv()` except that it
    does not use :type:`nghttp2_recv_callback` to receive data; the
    *in* is the only data for the invocation of this function.  If all
    bytes are processed, this function returns.  The other callbacks
    are called in the same way as they are in `nghttp2_session_recv()`.
    
    In the current implementation, this function always tries to
    processes *inlen* bytes of input data unless either an error occurs or
    :enum:`nghttp2_error.NGHTTP2_ERR_PAUSE` is returned from
    :type:`nghttp2_on_header_callback` or
    :type:`nghttp2_on_data_chunk_recv_callback`.  If
    :enum:`nghttp2_error.NGHTTP2_ERR_PAUSE` is used, the return value
    includes the number of bytes which was used to produce the data or
    frame for the callback.
    
    This function returns the number of processed bytes, or one of the
    following negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE`
        The callback function failed.
    :enum:`nghttp2_error.NGHTTP2_ERR_BAD_CLIENT_MAGIC`
        Invalid client magic was detected.  This error only returns
        when *session* was configured as server and
        `nghttp2_option_set_no_recv_client_magic()` is not used with
        nonzero value.
    :enum:`nghttp2_error.NGHTTP2_ERR_FLOODED`
        Flooding was detected in this HTTP/2 session, and it must be
        closed.  This is most likely caused by misbehaviour of peer.
