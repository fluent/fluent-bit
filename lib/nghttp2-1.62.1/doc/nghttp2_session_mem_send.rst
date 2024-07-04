
nghttp2_session_mem_send
========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: ssize_t nghttp2_session_mem_send(nghttp2_session *session, const uint8_t **data_ptr)

    
    .. warning::
    
      Deprecated.  Use `nghttp2_session_mem_send2()` instead.
    
    Returns the serialized data to send.
    
    This function behaves like `nghttp2_session_send()` except that it
    does not use :type:`nghttp2_send_callback` to transmit data.
    Instead, it assigns the pointer to the serialized data to the
    *\*data_ptr* and returns its length.  The other callbacks are called
    in the same way as they are in `nghttp2_session_send()`.
    
    If no data is available to send, this function returns 0.
    
    This function may not return all serialized data in one invocation.
    To get all data, call this function repeatedly until it returns 0
    or one of negative error codes.
    
    The assigned *\*data_ptr* is valid until the next call of
    `nghttp2_session_mem_send()` or `nghttp2_session_send()`.
    
    The caller must send all data before sending the next chunk of
    data.
    
    This function returns the length of the data pointed by the
    *\*data_ptr* if it succeeds, or one of the following negative error
    codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    
    .. note::
    
      This function may produce very small byte string.  If that is the
      case, and application disables Nagle algorithm (``TCP_NODELAY``),
      then writing this small chunk leads to very small packet, and it
      is very inefficient.  An application should be responsible to
      buffer up small chunks of data as necessary to avoid this
      situation.
