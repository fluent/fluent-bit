
nghttp2_session_find_stream
===========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: nghttp2_stream * nghttp2_session_find_stream(nghttp2_session *session, int32_t stream_id)

    
    Returns pointer to :type:`nghttp2_stream` object denoted by
    *stream_id*.  If stream was not found, returns NULL.
    
    Returns imaginary root stream (see
    `nghttp2_session_get_root_stream()`) if 0 is given in *stream_id*.
    
    Unless *stream_id* == 0, the returned pointer is valid until next
    call of `nghttp2_session_send()`, `nghttp2_session_mem_send2()`,
    `nghttp2_session_recv()`, and `nghttp2_session_mem_recv2()`.
