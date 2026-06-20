
nghttp2_session_get_next_stream_id
==================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: uint32_t nghttp2_session_get_next_stream_id(nghttp2_session *session)

    
    Returns the next outgoing stream ID.  Notice that return type is
    uint32_t.  If we run out of stream ID for this session, this
    function returns 1 << 31.
