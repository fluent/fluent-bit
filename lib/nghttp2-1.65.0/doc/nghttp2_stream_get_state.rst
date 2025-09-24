
nghttp2_stream_get_state
========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: nghttp2_stream_proto_state nghttp2_stream_get_state(nghttp2_stream *stream)

    
    Returns state of *stream*.  The root stream retrieved by
    `nghttp2_session_get_root_stream()` will have stream state
    :enum:`nghttp2_stream_proto_state.NGHTTP2_STREAM_STATE_IDLE`.
