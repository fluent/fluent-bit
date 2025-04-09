
nghttp2_session_get_stream_user_data
====================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void * nghttp2_session_get_stream_user_data(nghttp2_session *session, int32_t stream_id)

    
    Returns stream_user_data for the stream *stream_id*.  The
    stream_user_data is provided by `nghttp2_submit_request2()`,
    `nghttp2_submit_headers()` or
    `nghttp2_session_set_stream_user_data()`.  Unless it is set using
    `nghttp2_session_set_stream_user_data()`, if the stream is
    initiated by the remote endpoint, stream_user_data is always
    ``NULL``.  If the stream does not exist, this function returns
    ``NULL``.
