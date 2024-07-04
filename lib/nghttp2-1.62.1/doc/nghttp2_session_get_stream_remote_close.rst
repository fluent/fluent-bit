
nghttp2_session_get_stream_remote_close
=======================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_get_stream_remote_close(nghttp2_session *session, int32_t stream_id)

    
    Returns 1 if remote peer half closed the given stream *stream_id*.
    Returns 0 if it did not.  Returns -1 if no such stream exists.
