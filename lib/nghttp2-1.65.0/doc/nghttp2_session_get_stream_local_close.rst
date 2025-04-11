
nghttp2_session_get_stream_local_close
======================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_get_stream_local_close(nghttp2_session *session, int32_t stream_id)

    
    Returns 1 if local peer half closed the given stream *stream_id*.
    Returns 0 if it did not.  Returns -1 if no such stream exists.
