
nghttp2_session_get_outbound_queue_size
=======================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: size_t nghttp2_session_get_outbound_queue_size(nghttp2_session *session)

    
    Returns the number of frames in the outbound queue.  This does not
    include the deferred DATA frames.
