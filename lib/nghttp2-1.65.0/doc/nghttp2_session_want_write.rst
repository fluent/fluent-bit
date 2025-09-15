
nghttp2_session_want_write
==========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_want_write(nghttp2_session *session)

    
    Returns nonzero value if *session* wants to send data to the remote
    peer.
    
    If both `nghttp2_session_want_read()` and
    `nghttp2_session_want_write()` return 0, the application should
    drop the connection.
