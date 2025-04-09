
nghttp2_session_want_read
=========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_want_read(nghttp2_session *session)

    
    Returns nonzero value if *session* wants to receive data from the
    remote peer.
    
    If both `nghttp2_session_want_read()` and
    `nghttp2_session_want_write()` return 0, the application should
    drop the connection.
