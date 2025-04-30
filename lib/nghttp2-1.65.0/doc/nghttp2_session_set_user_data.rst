
nghttp2_session_set_user_data
=============================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_set_user_data(nghttp2_session *session, void *user_data)

    
    Sets *user_data* to *session*, overwriting the existing user data
    specified in `nghttp2_session_client_new()`, or
    `nghttp2_session_server_new()`.
