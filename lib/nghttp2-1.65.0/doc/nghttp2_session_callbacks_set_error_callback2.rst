
nghttp2_session_callbacks_set_error_callback2
=============================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_error_callback2( nghttp2_session_callbacks *cbs, nghttp2_error_callback2 error_callback2)

    
    Sets callback function invoked when library tells error code, and
    message to the application.
    
    If both :type:`nghttp2_error_callback` and
    :type:`nghttp2_error_callback2` are set, the latter takes
    precedence.
