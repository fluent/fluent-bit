
nghttp2_session_callbacks_set_error_callback
============================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_error_callback( nghttp2_session_callbacks *cbs, nghttp2_error_callback error_callback)

    
    .. warning::
    
      Deprecated.  Use
      `nghttp2_session_callbacks_set_error_callback2()` with
      :type:`nghttp2_error_callback2` instead.
    
    Sets callback function invoked when library tells error message to
    the application.
    
    If both :type:`nghttp2_error_callback` and
    :type:`nghttp2_error_callback2` are set, the latter takes
    precedence.
