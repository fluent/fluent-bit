
nghttp2_session_callbacks_new
=============================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_callbacks_new(nghttp2_session_callbacks **callbacks_ptr)

    
    Initializes *\*callbacks_ptr* with NULL values.
    
    The initialized object can be used when initializing multiple
    :type:`nghttp2_session` objects.
    
    When the application finished using this object, it can use
    `nghttp2_session_callbacks_del()` to free its memory.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
