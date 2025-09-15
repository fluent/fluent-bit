
nghttp2_session_server_new2
===========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_server_new2(nghttp2_session **session_ptr, const nghttp2_session_callbacks *callbacks, void *user_data, const nghttp2_option *option)

    
    Like `nghttp2_session_server_new()`, but with additional options
    specified in the *option*.
    
    The *option* can be ``NULL`` and the call is equivalent to
    `nghttp2_session_server_new()`.
    
    This function does not take ownership *option*.  The application is
    responsible for freeing *option* if it finishes using the object.
    
    The library code does not refer to *option* after this function
    returns.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
