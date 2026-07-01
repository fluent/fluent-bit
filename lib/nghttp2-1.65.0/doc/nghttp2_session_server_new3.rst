
nghttp2_session_server_new3
===========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_session_server_new3( nghttp2_session **session_ptr, const nghttp2_session_callbacks *callbacks, void *user_data, const nghttp2_option *option, nghttp2_mem *mem)

    
    Like `nghttp2_session_server_new2()`, but with additional custom
    memory allocator specified in the *mem*.
    
    The *mem* can be ``NULL`` and the call is equivalent to
    `nghttp2_session_server_new2()`.
    
    This function does not take ownership *mem*.  The application is
    responsible for freeing *mem*.
    
    The library code does not refer to *mem* pointer after this
    function returns, so the application can safely free it.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
