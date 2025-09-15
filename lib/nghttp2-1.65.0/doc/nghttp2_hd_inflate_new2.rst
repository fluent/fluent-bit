
nghttp2_hd_inflate_new2
=======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_hd_inflate_new2(nghttp2_hd_inflater **inflater_ptr, nghttp2_mem *mem)

    
    Like `nghttp2_hd_inflate_new()`, but with additional custom memory
    allocator specified in the *mem*.
    
    The *mem* can be ``NULL`` and the call is equivalent to
    `nghttp2_hd_inflate_new()`.
    
    This function does not take ownership *mem*.  The application is
    responsible for freeing *mem*.
    
    The library code does not refer to *mem* pointer after this
    function returns, so the application can safely free it.
