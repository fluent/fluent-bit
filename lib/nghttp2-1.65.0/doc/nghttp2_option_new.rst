
nghttp2_option_new
==================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_option_new(nghttp2_option **option_ptr)

    
    Initializes *\*option_ptr* with default values.
    
    When the application finished using this object, it can use
    `nghttp2_option_del()` to free its memory.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
