
nghttp2_hd_inflate_new
======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_hd_inflate_new(nghttp2_hd_inflater **inflater_ptr)

    
    Initializes *\*inflater_ptr* for inflating name/values pairs.
    
    If this function fails, *\*inflater_ptr* is left untouched.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
