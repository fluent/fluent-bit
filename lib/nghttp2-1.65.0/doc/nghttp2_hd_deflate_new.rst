
nghttp2_hd_deflate_new
======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_hd_deflate_new(nghttp2_hd_deflater **deflater_ptr, size_t max_deflate_dynamic_table_size)

    
    Initializes *\*deflater_ptr* for deflating name/values pairs.
    
    The *max_deflate_dynamic_table_size* is the upper bound of header
    table size the deflater will use.
    
    If this function fails, *\*deflater_ptr* is left untouched.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
