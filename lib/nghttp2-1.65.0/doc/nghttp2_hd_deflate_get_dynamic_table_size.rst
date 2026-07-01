
nghttp2_hd_deflate_get_dynamic_table_size
=========================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: size_t nghttp2_hd_deflate_get_dynamic_table_size(nghttp2_hd_deflater *deflater)

    
    Returns the used dynamic table size, including the overhead 32
    bytes per entry described in RFC 7541.
