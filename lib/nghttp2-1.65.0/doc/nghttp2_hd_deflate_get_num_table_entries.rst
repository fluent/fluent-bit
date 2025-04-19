
nghttp2_hd_deflate_get_num_table_entries
========================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: size_t nghttp2_hd_deflate_get_num_table_entries(nghttp2_hd_deflater *deflater)

    
    Returns the number of entries that header table of *deflater*
    contains.  This is the sum of the number of static table and
    dynamic table, so the return value is at least 61.
