
nghttp2_hd_deflate_get_table_entry
==================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: const nghttp2_nv * nghttp2_hd_deflate_get_table_entry(nghttp2_hd_deflater *deflater, size_t idx)

    
    Returns the table entry denoted by *idx* from header table of
    *deflater*.  The *idx* is 1-based, and idx=1 returns first entry of
    static table.  idx=62 returns first entry of dynamic table if it
    exists.  Specifying idx=0 is error, and this function returns NULL.
    If *idx* is strictly greater than the number of entries the tables
    contain, this function returns NULL.
