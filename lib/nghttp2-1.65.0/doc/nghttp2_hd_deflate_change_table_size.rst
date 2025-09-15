
nghttp2_hd_deflate_change_table_size
====================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_hd_deflate_change_table_size(nghttp2_hd_deflater *deflater, size_t settings_max_dynamic_table_size)

    
    Changes header table size of the *deflater* to
    *settings_max_dynamic_table_size* bytes.  This may trigger eviction
    in the dynamic table.
    
    The *settings_max_dynamic_table_size* should be the value received
    in SETTINGS_HEADER_TABLE_SIZE.
    
    The deflater never uses more memory than
    ``max_deflate_dynamic_table_size`` bytes specified in
    `nghttp2_hd_deflate_new()`.  Therefore, if
    *settings_max_dynamic_table_size* >
    ``max_deflate_dynamic_table_size``, resulting maximum table size
    becomes ``max_deflate_dynamic_table_size``.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
