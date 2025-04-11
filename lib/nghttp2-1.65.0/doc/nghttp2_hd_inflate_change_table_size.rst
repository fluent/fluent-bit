
nghttp2_hd_inflate_change_table_size
====================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_hd_inflate_change_table_size(nghttp2_hd_inflater *inflater, size_t settings_max_dynamic_table_size)

    
    Changes header table size in the *inflater*.  This may trigger
    eviction in the dynamic table.
    
    The *settings_max_dynamic_table_size* should be the value
    transmitted in SETTINGS_HEADER_TABLE_SIZE.
    
    This function must not be called while header block is being
    inflated.  In other words, this function must be called after
    initialization of *inflater*, but before calling
    `nghttp2_hd_inflate_hd3()`, or after
    `nghttp2_hd_inflate_end_headers()`.  Otherwise,
    `NGHTTP2_ERR_INVALID_STATE` was returned.
    
    This function returns 0 if it succeeds, or one of the following
    negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_INVALID_STATE`
        The function is called while header block is being inflated.
        Probably, application missed to call
        `nghttp2_hd_inflate_end_headers()`.
