
nghttp2_option_set_max_deflate_dynamic_table_size
=================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_max_deflate_dynamic_table_size(nghttp2_option *option, size_t val)

    
    This option sets the maximum dynamic table size for deflating
    header fields.  The default value is 4KiB.  In HTTP/2, receiver of
    deflated header block can specify maximum dynamic table size.  The
    actual maximum size is the minimum of the size receiver specified
    and this option value.
