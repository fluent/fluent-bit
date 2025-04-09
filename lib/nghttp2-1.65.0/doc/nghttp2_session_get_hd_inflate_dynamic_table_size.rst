
nghttp2_session_get_hd_inflate_dynamic_table_size
=================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: size_t nghttp2_session_get_hd_inflate_dynamic_table_size(nghttp2_session *session)

    
    Returns the current dynamic table size of HPACK inflater, including
    the overhead 32 bytes per entry described in RFC 7541.
