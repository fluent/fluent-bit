
nghttp2_hd_deflate_bound
========================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: size_t nghttp2_hd_deflate_bound(nghttp2_hd_deflater *deflater, const nghttp2_nv *nva, size_t nvlen)

    
    Returns an upper bound on the compressed size after deflation of
    *nva* of length *nvlen*.
