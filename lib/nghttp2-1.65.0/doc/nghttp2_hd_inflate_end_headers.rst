
nghttp2_hd_inflate_end_headers
==============================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_hd_inflate_end_headers(nghttp2_hd_inflater *inflater)

    
    Signals the end of decompression for one header block.
    
    This function returns 0 if it succeeds. Currently this function
    always succeeds.
