
nghttp2_rcbuf_is_static
=======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: int nghttp2_rcbuf_is_static(const nghttp2_rcbuf *rcbuf)

    
    Returns nonzero if the underlying buffer is statically allocated,
    and 0 otherwise. This can be useful for language bindings that wish
    to avoid creating duplicate strings for these buffers.
