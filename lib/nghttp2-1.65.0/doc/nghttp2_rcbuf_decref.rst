
nghttp2_rcbuf_decref
====================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_rcbuf_decref(nghttp2_rcbuf *rcbuf)

    
    Decrements the reference count of *rcbuf* by 1.  If the reference
    count becomes zero, the object pointed by *rcbuf* will be freed.
    In this case, application must not use *rcbuf* again.
