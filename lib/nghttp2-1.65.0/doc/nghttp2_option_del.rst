
nghttp2_option_del
==================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_del(nghttp2_option *option)

    
    Frees any resources allocated for *option*.  If *option* is
    ``NULL``, this function does nothing.
