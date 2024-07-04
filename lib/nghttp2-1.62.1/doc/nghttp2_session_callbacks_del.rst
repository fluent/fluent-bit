
nghttp2_session_callbacks_del
=============================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_del(nghttp2_session_callbacks *callbacks)

    
    Frees any resources allocated for *callbacks*.  If *callbacks* is
    ``NULL``, this function does nothing.
