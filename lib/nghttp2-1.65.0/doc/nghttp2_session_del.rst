
nghttp2_session_del
===================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_del(nghttp2_session *session)

    
    Frees any resources allocated for *session*.  If *session* is
    ``NULL``, this function does nothing.
