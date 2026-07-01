
nghttp2_option_set_max_continuations
====================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_max_continuations(nghttp2_option *option, size_t val)

    
    This function sets the maximum number of CONTINUATION frames
    following an incoming HEADER frame.  If more than those frames are
    received, the remote endpoint is considered to be misbehaving and
    session will be closed.  The default value is 8.
