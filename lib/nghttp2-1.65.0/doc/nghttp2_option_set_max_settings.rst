
nghttp2_option_set_max_settings
===============================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_max_settings(nghttp2_option *option, size_t val)

    
    This function sets the maximum number of SETTINGS entries per
    SETTINGS frame that will be accepted. If more than those entries
    are received, the peer is considered to be misbehaving and session
    will be closed. The default value is 32.
