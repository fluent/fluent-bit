
nghttp2_option_set_server_fallback_rfc7540_priorities
=====================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_server_fallback_rfc7540_priorities(nghttp2_option *option, int val)

    
    .. warning::
       Deprecated.  :rfc:`7540` priorities have been removed.
    
    This function works as before, but it does not take any effect
    against :type:`nghttp2_session`.
