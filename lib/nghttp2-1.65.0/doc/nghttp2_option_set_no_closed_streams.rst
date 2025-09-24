
nghttp2_option_set_no_closed_streams
====================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_no_closed_streams(nghttp2_option *option, int val)

    
    .. warning::
    
      Deprecated.  Closed streams are not retained anymore.
    
    This function works as before, but it does not take any effect
    against :type:`nghttp2_session`.
