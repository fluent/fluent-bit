
nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation
================================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation( nghttp2_option *option, int val)

    
    This option, if set to nonzero, turns off RFC 9113 leading and
    trailing white spaces validation against HTTP field value.  Some
    important fields, such as HTTP/2 pseudo header fields, are
    validated more strictly and this option does not apply to them.
