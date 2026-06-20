
nghttp2_option_set_builtin_recv_extension_type
==============================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_builtin_recv_extension_type(nghttp2_option *option, uint8_t type)

    
    Sets extension frame type the application is willing to receive
    using builtin handler.  The *type* is the extension frame type to
    receive, and must be strictly greater than 0x9.  Otherwise, this
    function does nothing.  The application can call this function
    multiple times to set more than one frame type to receive.  The
    application does not have to call this function if it just sends
    extension frames.
    
    If same frame type is passed to both
    `nghttp2_option_set_builtin_recv_extension_type()` and
    `nghttp2_option_set_user_recv_extension_type()`, the latter takes
    precedence.
