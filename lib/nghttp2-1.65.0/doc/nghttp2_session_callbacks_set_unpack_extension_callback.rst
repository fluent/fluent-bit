
nghttp2_session_callbacks_set_unpack_extension_callback
=======================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_unpack_extension_callback( nghttp2_session_callbacks *cbs, nghttp2_unpack_extension_callback unpack_extension_callback)

    
    Sets callback function invoked when the library asks the
    application to unpack extension frame payload from wire format.
