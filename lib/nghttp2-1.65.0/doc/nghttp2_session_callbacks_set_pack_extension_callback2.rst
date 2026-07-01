
nghttp2_session_callbacks_set_pack_extension_callback2
======================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_pack_extension_callback2( nghttp2_session_callbacks *cbs, nghttp2_pack_extension_callback2 pack_extension_callback)

    
    Sets callback function invoked when the library asks the
    application to pack extension frame payload in wire format.
