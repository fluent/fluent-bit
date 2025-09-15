
nghttp2_session_callbacks_set_pack_extension_callback
=====================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_pack_extension_callback( nghttp2_session_callbacks *cbs, nghttp2_pack_extension_callback pack_extension_callback)

    
    .. warning::
    
      Deprecated.  Use
      `nghttp2_session_callbacks_set_pack_extension_callback2()` with
      :type:`nghttp2_pack_extension_callback2` instead.
    
    Sets callback function invoked when the library asks the
    application to pack extension frame payload in wire format.
