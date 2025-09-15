
nghttp2_option_set_no_auto_window_update
========================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_no_auto_window_update(nghttp2_option *option, int val)

    
    This option prevents the library from sending WINDOW_UPDATE for a
    connection automatically.  If this option is set to nonzero, the
    library won't send WINDOW_UPDATE for DATA until application calls
    `nghttp2_session_consume()` to indicate the consumed amount of
    data.  Don't use `nghttp2_submit_window_update()` for this purpose.
    By default, this option is set to zero.
