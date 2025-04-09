
nghttp2_session_callbacks_set_select_padding_callback2
======================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_select_padding_callback2( nghttp2_session_callbacks *cbs, nghttp2_select_padding_callback2 select_padding_callback)

    
    Sets callback function invoked when the library asks application
    how many padding bytes are required for the transmission of the
    given frame.
