
nghttp2_session_callbacks_set_data_source_read_length_callback2
===============================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_data_source_read_length_callback2( nghttp2_session_callbacks *cbs, nghttp2_data_source_read_length_callback2 data_source_read_length_callback)

    
    Sets callback function determine the length allowed in
    :type:`nghttp2_data_source_read_callback2`.
