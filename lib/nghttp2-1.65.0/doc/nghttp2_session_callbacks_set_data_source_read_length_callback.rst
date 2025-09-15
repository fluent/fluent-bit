
nghttp2_session_callbacks_set_data_source_read_length_callback
==============================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_session_callbacks_set_data_source_read_length_callback( nghttp2_session_callbacks *cbs, nghttp2_data_source_read_length_callback data_source_read_length_callback)

    
    .. warning::
    
      Deprecated.  Use
      `nghttp2_session_callbacks_set_data_source_read_length_callback2()`
      with :type:`nghttp2_data_source_read_length_callback2` instead.
    
    Sets callback function determine the length allowed in
    :type:`nghttp2_data_source_read_callback`.
