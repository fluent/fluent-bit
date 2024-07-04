
nghttp2_option_set_no_closed_streams
====================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_no_closed_streams(nghttp2_option *option, int val)

    
    This option prevents the library from retaining closed streams to
    maintain the priority tree.  If this option is set to nonzero,
    applications can discard closed stream completely to save memory.
    
    If
    :enum:`nghttp2_settings_id.NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES`
    of value of 1 is submitted via `nghttp2_submit_settings()`, any
    closed streams are not retained regardless of this option.
