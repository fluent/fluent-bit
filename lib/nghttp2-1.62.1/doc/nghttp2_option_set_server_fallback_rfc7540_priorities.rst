
nghttp2_option_set_server_fallback_rfc7540_priorities
=====================================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_server_fallback_rfc7540_priorities(nghttp2_option *option, int val)

    
    This option, if set to nonzero, allows server to fallback to
    :rfc:`7540` priorities if SETTINGS_NO_RFC7540_PRIORITIES was not
    received from client, and server submitted
    :enum:`nghttp2_settings_id.NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES`
    = 1 via `nghttp2_submit_settings()`.  Most of the advanced
    functionality for RFC 7540 priorities are still disabled.  This
    fallback only enables the minimal feature set of RFC 7540
    priorities to deal with priority signaling from client.
    
    Client session ignores this option.
