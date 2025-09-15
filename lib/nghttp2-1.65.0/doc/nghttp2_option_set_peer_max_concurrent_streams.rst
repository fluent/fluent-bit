
nghttp2_option_set_peer_max_concurrent_streams
==============================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_peer_max_concurrent_streams(nghttp2_option *option, uint32_t val)

    
    This option sets the SETTINGS_MAX_CONCURRENT_STREAMS value of
    remote endpoint as if it is received in SETTINGS frame.  Without
    specifying this option, the maximum number of outgoing concurrent
    streams is initially limited to 100 to avoid issues when the local
    endpoint submits lots of requests before receiving initial SETTINGS
    frame from the remote endpoint, since sending them at once to the
    remote endpoint could lead to rejection of some of the requests.
    This value will be overwritten when the local endpoint receives
    initial SETTINGS frame from the remote endpoint, either to the
    value advertised in SETTINGS_MAX_CONCURRENT_STREAMS or to the
    default value (unlimited) if none was advertised.
