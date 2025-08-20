
nghttp2_option_set_max_reserved_remote_streams
==============================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_max_reserved_remote_streams(nghttp2_option *option, uint32_t val)

    
    RFC 7540 does not enforce any limit on the number of incoming
    reserved streams (in RFC 7540 terms, streams in reserved (remote)
    state).  This only affects client side, since only server can push
    streams.  Malicious server can push arbitrary number of streams,
    and make client's memory exhausted.  This option can set the
    maximum number of such incoming streams to avoid possible memory
    exhaustion.  If this option is set, and pushed streams are
    automatically closed on reception, without calling user provided
    callback, if they exceed the given limit.  The default value is
    200.  If session is configured as server side, this option has no
    effect.  Server can control the number of streams to push.
