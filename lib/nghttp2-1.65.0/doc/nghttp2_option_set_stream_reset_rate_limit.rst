
nghttp2_option_set_stream_reset_rate_limit
==========================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_stream_reset_rate_limit(nghttp2_option *option, uint64_t burst, uint64_t rate)

    
    This function sets the rate limit for the incoming stream reset
    (RST_STREAM frame).  It is server use only.  It is a token-bucket
    based rate limiter.  *burst* specifies the number of tokens that is
    initially available.  The maximum number of tokens is capped to
    this value.  *rate* specifies the number of tokens that are
    regenerated per second.  An incoming RST_STREAM consumes one token.
    If there is no token available, GOAWAY is sent to tear down the
    connection.  *burst* and *rate* default to 1000 and 33
    respectively.
