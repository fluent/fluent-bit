
nghttp2_option_set_no_recv_client_magic
=======================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_no_recv_client_magic(nghttp2_option *option, int val)

    
    By default, nghttp2 library, if configured as server, requires
    first 24 bytes of client magic byte string (MAGIC).  In most cases,
    this will simplify the implementation of server.  But sometimes
    server may want to detect the application protocol based on first
    few bytes on clear text communication.
    
    If this option is used with nonzero *val*, nghttp2 library does not
    handle MAGIC.  It still checks following SETTINGS frame.  This
    means that applications should deal with MAGIC by themselves.
    
    If this option is not used or used with zero value, if MAGIC does
    not match :macro:`NGHTTP2_CLIENT_MAGIC`, `nghttp2_session_recv()`
    and `nghttp2_session_mem_recv2()` will return error
    :enum:`nghttp2_error.NGHTTP2_ERR_BAD_CLIENT_MAGIC`, which is fatal
    error.
