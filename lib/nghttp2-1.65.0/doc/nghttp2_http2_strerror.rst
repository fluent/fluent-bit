
nghttp2_http2_strerror
======================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: const char *nghttp2_http2_strerror(uint32_t error_code)

    
    Returns string representation of HTTP/2 error code *error_code*
    (e.g., ``PROTOCOL_ERROR`` is returned if ``error_code ==
    NGHTTP2_PROTOCOL_ERROR``).  If string representation is unknown for
    given *error_code*, this function returns string ``unknown``.
