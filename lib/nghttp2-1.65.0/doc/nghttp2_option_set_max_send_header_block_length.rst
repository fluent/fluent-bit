
nghttp2_option_set_max_send_header_block_length
===============================================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: void nghttp2_option_set_max_send_header_block_length(nghttp2_option *option, size_t val)

    
    This option sets the maximum length of header block (a set of
    header fields per one HEADERS frame) to send.  The length of a
    given set of header fields is calculated using
    `nghttp2_hd_deflate_bound()`.  The default value is 64KiB.  If
    application attempts to send header fields larger than this limit,
    the transmission of the frame fails with error code
    :enum:`nghttp2_error.NGHTTP2_ERR_FRAME_SIZE_ERROR`.
