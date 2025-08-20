
nghttp2_hd_deflate_hd
=====================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: ssize_t nghttp2_hd_deflate_hd(nghttp2_hd_deflater *deflater, uint8_t *buf, size_t buflen, const nghttp2_nv *nva, size_t nvlen)

    
    .. warning::
    
      Deprecated.  Use `nghttp2_hd_deflate_hd2()` instead.
    
    Deflates the *nva*, which has the *nvlen* name/value pairs, into
    the *buf* of length *buflen*.
    
    If *buf* is not large enough to store the deflated header block,
    this function fails with
    :enum:`nghttp2_error.NGHTTP2_ERR_INSUFF_BUFSIZE`.  The caller
    should use `nghttp2_hd_deflate_bound()` to know the upper bound of
    buffer size required to deflate given header name/value pairs.
    
    Once this function fails, subsequent call of this function always
    returns :enum:`nghttp2_error.NGHTTP2_ERR_HEADER_COMP`.
    
    After this function returns, it is safe to delete the *nva*.
    
    This function returns the number of bytes written to *buf* if it
    succeeds, or one of the following negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_HEADER_COMP`
        Deflation process has failed.
    :enum:`nghttp2_error.NGHTTP2_ERR_INSUFF_BUFSIZE`
        The provided *buflen* size is too small to hold the output.
