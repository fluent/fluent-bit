
nghttp2_hd_inflate_hd
=====================

Synopsis
--------

*#include <nghttp2/nghttp2.h>*

.. function:: ssize_t nghttp2_hd_inflate_hd(nghttp2_hd_inflater *inflater, nghttp2_nv *nv_out, int *inflate_flags, uint8_t *in, size_t inlen, int in_final)

    
    .. warning::
    
      Deprecated.  Use `nghttp2_hd_inflate_hd2()` instead.
    
    Inflates name/value block stored in *in* with length *inlen*.  This
    function performs decompression.  For each successful emission of
    header name/value pair,
    :enum:`nghttp2_hd_inflate_flag.NGHTTP2_HD_INFLATE_EMIT` is set in
    *\*inflate_flags* and name/value pair is assigned to the *nv_out*
    and the function returns.  The caller must not free the members of
    *nv_out*.
    
    The *nv_out* may include pointers to the memory region in the *in*.
    The caller must retain the *in* while the *nv_out* is used.
    
    The application should call this function repeatedly until the
    ``(*inflate_flags) & NGHTTP2_HD_INFLATE_FINAL`` is nonzero and
    return value is non-negative.  This means the all input values are
    processed successfully.  Then the application must call
    `nghttp2_hd_inflate_end_headers()` to prepare for the next header
    block input.
    
    The caller can feed complete compressed header block.  It also can
    feed it in several chunks.  The caller must set *in_final* to
    nonzero if the given input is the last block of the compressed
    header.
    
    This function returns the number of bytes processed if it succeeds,
    or one of the following negative error codes:
    
    :enum:`nghttp2_error.NGHTTP2_ERR_NOMEM`
        Out of memory.
    :enum:`nghttp2_error.NGHTTP2_ERR_HEADER_COMP`
        Inflation process has failed.
    :enum:`nghttp2_error.NGHTTP2_ERR_BUFFER_ERROR`
        The header field name or value is too large.
    
    Example follows::
    
        int inflate_header_block(nghttp2_hd_inflater *hd_inflater,
                                 uint8_t *in, size_t inlen, int final)
        {
            ssize_t rv;
    
            for(;;) {
                nghttp2_nv nv;
                int inflate_flags = 0;
    
                rv = nghttp2_hd_inflate_hd(hd_inflater, &nv, &inflate_flags,
                                           in, inlen, final);
    
                if(rv < 0) {
                    fprintf(stderr, "inflate failed with error code %zd", rv);
                    return -1;
                }
    
                in += rv;
                inlen -= rv;
    
                if(inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
                    fwrite(nv.name, nv.namelen, 1, stderr);
                    fprintf(stderr, ": ");
                    fwrite(nv.value, nv.valuelen, 1, stderr);
                    fprintf(stderr, "\n");
                }
                if(inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
                    nghttp2_hd_inflate_end_headers(hd_inflater);
                    break;
                }
                if((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 &&
                   inlen == 0) {
                   break;
                }
            }
    
            return 0;
        }
    
