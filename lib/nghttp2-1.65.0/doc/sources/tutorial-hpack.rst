Tutorial: HPACK API
===================

In this tutorial, we describe basic use of nghttp2's HPACK API.  We
briefly describe the APIs for deflating and inflating header fields.
The full example of using these APIs, `deflate.c`_, is attached at the
end of this page. It also resides in the examples directory in the
archive or repository.

Deflating (encoding) headers
----------------------------

First we need to initialize a :type:`nghttp2_hd_deflater` object using
the `nghttp2_hd_deflate_new()` function::

    int nghttp2_hd_deflate_new(nghttp2_hd_deflater **deflater_ptr,
                               size_t deflate_hd_table_bufsize_max);

This function allocates a :type:`nghttp2_hd_deflater` object,
initializes it, and assigns its pointer to ``*deflater_ptr``. The
*deflate_hd_table_bufsize_max* is the upper bound of header table size
the deflater will use.  This will limit the memory usage by the
deflater object for the dynamic header table.  If in doubt, just
specify 4096 here, which is the default upper bound of dynamic header
table buffer size.

To encode header fields, use the `nghttp2_hd_deflate_hd2()` function::

    nghttp2_ssize nghttp2_hd_deflate_hd2(nghttp2_hd_deflater *deflater,
                                         uint8_t *buf, size_t buflen,
                                         const nghttp2_nv *nva, size_t nvlen);

The *deflater* is the deflater object initialized by
`nghttp2_hd_deflate_new()` described above. The encoded byte string is
written to the buffer *buf*, which has length *buflen*.  The *nva* is
a pointer to an array of headers fields, each of type
:type:`nghttp2_nv`.  *nvlen* is the number of header fields which
*nva* contains.

It is important to initialize and assign all members of
:type:`nghttp2_nv`. For security sensitive header fields (such as
cookies), set the :macro:`NGHTTP2_NV_FLAG_NO_INDEX` flag in
:member:`nghttp2_nv.flags`.  Setting this flag prevents recovery of
sensitive header fields by compression based attacks: This is achieved
by not inserting the header field into the dynamic header table.

`nghttp2_hd_deflate_hd2()` processes all headers given in *nva*.  The
*nva* must include all request or response header fields to be sent in
one HEADERS (or optionally following (multiple) CONTINUATION
frame(s)).  The *buf* must have enough space to store the encoded
result, otherwise the function will fail.  To estimate the upper bound
of the encoded result length, use `nghttp2_hd_deflate_bound()`::

    size_t nghttp2_hd_deflate_bound(nghttp2_hd_deflater *deflater,
                                    const nghttp2_nv *nva, size_t nvlen);

Pass this function the same parameters (*deflater*, *nva*, and
*nvlen*) which will be passed to `nghttp2_hd_deflate_hd2()`.

Subsequent calls to `nghttp2_hd_deflate_hd2()` will use the current
encoder state and perform differential encoding, which yields HPAC's
fundamental compression gain.

If `nghttp2_hd_deflate_hd2()` fails, the failure is fatal and any
further calls with the same deflater object will fail.  Thus it's very
important to use `nghttp2_hd_deflate_bound()` to determine the
required size of the output buffer.

To delete a :type:`nghttp2_hd_deflater` object, use the
`nghttp2_hd_deflate_del()` function.

Inflating (decoding) headers
----------------------------

A :type:`nghttp2_hd_inflater` object is used to inflate compressed
header data.  To initialize the object, use
`nghttp2_hd_inflate_new()`::

    int nghttp2_hd_inflate_new(nghttp2_hd_inflater **inflater_ptr);

To inflate header data, use `nghttp2_hd_inflate_hd3()`::

    nghttp2_ssize nghttp2_hd_inflate_hd3(nghttp2_hd_inflater *inflater,
					 nghttp2_nv *nv_out, int *inflate_flags,
					 const uint8_t *in, size_t inlen,
					 int in_final);

`nghttp2_hd_inflate_hd3()` reads a stream of bytes and outputs a
single header field at a time. Multiple calls are normally required to
read a full stream of bytes and output all of the header fields.

The *inflater* is the inflater object initialized above.  The *nv_out*
is a pointer to a :type:`nghttp2_nv` into which one header field may
be stored.  The *in* is a pointer to input data, and *inlen* is its
length.  The caller is not required to specify the whole deflated
header data via *in* at once: Instead it can call this function
multiple times as additional data bytes become available.  If
*in_final* is nonzero, it tells the function that the passed data is
the final sequence of deflated header data.

The *inflate_flags* is an output parameter; on success the function
sets it to a bitset of flags.  It will be described later.

This function returns when each header field is inflated.  When this
happens, the function sets the :macro:`NGHTTP2_HD_INFLATE_EMIT` flag
in *inflate_flags*, and a header field is stored in *nv_out*.  The
return value indicates the number of bytes read from *in* processed so
far, which may be less than *inlen*.  The caller should call the
function repeatedly until all bytes are processed. Processed bytes
should be removed from *in*, and *inlen* should be adjusted
appropriately.

If *in_final* is nonzero and all given data was processed, the
function sets the :macro:`NGHTTP2_HD_INFLATE_FINAL` flag in
*inflate_flags*.  When you see this flag set, call the
`nghttp2_hd_inflate_end_headers()` function.

If *in_final* is zero and the :macro:`NGHTTP2_HD_INFLATE_EMIT` flag is
not set, it indicates that all given data was processed.  The caller
is required to pass additional data.

Example usage of `nghttp2_hd_inflate_hd3()` is shown in the
`inflate_header_block()` function in `deflate.c`_.

Finally, to delete a :type:`nghttp2_hd_inflater` object, use
`nghttp2_hd_inflate_del()`.
