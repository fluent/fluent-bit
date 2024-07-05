/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "nghttp2_gzip_test.h"

#include <stdio.h>
#include <assert.h>

#include <CUnit/CUnit.h>

#include <zlib.h>

#include "nghttp2_gzip.h"

static size_t deflate_data(uint8_t *out, size_t outlen, const uint8_t *in,
                           size_t inlen) {
  int rv;
  z_stream zst = {0};

  rv = deflateInit(&zst, Z_DEFAULT_COMPRESSION);
  CU_ASSERT(rv == Z_OK);

  zst.avail_in = (unsigned int)inlen;
  zst.next_in = (uint8_t *)in;
  zst.avail_out = (unsigned int)outlen;
  zst.next_out = out;
  rv = deflate(&zst, Z_SYNC_FLUSH);
  CU_ASSERT(rv == Z_OK);

  deflateEnd(&zst);

  return outlen - zst.avail_out;
}

static const char input[] =
    "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND "
    "EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF "
    "MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND "
    "NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE "
    "LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION "
    "OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION "
    "WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.";

void test_nghttp2_gzip_inflate(void) {
  nghttp2_gzip *inflater;
  uint8_t in[4096], out[4096], *inptr;
  size_t inlen = sizeof(in);
  size_t inproclen, outproclen;
  const char *inputptr = input;

  inlen = deflate_data(in, inlen, (const uint8_t *)input, sizeof(input) - 1);

  CU_ASSERT(0 == nghttp2_gzip_inflate_new(&inflater));
  /* First 16 bytes */
  inptr = in;
  inproclen = inlen;
  outproclen = 16;
  CU_ASSERT(
      0 == nghttp2_gzip_inflate(inflater, out, &outproclen, inptr, &inproclen));
  CU_ASSERT(16 == outproclen);
  CU_ASSERT(inproclen > 0);
  CU_ASSERT(0 == memcmp(inputptr, out, outproclen));
  /* Next 32 bytes */
  inptr += inproclen;
  inlen -= inproclen;
  inproclen = inlen;
  inputptr += outproclen;
  outproclen = 32;
  CU_ASSERT(
      0 == nghttp2_gzip_inflate(inflater, out, &outproclen, inptr, &inproclen));
  CU_ASSERT(32 == outproclen);
  CU_ASSERT(inproclen > 0);
  CU_ASSERT(0 == memcmp(inputptr, out, outproclen));
  /* Rest */
  inptr += inproclen;
  inlen -= inproclen;
  inproclen = inlen;
  inputptr += outproclen;
  outproclen = sizeof(out);
  CU_ASSERT(
      0 == nghttp2_gzip_inflate(inflater, out, &outproclen, inptr, &inproclen));
  CU_ASSERT(sizeof(input) - 49 == outproclen);
  CU_ASSERT(inproclen > 0);
  CU_ASSERT(0 == memcmp(inputptr, out, outproclen));

  inlen -= inproclen;
  CU_ASSERT(0 == inlen);

  nghttp2_gzip_inflate_del(inflater);
}
