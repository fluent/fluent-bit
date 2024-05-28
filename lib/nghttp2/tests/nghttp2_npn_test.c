/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2012 Twist Inc.
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
#include "nghttp2_npn_test.h"

#include <stdio.h>
#include <string.h>

#include <CUnit/CUnit.h>
#include <nghttp2/nghttp2.h>

static void http2(void) {
  const unsigned char p[] = {8,   'h', 't', 't', 'p', '/', '1', '.', '1', 2,
                             'h', '2', 6,   's', 'p', 'd', 'y', '/', '3'};
  unsigned char outlen;
  unsigned char *out;
  CU_ASSERT(1 == nghttp2_select_next_protocol(&out, &outlen, p, sizeof(p)));
  CU_ASSERT(NGHTTP2_PROTO_VERSION_ID_LEN == outlen);
  CU_ASSERT(memcmp(NGHTTP2_PROTO_VERSION_ID, out, outlen) == 0);
}

static void http11(void) {
  const unsigned char spdy[] = {
      6,   's', 'p', 'd', 'y', '/', '4', 8,   's', 'p', 'd', 'y', '/',
      '2', '.', '1', 8,   'h', 't', 't', 'p', '/', '1', '.', '1',
  };
  unsigned char outlen;
  unsigned char *out;
  CU_ASSERT(0 ==
            nghttp2_select_next_protocol(&out, &outlen, spdy, sizeof(spdy)));
  CU_ASSERT(8 == outlen);
  CU_ASSERT(memcmp("http/1.1", out, outlen) == 0);
}

static void no_overlap(void) {
  const unsigned char spdy[] = {
      6,   's', 'p', 'd', 'y', '/', '4', 8,   's', 'p', 'd', 'y', '/',
      '2', '.', '1', 8,   'h', 't', 't', 'p', '/', '1', '.', '0',
  };
  unsigned char outlen = 0;
  unsigned char *out = NULL;
  CU_ASSERT(-1 ==
            nghttp2_select_next_protocol(&out, &outlen, spdy, sizeof(spdy)));
  CU_ASSERT(0 == outlen);
  CU_ASSERT(NULL == out);
}

void test_nghttp2_npn(void) {
  http2();
  http11();
  no_overlap();
}
