/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
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
#include "nghttp2_helper_test.h"

#include <stdio.h>

#include <CUnit/CUnit.h>

#include "nghttp2_helper.h"

void test_nghttp2_adjust_local_window_size(void) {
  int32_t local_window_size = 100;
  int32_t recv_window_size = 50;
  int32_t recv_reduction = 0;
  int32_t delta;

  delta = 0;
  CU_ASSERT(0 == nghttp2_adjust_local_window_size(&local_window_size,
                                                  &recv_window_size,
                                                  &recv_reduction, &delta));
  CU_ASSERT(100 == local_window_size);
  CU_ASSERT(50 == recv_window_size);
  CU_ASSERT(0 == recv_reduction);
  CU_ASSERT(0 == delta);

  delta = 49;
  CU_ASSERT(0 == nghttp2_adjust_local_window_size(&local_window_size,
                                                  &recv_window_size,
                                                  &recv_reduction, &delta));
  CU_ASSERT(100 == local_window_size);
  CU_ASSERT(1 == recv_window_size);
  CU_ASSERT(0 == recv_reduction);
  CU_ASSERT(49 == delta);

  delta = 1;
  CU_ASSERT(0 == nghttp2_adjust_local_window_size(&local_window_size,
                                                  &recv_window_size,
                                                  &recv_reduction, &delta));
  CU_ASSERT(100 == local_window_size);
  CU_ASSERT(0 == recv_window_size);
  CU_ASSERT(0 == recv_reduction);
  CU_ASSERT(1 == delta);

  delta = 1;
  CU_ASSERT(0 == nghttp2_adjust_local_window_size(&local_window_size,
                                                  &recv_window_size,
                                                  &recv_reduction, &delta));
  CU_ASSERT(101 == local_window_size);
  CU_ASSERT(0 == recv_window_size);
  CU_ASSERT(0 == recv_reduction);
  CU_ASSERT(1 == delta);

  delta = -1;
  CU_ASSERT(0 == nghttp2_adjust_local_window_size(&local_window_size,
                                                  &recv_window_size,
                                                  &recv_reduction, &delta));
  CU_ASSERT(100 == local_window_size);
  CU_ASSERT(-1 == recv_window_size);
  CU_ASSERT(1 == recv_reduction);
  CU_ASSERT(0 == delta);

  delta = 1;
  CU_ASSERT(0 == nghttp2_adjust_local_window_size(&local_window_size,
                                                  &recv_window_size,
                                                  &recv_reduction, &delta));
  CU_ASSERT(101 == local_window_size);
  CU_ASSERT(0 == recv_window_size);
  CU_ASSERT(0 == recv_reduction);
  CU_ASSERT(0 == delta);

  delta = 100;
  CU_ASSERT(0 == nghttp2_adjust_local_window_size(&local_window_size,
                                                  &recv_window_size,
                                                  &recv_reduction, &delta));
  CU_ASSERT(201 == local_window_size);
  CU_ASSERT(0 == recv_window_size);
  CU_ASSERT(0 == recv_reduction);
  CU_ASSERT(100 == delta);

  delta = -3;
  CU_ASSERT(0 == nghttp2_adjust_local_window_size(&local_window_size,
                                                  &recv_window_size,
                                                  &recv_reduction, &delta));
  CU_ASSERT(198 == local_window_size);
  CU_ASSERT(-3 == recv_window_size);
  CU_ASSERT(3 == recv_reduction);
  CU_ASSERT(0 == delta);

  recv_window_size += 3;

  delta = 3;
  CU_ASSERT(0 == nghttp2_adjust_local_window_size(&local_window_size,
                                                  &recv_window_size,
                                                  &recv_reduction, &delta));
  CU_ASSERT(201 == local_window_size);
  CU_ASSERT(3 == recv_window_size);
  CU_ASSERT(0 == recv_reduction);
  CU_ASSERT(0 == delta);

  local_window_size = 100;
  recv_window_size = 50;
  recv_reduction = 0;
  delta = INT32_MAX;
  CU_ASSERT(NGHTTP2_ERR_FLOW_CONTROL ==
            nghttp2_adjust_local_window_size(&local_window_size,
                                             &recv_window_size, &recv_reduction,
                                             &delta));
  CU_ASSERT(100 == local_window_size);
  CU_ASSERT(50 == recv_window_size);
  CU_ASSERT(0 == recv_reduction);
  CU_ASSERT(INT32_MAX == delta);

  delta = INT32_MIN;
  CU_ASSERT(NGHTTP2_ERR_FLOW_CONTROL ==
            nghttp2_adjust_local_window_size(&local_window_size,
                                             &recv_window_size, &recv_reduction,
                                             &delta));
  CU_ASSERT(100 == local_window_size);
  CU_ASSERT(50 == recv_window_size);
  CU_ASSERT(0 == recv_reduction);
  CU_ASSERT(INT32_MIN == delta);
}

#define check_header_name(S)                                                   \
  nghttp2_check_header_name((const uint8_t *)S, sizeof(S) - 1)

void test_nghttp2_check_header_name(void) {
  CU_ASSERT(check_header_name(":path"));
  CU_ASSERT(check_header_name("path"));
  CU_ASSERT(check_header_name("!#$%&'*+-.^_`|~"));
  CU_ASSERT(!check_header_name(":PATH"));
  CU_ASSERT(!check_header_name("path:"));
  CU_ASSERT(!check_header_name(""));
  CU_ASSERT(!check_header_name(":"));
}

#define check_header_value(S)                                                  \
  nghttp2_check_header_value((const uint8_t *)S, sizeof(S) - 1)

void test_nghttp2_check_header_value(void) {
  uint8_t goodval[] = {'a', 'b', 0x80u, 'c', 0xffu, 'd', '\t', ' '};
  uint8_t badval1[] = {'a', 0x1fu, 'b'};
  uint8_t badval2[] = {'a', 0x7fu, 'b'};

  CU_ASSERT(check_header_value(" !|}~"));
  CU_ASSERT(check_header_value(goodval));
  CU_ASSERT(!check_header_value(badval1));
  CU_ASSERT(!check_header_value(badval2));
  CU_ASSERT(check_header_value(""));
  CU_ASSERT(check_header_value(" "));
  CU_ASSERT(check_header_value("\t"));
}

#define check_header_value_rfc9113(S)                                          \
  nghttp2_check_header_value_rfc9113((const uint8_t *)S, sizeof(S) - 1)

void test_nghttp2_check_header_value_rfc9113(void) {
  uint8_t goodval[] = {'a', 'b', 0x80u, 'c', 0xffu, 'd'};
  uint8_t badval1[] = {'a', 0x1fu, 'b'};
  uint8_t badval2[] = {'a', 0x7fu, 'b'};

  CU_ASSERT(check_header_value_rfc9113("!|}~"));
  CU_ASSERT(!check_header_value_rfc9113(" !|}~"));
  CU_ASSERT(!check_header_value_rfc9113("!|}~ "));
  CU_ASSERT(!check_header_value_rfc9113("\t!|}~"));
  CU_ASSERT(!check_header_value_rfc9113("!|}~\t"));
  CU_ASSERT(check_header_value_rfc9113(goodval));
  CU_ASSERT(!check_header_value_rfc9113(badval1));
  CU_ASSERT(!check_header_value_rfc9113(badval2));
  CU_ASSERT(check_header_value_rfc9113(""));
  CU_ASSERT(!check_header_value_rfc9113(" "));
  CU_ASSERT(!check_header_value_rfc9113("\t"));
}
