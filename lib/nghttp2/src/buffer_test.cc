/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2015 Tatsuhiro Tsujikawa
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
#include "buffer_test.h"

#include <cstring>
#include <iostream>
#include <tuple>

#include <CUnit/CUnit.h>

#include <nghttp2/nghttp2.h>

#include "buffer.h"

namespace nghttp2 {

void test_buffer_write(void) {
  Buffer<16> b;
  CU_ASSERT(0 == b.rleft());
  CU_ASSERT(16 == b.wleft());

  b.write("012", 3);

  CU_ASSERT(3 == b.rleft());
  CU_ASSERT(13 == b.wleft());
  CU_ASSERT(b.pos == std::begin(b.buf));

  b.drain(3);

  CU_ASSERT(0 == b.rleft());
  CU_ASSERT(13 == b.wleft());
  CU_ASSERT(3 == b.pos - std::begin(b.buf));

  auto n = b.write("0123456789ABCDEF", 16);

  CU_ASSERT(n == 13);

  CU_ASSERT(13 == b.rleft());
  CU_ASSERT(0 == b.wleft());
  CU_ASSERT(3 == b.pos - std::begin(b.buf));
  CU_ASSERT(0 == memcmp(b.pos, "0123456789ABC", 13));

  b.reset();

  CU_ASSERT(0 == b.rleft());
  CU_ASSERT(16 == b.wleft());
  CU_ASSERT(b.pos == std::begin(b.buf));

  b.write(5);

  CU_ASSERT(5 == b.rleft());
  CU_ASSERT(11 == b.wleft());
  CU_ASSERT(b.pos == std::begin(b.buf));
}

} // namespace nghttp2
