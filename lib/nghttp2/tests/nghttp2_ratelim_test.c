/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2023 nghttp2 contributors
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
#include "nghttp2_ratelim_test.h"

#include <stdio.h>

#include <CUnit/CUnit.h>

#include "nghttp2_ratelim.h"

void test_nghttp2_ratelim_update(void) {
  nghttp2_ratelim rl;

  nghttp2_ratelim_init(&rl, 1000, 21);

  CU_ASSERT(1000 == rl.val);
  CU_ASSERT(1000 == rl.burst);
  CU_ASSERT(21 == rl.rate);
  CU_ASSERT(0 == rl.tstamp);

  nghttp2_ratelim_update(&rl, 999);

  CU_ASSERT(1000 == rl.val);
  CU_ASSERT(999 == rl.tstamp);

  nghttp2_ratelim_drain(&rl, 100);

  CU_ASSERT(900 == rl.val);

  nghttp2_ratelim_update(&rl, 1000);

  CU_ASSERT(921 == rl.val);

  nghttp2_ratelim_update(&rl, 1002);

  CU_ASSERT(963 == rl.val);

  nghttp2_ratelim_update(&rl, 1004);

  CU_ASSERT(1000 == rl.val);
  CU_ASSERT(1004 == rl.tstamp);

  /* timer skew */
  nghttp2_ratelim_init(&rl, 1000, 21);
  nghttp2_ratelim_update(&rl, 1);

  CU_ASSERT(1000 == rl.val);

  nghttp2_ratelim_update(&rl, 0);

  CU_ASSERT(1000 == rl.val);

  /* rate * duration overflow */
  nghttp2_ratelim_init(&rl, 1000, 100);
  nghttp2_ratelim_drain(&rl, 999);

  CU_ASSERT(1 == rl.val);

  nghttp2_ratelim_update(&rl, UINT64_MAX);

  CU_ASSERT(1000 == rl.val);

  /* val + rate * duration overflow */
  nghttp2_ratelim_init(&rl, UINT64_MAX - 1, 2);
  nghttp2_ratelim_update(&rl, 1);

  CU_ASSERT(UINT64_MAX - 1 == rl.val);
}

void test_nghttp2_ratelim_drain(void) {
  nghttp2_ratelim rl;

  nghttp2_ratelim_init(&rl, 100, 7);

  CU_ASSERT(-1 == nghttp2_ratelim_drain(&rl, 101));
  CU_ASSERT(0 == nghttp2_ratelim_drain(&rl, 51));
  CU_ASSERT(0 == nghttp2_ratelim_drain(&rl, 49));
  CU_ASSERT(-1 == nghttp2_ratelim_drain(&rl, 1));
}
