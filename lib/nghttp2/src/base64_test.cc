/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2016 Tatsuhiro Tsujikawa
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
#include "base64_test.h"

#include <cstring>
#include <iostream>

#include <CUnit/CUnit.h>

#include <nghttp2/nghttp2.h>

#include "base64.h"

namespace nghttp2 {

void test_base64_encode(void) {
  {
    std::string in = "\xff";
    auto out = base64::encode(std::begin(in), std::end(in));
    CU_ASSERT("/w==" == out);
  }
  {
    std::string in = "\xff\xfe";
    auto out = base64::encode(std::begin(in), std::end(in));
    CU_ASSERT("//4=" == out);
  }
  {
    std::string in = "\xff\xfe\xfd";
    auto out = base64::encode(std::begin(in), std::end(in));
    CU_ASSERT("//79" == out);
  }
  {
    std::string in = "\xff\xfe\xfd\xfc";
    auto out = base64::encode(std::begin(in), std::end(in));
    CU_ASSERT("//79/A==" == out);
  }
}

void test_base64_decode(void) {
  BlockAllocator balloc(4096, 4096);
  {
    std::string in = "/w==";
    auto out = base64::decode(std::begin(in), std::end(in));
    CU_ASSERT("\xff" == out);
    CU_ASSERT("\xff" == base64::decode(balloc, std::begin(in), std::end(in)));
  }
  {
    std::string in = "//4=";
    auto out = base64::decode(std::begin(in), std::end(in));
    CU_ASSERT("\xff\xfe" == out);
    CU_ASSERT("\xff\xfe" ==
              base64::decode(balloc, std::begin(in), std::end(in)));
  }
  {
    std::string in = "//79";
    auto out = base64::decode(std::begin(in), std::end(in));
    CU_ASSERT("\xff\xfe\xfd" == out);
    CU_ASSERT("\xff\xfe\xfd" ==
              base64::decode(balloc, std::begin(in), std::end(in)));
  }
  {
    std::string in = "//79/A==";
    auto out = base64::decode(std::begin(in), std::end(in));
    CU_ASSERT("\xff\xfe\xfd\xfc" == out);
    CU_ASSERT("\xff\xfe\xfd\xfc" ==
              base64::decode(balloc, std::begin(in), std::end(in)));
  }
  {
    // we check the number of valid input must be multiples of 4
    std::string in = "//79=";
    auto out = base64::decode(std::begin(in), std::end(in));
    CU_ASSERT("" == out);
    CU_ASSERT("" == base64::decode(balloc, std::begin(in), std::end(in)));
  }
  {
    // ending invalid character at the boundary of multiples of 4 is
    // bad
    std::string in = "bmdodHRw\n";
    auto out = base64::decode(std::begin(in), std::end(in));
    CU_ASSERT("" == out);
    CU_ASSERT("" == base64::decode(balloc, std::begin(in), std::end(in)));
  }
  {
    // after seeing '=', subsequent input must be also '='.
    std::string in = "//79/A=A";
    auto out = base64::decode(std::begin(in), std::end(in));
    CU_ASSERT("" == out);
    CU_ASSERT("" == base64::decode(balloc, std::begin(in), std::end(in)));
  }
  {
    // additional '=' at the end is bad
    std::string in = "//79/A======";
    auto out = base64::decode(std::begin(in), std::end(in));
    CU_ASSERT("" == out);
    CU_ASSERT("" == base64::decode(balloc, std::begin(in), std::end(in)));
  }
}

} // namespace nghttp2
