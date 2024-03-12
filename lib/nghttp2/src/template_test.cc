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
#include "template_test.h"

#include <cstring>
#include <iostream>
#include <sstream>

#include <CUnit/CUnit.h>

#include "template.h"

namespace nghttp2 {

void test_template_immutable_string(void) {
  ImmutableString null;

  CU_ASSERT("" == null);
  CU_ASSERT(0 == null.size());
  CU_ASSERT(null.empty());

  ImmutableString from_cstr("alpha");

  CU_ASSERT(0 == strcmp("alpha", from_cstr.c_str()));
  CU_ASSERT(5 == from_cstr.size());
  CU_ASSERT(!from_cstr.empty());
  CU_ASSERT("alpha" == from_cstr);
  CU_ASSERT(from_cstr == "alpha");
  CU_ASSERT(std::string("alpha") == from_cstr);
  CU_ASSERT(from_cstr == std::string("alpha"));

  // copy constructor
  ImmutableString src("charlie");
  ImmutableString copy = src;

  CU_ASSERT("charlie" == copy);
  CU_ASSERT(7 == copy.size());

  // copy assignment
  ImmutableString copy2;
  copy2 = src;

  CU_ASSERT("charlie" == copy2);
  CU_ASSERT(7 == copy2.size());

  // move constructor
  ImmutableString move = std::move(copy);

  CU_ASSERT("charlie" == move);
  CU_ASSERT(7 == move.size());
  CU_ASSERT("" == copy);
  CU_ASSERT(0 == copy.size());

  // move assignment
  move = std::move(from_cstr);

  CU_ASSERT("alpha" == move);
  CU_ASSERT(5 == move.size());
  CU_ASSERT("" == from_cstr);
  CU_ASSERT(0 == from_cstr.size());

  // from string literal
  auto from_lit = StringRef::from_lit("bravo");

  CU_ASSERT("bravo" == from_lit);
  CU_ASSERT(5 == from_lit.size());

  // equality
  ImmutableString eq("delta");

  CU_ASSERT("delta1" != eq);
  CU_ASSERT("delt" != eq);
  CU_ASSERT(eq != "delta1");
  CU_ASSERT(eq != "delt");

  // operator[]
  ImmutableString br_op("foxtrot");

  CU_ASSERT('f' == br_op[0]);
  CU_ASSERT('o' == br_op[1]);
  CU_ASSERT('t' == br_op[6]);
  CU_ASSERT('\0' == br_op[7]);

  // operator==(const ImmutableString &, const ImmutableString &)
  {
    ImmutableString a("foo");
    ImmutableString b("foo");
    ImmutableString c("fo");

    CU_ASSERT(a == b);
    CU_ASSERT(a != c);
    CU_ASSERT(c != b);
  }

  // operator<<
  {
    ImmutableString a("foo");
    std::stringstream ss;
    ss << a;

    CU_ASSERT("foo" == ss.str());
  }

  // operator +=(std::string &, const ImmutableString &)
  {
    std::string a = "alpha";
    a += ImmutableString("bravo");

    CU_ASSERT("alphabravo" == a);
  }
}

void test_template_string_ref(void) {
  StringRef empty;

  CU_ASSERT("" == empty);
  CU_ASSERT(0 == empty.size());

  // from std::string
  std::string alpha = "alpha";

  StringRef ref(alpha);

  CU_ASSERT("alpha" == ref);
  CU_ASSERT(ref == "alpha");
  CU_ASSERT(alpha == ref);
  CU_ASSERT(ref == alpha);
  CU_ASSERT(5 == ref.size());

  // from string literal
  auto from_lit = StringRef::from_lit("alpha");

  CU_ASSERT("alpha" == from_lit);
  CU_ASSERT(5 == from_lit.size());

  // from ImmutableString
  auto im = ImmutableString::from_lit("bravo");

  StringRef imref(im);

  CU_ASSERT("bravo" == imref);
  CU_ASSERT(5 == imref.size());

  // from C-string
  StringRef cstrref("charlie");

  CU_ASSERT("charlie" == cstrref);
  CU_ASSERT(7 == cstrref.size());

  // from C-string and its length
  StringRef cstrnref("delta", 5);

  CU_ASSERT("delta" == cstrnref);
  CU_ASSERT(5 == cstrnref.size());

  // operator[]
  StringRef br_op("foxtrot");

  CU_ASSERT('f' == br_op[0]);
  CU_ASSERT('o' == br_op[1]);
  CU_ASSERT('t' == br_op[6]);
  CU_ASSERT('\0' == br_op[7]);

  // operator<<
  {
    StringRef a("foo");
    std::stringstream ss;
    ss << a;

    CU_ASSERT("foo" == ss.str());
  }

  // operator +=(std::string &, const StringRef &)
  {
    std::string a = "alpha";
    a += StringRef("bravo");

    CU_ASSERT("alphabravo" == a);
  }
}

} // namespace nghttp2
