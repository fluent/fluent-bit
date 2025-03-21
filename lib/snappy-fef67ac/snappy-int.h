// Copyright 2011 Google Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Various stubs for the open-source version of Snappy.

#define likely(x) __builtin_expect(x, 1)
#define unlikely(x) __builtin_expect(x, 0)

#define CRASH_UNLESS(x) assert(x)
#define CHECK(cond) assert(cond)
#define CHECK_LE(a, b) CRASH_UNLESS((a) <= (b))
#define CHECK_GE(a, b) CRASH_UNLESS((a) >= (b))
#define CHECK_EQ(a, b) CRASH_UNLESS((a) == (b))
#define CHECK_NE(a, b) CRASH_UNLESS((a) != (b))
#define CHECK_LT(a, b) CRASH_UNLESS((a) < (b))
#define CHECK_GT(a, b) CRASH_UNLESS((a) > (b))

#define UNALIGNED_LOAD16(_p) (*(const uint16 *)(_p))
#define UNALIGNED_LOAD32(_p) (*(const uint32 *)(_p))
#define UNALIGNED_LOAD64(_p) (*(const uint64 *)(_p))

#define UNALIGNED_STORE16(_p, _val) (*(uint16 *)(_p) = (_val))
#define UNALIGNED_STORE32(_p, _val) (*(uint32 *)(_p) = (_val))
#define UNALIGNED_STORE64(_p, _val) (*(uint64 *)(_p) = (_val))

#ifdef NDEBUG

#define DCHECK(cond) CRASH_UNLESS(true)
#define DCHECK_LE(a, b) CRASH_UNLESS(true)
#define DCHECK_GE(a, b) CRASH_UNLESS(true)
#define DCHECK_EQ(a, b) CRASH_UNLESS(true)
#define DCHECK_NE(a, b) CRASH_UNLESS(true)
#define DCHECK_LT(a, b) CRASH_UNLESS(true)
#define DCHECK_GT(a, b) CRASH_UNLESS(true)

#else

#define DCHECK(cond) CHECK(cond)
#define DCHECK_LE(a, b) CHECK_LE(a, b)
#define DCHECK_GE(a, b) CHECK_GE(a, b)
#define DCHECK_EQ(a, b) CHECK_EQ(a, b)
#define DCHECK_NE(a, b) CHECK_NE(a, b)
#define DCHECK_LT(a, b) CHECK_LT(a, b)
#define DCHECK_GT(a, b) CHECK_GT(a, b)

#endif
