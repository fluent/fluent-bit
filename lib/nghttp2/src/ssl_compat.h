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
#ifndef OPENSSL_COMPAT_H

#  include <openssl/opensslv.h>

#  ifdef LIBRESSL_VERSION_NUMBER
#    define OPENSSL_1_1_API 0
#    define OPENSSL_1_1_1_API 0
#    define OPENSSL_3_0_0_API 0
#    define LIBRESSL_IN_USE 1
#    define LIBRESSL_LEGACY_API (LIBRESSL_VERSION_NUMBER < 0x20700000L)
#    define LIBRESSL_2_7_API (LIBRESSL_VERSION_NUMBER >= 0x20700000L)
#    define LIBRESSL_3_5_API (LIBRESSL_VERSION_NUMBER >= 0x30500000L)
#  else // !LIBRESSL_VERSION_NUMBER
#    define OPENSSL_1_1_API (OPENSSL_VERSION_NUMBER >= 0x1010000fL)
#    define OPENSSL_1_1_1_API (OPENSSL_VERSION_NUMBER >= 0x10101000L)
#    define OPENSSL_3_0_0_API (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#    define LIBRESSL_IN_USE 0
#    define LIBRESSL_LEGACY_API 0
#    define LIBRESSL_2_7_API 0
#    define LIBRESSL_3_5_API 0
#  endif // !LIBRESSL_VERSION_NUMBER

#  if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
#    define NGHTTP2_OPENSSL_IS_BORINGSSL
#  endif // OPENSSL_IS_BORINGSSL || OPENSSL_IS_AWSLC

#endif // OPENSSL_COMPAT_H
