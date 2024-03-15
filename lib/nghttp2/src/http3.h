/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2021 Tatsuhiro Tsujikawa
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
#ifndef HTTP3_H
#define HTTP3_H

#include "nghttp2_config.h"

#include <cstring>
#include <string>
#include <vector>

#include <nghttp3/nghttp3.h>

#include "http2.h"
#include "template.h"

namespace nghttp2 {

namespace http3 {

// Creates nghttp3_nv using |name| and |value| and returns it. The
// returned value only references the data pointer to name.c_str() and
// value.c_str().  If |no_index| is true, nghttp3_nv flags member has
// NGHTTP3_NV_FLAG_NEVER_INDEX flag set.
nghttp3_nv make_nv(const std::string &name, const std::string &value,
                   bool never_index = false);

nghttp3_nv make_nv(const StringRef &name, const StringRef &value,
                   bool never_index = false);

nghttp3_nv make_nv_nocopy(const std::string &name, const std::string &value,
                          bool never_index = false);

nghttp3_nv make_nv_nocopy(const StringRef &name, const StringRef &value,
                          bool never_index = false);

// Create nghttp3_nv from string literal |name| and |value|.
template <size_t N, size_t M>
constexpr nghttp3_nv make_nv_ll(const char (&name)[N], const char (&value)[M]) {
  return {(uint8_t *)name, (uint8_t *)value, N - 1, M - 1,
          NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE};
}

// Create nghttp3_nv from string literal |name| and c-string |value|.
template <size_t N>
nghttp3_nv make_nv_lc(const char (&name)[N], const char *value) {
  return {(uint8_t *)name, (uint8_t *)value, N - 1, strlen(value),
          NGHTTP3_NV_FLAG_NO_COPY_NAME};
}

template <size_t N>
nghttp3_nv make_nv_lc_nocopy(const char (&name)[N], const char *value) {
  return {(uint8_t *)name, (uint8_t *)value, N - 1, strlen(value),
          NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE};
}

// Create nghttp3_nv from string literal |name| and std::string
// |value|.
template <size_t N>
nghttp3_nv make_nv_ls(const char (&name)[N], const std::string &value) {
  return {(uint8_t *)name, (uint8_t *)value.c_str(), N - 1, value.size(),
          NGHTTP3_NV_FLAG_NO_COPY_NAME};
}

template <size_t N>
nghttp3_nv make_nv_ls_nocopy(const char (&name)[N], const std::string &value) {
  return {(uint8_t *)name, (uint8_t *)value.c_str(), N - 1, value.size(),
          NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE};
}

template <size_t N>
nghttp3_nv make_nv_ls_nocopy(const char (&name)[N], const StringRef &value) {
  return {(uint8_t *)name, (uint8_t *)value.c_str(), N - 1, value.size(),
          NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE};
}

// Appends headers in |headers| to |nv|.  |headers| must be indexed
// before this call (its element's token field is assigned).  Certain
// headers, including disallowed headers in HTTP/3 spec and headers
// which require special handling (i.e. via), are not copied.  |flags|
// is one or more of HeaderBuildOp flags.  They tell function that
// certain header fields should not be added.
void copy_headers_to_nva(std::vector<nghttp3_nv> &nva,
                         const HeaderRefs &headers, uint32_t flags);

// Just like copy_headers_to_nva(), but this adds
// NGHTTP3_NV_FLAG_NO_COPY_NAME and NGHTTP3_NV_FLAG_NO_COPY_VALUE.
void copy_headers_to_nva_nocopy(std::vector<nghttp3_nv> &nva,
                                const HeaderRefs &headers, uint32_t flags);

// Checks the header name/value pair using nghttp3_check_header_name()
// and nghttp3_check_header_value(). If both function returns nonzero,
// this function returns nonzero.
int check_nv(const uint8_t *name, size_t namelen, const uint8_t *value,
             size_t valuelen);

} // namespace http3

} // namespace nghttp2

#endif // HTTP3_H
