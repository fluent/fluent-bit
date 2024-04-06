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
#include "http3.h"

namespace nghttp2 {

namespace http3 {

namespace {
nghttp3_nv make_nv_internal(const std::string &name, const std::string &value,
                            bool never_index, uint8_t nv_flags) {
  uint8_t flags;

  flags = nv_flags |
          (never_index ? NGHTTP3_NV_FLAG_NEVER_INDEX : NGHTTP3_NV_FLAG_NONE);

  return {(uint8_t *)name.c_str(), (uint8_t *)value.c_str(), name.size(),
          value.size(), flags};
}
} // namespace

namespace {
nghttp3_nv make_nv_internal(const StringRef &name, const StringRef &value,
                            bool never_index, uint8_t nv_flags) {
  uint8_t flags;

  flags = nv_flags |
          (never_index ? NGHTTP3_NV_FLAG_NEVER_INDEX : NGHTTP3_NV_FLAG_NONE);

  return {(uint8_t *)name.c_str(), (uint8_t *)value.c_str(), name.size(),
          value.size(), flags};
}
} // namespace

nghttp3_nv make_nv(const std::string &name, const std::string &value,
                   bool never_index) {
  return make_nv_internal(name, value, never_index, NGHTTP3_NV_FLAG_NONE);
}

nghttp3_nv make_nv(const StringRef &name, const StringRef &value,
                   bool never_index) {
  return make_nv_internal(name, value, never_index, NGHTTP3_NV_FLAG_NONE);
}

nghttp3_nv make_nv_nocopy(const std::string &name, const std::string &value,
                          bool never_index) {
  return make_nv_internal(name, value, never_index,
                          NGHTTP3_NV_FLAG_NO_COPY_NAME |
                              NGHTTP3_NV_FLAG_NO_COPY_VALUE);
}

nghttp3_nv make_nv_nocopy(const StringRef &name, const StringRef &value,
                          bool never_index) {
  return make_nv_internal(name, value, never_index,
                          NGHTTP3_NV_FLAG_NO_COPY_NAME |
                              NGHTTP3_NV_FLAG_NO_COPY_VALUE);
}

namespace {
void copy_headers_to_nva_internal(std::vector<nghttp3_nv> &nva,
                                  const HeaderRefs &headers, uint8_t nv_flags,
                                  uint32_t flags) {
  auto it_forwarded = std::end(headers);
  auto it_xff = std::end(headers);
  auto it_xfp = std::end(headers);
  auto it_via = std::end(headers);

  for (auto it = std::begin(headers); it != std::end(headers); ++it) {
    auto kv = &(*it);
    if (kv->name.empty() || kv->name[0] == ':') {
      continue;
    }
    switch (kv->token) {
    case http2::HD_COOKIE:
    case http2::HD_CONNECTION:
    case http2::HD_HOST:
    case http2::HD_HTTP2_SETTINGS:
    case http2::HD_KEEP_ALIVE:
    case http2::HD_PROXY_CONNECTION:
    case http2::HD_SERVER:
    case http2::HD_TE:
    case http2::HD_TRANSFER_ENCODING:
    case http2::HD_UPGRADE:
      continue;
    case http2::HD_EARLY_DATA:
      if (flags & http2::HDOP_STRIP_EARLY_DATA) {
        continue;
      }
      break;
    case http2::HD_SEC_WEBSOCKET_ACCEPT:
      if (flags & http2::HDOP_STRIP_SEC_WEBSOCKET_ACCEPT) {
        continue;
      }
      break;
    case http2::HD_SEC_WEBSOCKET_KEY:
      if (flags & http2::HDOP_STRIP_SEC_WEBSOCKET_KEY) {
        continue;
      }
      break;
    case http2::HD_FORWARDED:
      if (flags & http2::HDOP_STRIP_FORWARDED) {
        continue;
      }

      if (it_forwarded == std::end(headers)) {
        it_forwarded = it;
        continue;
      }

      kv = &(*it_forwarded);
      it_forwarded = it;
      break;
    case http2::HD_X_FORWARDED_FOR:
      if (flags & http2::HDOP_STRIP_X_FORWARDED_FOR) {
        continue;
      }

      if (it_xff == std::end(headers)) {
        it_xff = it;
        continue;
      }

      kv = &(*it_xff);
      it_xff = it;
      break;
    case http2::HD_X_FORWARDED_PROTO:
      if (flags & http2::HDOP_STRIP_X_FORWARDED_PROTO) {
        continue;
      }

      if (it_xfp == std::end(headers)) {
        it_xfp = it;
        continue;
      }

      kv = &(*it_xfp);
      it_xfp = it;
      break;
    case http2::HD_VIA:
      if (flags & http2::HDOP_STRIP_VIA) {
        continue;
      }

      if (it_via == std::end(headers)) {
        it_via = it;
        continue;
      }

      kv = &(*it_via);
      it_via = it;
      break;
    }
    nva.push_back(
        make_nv_internal(kv->name, kv->value, kv->no_index, nv_flags));
  }
}
} // namespace

void copy_headers_to_nva(std::vector<nghttp3_nv> &nva,
                         const HeaderRefs &headers, uint32_t flags) {
  copy_headers_to_nva_internal(nva, headers, NGHTTP3_NV_FLAG_NONE, flags);
}

void copy_headers_to_nva_nocopy(std::vector<nghttp3_nv> &nva,
                                const HeaderRefs &headers, uint32_t flags) {
  copy_headers_to_nva_internal(
      nva, headers,
      NGHTTP3_NV_FLAG_NO_COPY_NAME | NGHTTP3_NV_FLAG_NO_COPY_VALUE, flags);
}

int check_nv(const uint8_t *name, size_t namelen, const uint8_t *value,
             size_t valuelen) {
  if (!nghttp3_check_header_name(name, namelen)) {
    return 0;
  }
  if (!nghttp3_check_header_value(value, valuelen)) {
    return 0;
  }
  return 1;
}

} // namespace http3

} // namespace nghttp2
