/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
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
#include "http2.h"

#include "llhttp.h"

#include "util.h"

namespace nghttp2 {

namespace http2 {

StringRef get_reason_phrase(unsigned int status_code) {
  switch (status_code) {
  case 100:
    return StringRef::from_lit("Continue");
  case 101:
    return StringRef::from_lit("Switching Protocols");
  case 103:
    return StringRef::from_lit("Early Hints");
  case 200:
    return StringRef::from_lit("OK");
  case 201:
    return StringRef::from_lit("Created");
  case 202:
    return StringRef::from_lit("Accepted");
  case 203:
    return StringRef::from_lit("Non-Authoritative Information");
  case 204:
    return StringRef::from_lit("No Content");
  case 205:
    return StringRef::from_lit("Reset Content");
  case 206:
    return StringRef::from_lit("Partial Content");
  case 300:
    return StringRef::from_lit("Multiple Choices");
  case 301:
    return StringRef::from_lit("Moved Permanently");
  case 302:
    return StringRef::from_lit("Found");
  case 303:
    return StringRef::from_lit("See Other");
  case 304:
    return StringRef::from_lit("Not Modified");
  case 305:
    return StringRef::from_lit("Use Proxy");
  // case 306: return StringRef::from_lit("(Unused)");
  case 307:
    return StringRef::from_lit("Temporary Redirect");
  case 308:
    return StringRef::from_lit("Permanent Redirect");
  case 400:
    return StringRef::from_lit("Bad Request");
  case 401:
    return StringRef::from_lit("Unauthorized");
  case 402:
    return StringRef::from_lit("Payment Required");
  case 403:
    return StringRef::from_lit("Forbidden");
  case 404:
    return StringRef::from_lit("Not Found");
  case 405:
    return StringRef::from_lit("Method Not Allowed");
  case 406:
    return StringRef::from_lit("Not Acceptable");
  case 407:
    return StringRef::from_lit("Proxy Authentication Required");
  case 408:
    return StringRef::from_lit("Request Timeout");
  case 409:
    return StringRef::from_lit("Conflict");
  case 410:
    return StringRef::from_lit("Gone");
  case 411:
    return StringRef::from_lit("Length Required");
  case 412:
    return StringRef::from_lit("Precondition Failed");
  case 413:
    return StringRef::from_lit("Payload Too Large");
  case 414:
    return StringRef::from_lit("URI Too Long");
  case 415:
    return StringRef::from_lit("Unsupported Media Type");
  case 416:
    return StringRef::from_lit("Requested Range Not Satisfiable");
  case 417:
    return StringRef::from_lit("Expectation Failed");
  case 421:
    return StringRef::from_lit("Misdirected Request");
  case 425:
    // https://tools.ietf.org/html/rfc8470
    return StringRef::from_lit("Too Early");
  case 426:
    return StringRef::from_lit("Upgrade Required");
  case 428:
    return StringRef::from_lit("Precondition Required");
  case 429:
    return StringRef::from_lit("Too Many Requests");
  case 431:
    return StringRef::from_lit("Request Header Fields Too Large");
  case 451:
    return StringRef::from_lit("Unavailable For Legal Reasons");
  case 500:
    return StringRef::from_lit("Internal Server Error");
  case 501:
    return StringRef::from_lit("Not Implemented");
  case 502:
    return StringRef::from_lit("Bad Gateway");
  case 503:
    return StringRef::from_lit("Service Unavailable");
  case 504:
    return StringRef::from_lit("Gateway Timeout");
  case 505:
    return StringRef::from_lit("HTTP Version Not Supported");
  case 511:
    return StringRef::from_lit("Network Authentication Required");
  default:
    return StringRef{};
  }
}

StringRef stringify_status(BlockAllocator &balloc, unsigned int status_code) {
  switch (status_code) {
  case 100:
    return StringRef::from_lit("100");
  case 101:
    return StringRef::from_lit("101");
  case 103:
    return StringRef::from_lit("103");
  case 200:
    return StringRef::from_lit("200");
  case 201:
    return StringRef::from_lit("201");
  case 202:
    return StringRef::from_lit("202");
  case 203:
    return StringRef::from_lit("203");
  case 204:
    return StringRef::from_lit("204");
  case 205:
    return StringRef::from_lit("205");
  case 206:
    return StringRef::from_lit("206");
  case 300:
    return StringRef::from_lit("300");
  case 301:
    return StringRef::from_lit("301");
  case 302:
    return StringRef::from_lit("302");
  case 303:
    return StringRef::from_lit("303");
  case 304:
    return StringRef::from_lit("304");
  case 305:
    return StringRef::from_lit("305");
  // case 306: return StringRef::from_lit("306");
  case 307:
    return StringRef::from_lit("307");
  case 308:
    return StringRef::from_lit("308");
  case 400:
    return StringRef::from_lit("400");
  case 401:
    return StringRef::from_lit("401");
  case 402:
    return StringRef::from_lit("402");
  case 403:
    return StringRef::from_lit("403");
  case 404:
    return StringRef::from_lit("404");
  case 405:
    return StringRef::from_lit("405");
  case 406:
    return StringRef::from_lit("406");
  case 407:
    return StringRef::from_lit("407");
  case 408:
    return StringRef::from_lit("408");
  case 409:
    return StringRef::from_lit("409");
  case 410:
    return StringRef::from_lit("410");
  case 411:
    return StringRef::from_lit("411");
  case 412:
    return StringRef::from_lit("412");
  case 413:
    return StringRef::from_lit("413");
  case 414:
    return StringRef::from_lit("414");
  case 415:
    return StringRef::from_lit("415");
  case 416:
    return StringRef::from_lit("416");
  case 417:
    return StringRef::from_lit("417");
  case 421:
    return StringRef::from_lit("421");
  case 426:
    return StringRef::from_lit("426");
  case 428:
    return StringRef::from_lit("428");
  case 429:
    return StringRef::from_lit("429");
  case 431:
    return StringRef::from_lit("431");
  case 451:
    return StringRef::from_lit("451");
  case 500:
    return StringRef::from_lit("500");
  case 501:
    return StringRef::from_lit("501");
  case 502:
    return StringRef::from_lit("502");
  case 503:
    return StringRef::from_lit("503");
  case 504:
    return StringRef::from_lit("504");
  case 505:
    return StringRef::from_lit("505");
  case 511:
    return StringRef::from_lit("511");
  default:
    return util::make_string_ref_uint(balloc, status_code);
  }
}

void capitalize(DefaultMemchunks *buf, const StringRef &s) {
  buf->append(util::upcase(s[0]));
  for (size_t i = 1; i < s.size(); ++i) {
    if (s[i - 1] == '-') {
      buf->append(util::upcase(s[i]));
    } else {
      buf->append(s[i]);
    }
  }
}

bool lws(const char *value) {
  for (; *value; ++value) {
    switch (*value) {
    case '\t':
    case ' ':
      continue;
    default:
      return false;
    }
  }
  return true;
}

void copy_url_component(std::string &dest, const http_parser_url *u, int field,
                        const char *url) {
  if (u->field_set & (1 << field)) {
    dest.assign(url + u->field_data[field].off, u->field_data[field].len);
  }
}

Headers::value_type to_header(const uint8_t *name, size_t namelen,
                              const uint8_t *value, size_t valuelen,
                              bool no_index, int32_t token) {
  return Header(std::string(reinterpret_cast<const char *>(name), namelen),
                std::string(reinterpret_cast<const char *>(value), valuelen),
                no_index, token);
}

void add_header(Headers &nva, const uint8_t *name, size_t namelen,
                const uint8_t *value, size_t valuelen, bool no_index,
                int32_t token) {
  if (valuelen > 0) {
    size_t i, j;
    for (i = 0; i < valuelen && (value[i] == ' ' || value[i] == '\t'); ++i)
      ;
    for (j = valuelen - 1; j > i && (value[j] == ' ' || value[j] == '\t'); --j)
      ;
    value += i;
    valuelen -= i + (valuelen - j - 1);
  }
  nva.push_back(to_header(name, namelen, value, valuelen, no_index, token));
}

const Headers::value_type *get_header(const Headers &nva, const char *name) {
  const Headers::value_type *res = nullptr;
  for (auto &nv : nva) {
    if (nv.name == name) {
      res = &nv;
    }
  }
  return res;
}

bool non_empty_value(const HeaderRefs::value_type *nv) {
  return nv && !nv->value.empty();
}

namespace {
nghttp2_nv make_nv_internal(const std::string &name, const std::string &value,
                            bool no_index, uint8_t nv_flags) {
  uint8_t flags;

  flags =
      nv_flags | (no_index ? NGHTTP2_NV_FLAG_NO_INDEX : NGHTTP2_NV_FLAG_NONE);

  return {(uint8_t *)name.c_str(), (uint8_t *)value.c_str(), name.size(),
          value.size(), flags};
}
} // namespace

namespace {
nghttp2_nv make_nv_internal(const StringRef &name, const StringRef &value,
                            bool no_index, uint8_t nv_flags) {
  uint8_t flags;

  flags =
      nv_flags | (no_index ? NGHTTP2_NV_FLAG_NO_INDEX : NGHTTP2_NV_FLAG_NONE);

  return {(uint8_t *)name.c_str(), (uint8_t *)value.c_str(), name.size(),
          value.size(), flags};
}
} // namespace

nghttp2_nv make_nv(const std::string &name, const std::string &value,
                   bool no_index) {
  return make_nv_internal(name, value, no_index, NGHTTP2_NV_FLAG_NONE);
}

nghttp2_nv make_nv(const StringRef &name, const StringRef &value,
                   bool no_index) {
  return make_nv_internal(name, value, no_index, NGHTTP2_NV_FLAG_NONE);
}

nghttp2_nv make_nv_nocopy(const std::string &name, const std::string &value,
                          bool no_index) {
  return make_nv_internal(name, value, no_index,
                          NGHTTP2_NV_FLAG_NO_COPY_NAME |
                              NGHTTP2_NV_FLAG_NO_COPY_VALUE);
}

nghttp2_nv make_nv_nocopy(const StringRef &name, const StringRef &value,
                          bool no_index) {
  return make_nv_internal(name, value, no_index,
                          NGHTTP2_NV_FLAG_NO_COPY_NAME |
                              NGHTTP2_NV_FLAG_NO_COPY_VALUE);
}

namespace {
void copy_headers_to_nva_internal(std::vector<nghttp2_nv> &nva,
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
    case HD_COOKIE:
    case HD_CONNECTION:
    case HD_HOST:
    case HD_HTTP2_SETTINGS:
    case HD_KEEP_ALIVE:
    case HD_PROXY_CONNECTION:
    case HD_SERVER:
    case HD_TE:
    case HD_TRANSFER_ENCODING:
    case HD_UPGRADE:
      continue;
    case HD_EARLY_DATA:
      if (flags & HDOP_STRIP_EARLY_DATA) {
        continue;
      }
      break;
    case HD_SEC_WEBSOCKET_ACCEPT:
      if (flags & HDOP_STRIP_SEC_WEBSOCKET_ACCEPT) {
        continue;
      }
      break;
    case HD_SEC_WEBSOCKET_KEY:
      if (flags & HDOP_STRIP_SEC_WEBSOCKET_KEY) {
        continue;
      }
      break;
    case HD_FORWARDED:
      if (flags & HDOP_STRIP_FORWARDED) {
        continue;
      }

      if (it_forwarded == std::end(headers)) {
        it_forwarded = it;
        continue;
      }

      kv = &(*it_forwarded);
      it_forwarded = it;
      break;
    case HD_X_FORWARDED_FOR:
      if (flags & HDOP_STRIP_X_FORWARDED_FOR) {
        continue;
      }

      if (it_xff == std::end(headers)) {
        it_xff = it;
        continue;
      }

      kv = &(*it_xff);
      it_xff = it;
      break;
    case HD_X_FORWARDED_PROTO:
      if (flags & HDOP_STRIP_X_FORWARDED_PROTO) {
        continue;
      }

      if (it_xfp == std::end(headers)) {
        it_xfp = it;
        continue;
      }

      kv = &(*it_xfp);
      it_xfp = it;
      break;
    case HD_VIA:
      if (flags & HDOP_STRIP_VIA) {
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

void copy_headers_to_nva(std::vector<nghttp2_nv> &nva,
                         const HeaderRefs &headers, uint32_t flags) {
  copy_headers_to_nva_internal(nva, headers, NGHTTP2_NV_FLAG_NONE, flags);
}

void copy_headers_to_nva_nocopy(std::vector<nghttp2_nv> &nva,
                                const HeaderRefs &headers, uint32_t flags) {
  copy_headers_to_nva_internal(
      nva, headers,
      NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE, flags);
}

void build_http1_headers_from_headers(DefaultMemchunks *buf,
                                      const HeaderRefs &headers,
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
    case HD_CONNECTION:
    case HD_COOKIE:
    case HD_HOST:
    case HD_HTTP2_SETTINGS:
    case HD_KEEP_ALIVE:
    case HD_PROXY_CONNECTION:
    case HD_SERVER:
    case HD_UPGRADE:
      continue;
    case HD_EARLY_DATA:
      if (flags & HDOP_STRIP_EARLY_DATA) {
        continue;
      }
      break;
    case HD_TRANSFER_ENCODING:
      if (flags & HDOP_STRIP_TRANSFER_ENCODING) {
        continue;
      }
      break;
    case HD_FORWARDED:
      if (flags & HDOP_STRIP_FORWARDED) {
        continue;
      }

      if (it_forwarded == std::end(headers)) {
        it_forwarded = it;
        continue;
      }

      kv = &(*it_forwarded);
      it_forwarded = it;
      break;
    case HD_X_FORWARDED_FOR:
      if (flags & HDOP_STRIP_X_FORWARDED_FOR) {
        continue;
      }

      if (it_xff == std::end(headers)) {
        it_xff = it;
        continue;
      }

      kv = &(*it_xff);
      it_xff = it;
      break;
    case HD_X_FORWARDED_PROTO:
      if (flags & HDOP_STRIP_X_FORWARDED_PROTO) {
        continue;
      }

      if (it_xfp == std::end(headers)) {
        it_xfp = it;
        continue;
      }

      kv = &(*it_xfp);
      it_xfp = it;
      break;
    case HD_VIA:
      if (flags & HDOP_STRIP_VIA) {
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
    capitalize(buf, kv->name);
    buf->append(": ");
    buf->append(kv->value);
    buf->append("\r\n");
  }
}

int32_t determine_window_update_transmission(nghttp2_session *session,
                                             int32_t stream_id) {
  int32_t recv_length, window_size;
  if (stream_id == 0) {
    recv_length = nghttp2_session_get_effective_recv_data_length(session);
    window_size = nghttp2_session_get_effective_local_window_size(session);
  } else {
    recv_length = nghttp2_session_get_stream_effective_recv_data_length(
        session, stream_id);
    window_size = nghttp2_session_get_stream_effective_local_window_size(
        session, stream_id);
  }
  if (recv_length != -1 && window_size != -1) {
    if (recv_length >= window_size / 2) {
      return recv_length;
    }
  }
  return -1;
}

void dump_nv(FILE *out, const char **nv) {
  for (size_t i = 0; nv[i]; i += 2) {
    fprintf(out, "%s: %s\n", nv[i], nv[i + 1]);
  }
  fputc('\n', out);
  fflush(out);
}

void dump_nv(FILE *out, const nghttp2_nv *nva, size_t nvlen) {
  auto end = nva + nvlen;
  for (; nva != end; ++nva) {
    fprintf(out, "%s: %s\n", nva->name, nva->value);
  }
  fputc('\n', out);
  fflush(out);
}

void dump_nv(FILE *out, const Headers &nva) {
  for (auto &nv : nva) {
    fprintf(out, "%s: %s\n", nv.name.c_str(), nv.value.c_str());
  }
  fputc('\n', out);
  fflush(out);
}

void dump_nv(FILE *out, const HeaderRefs &nva) {
  for (auto &nv : nva) {
    fprintf(out, "%s: %s\n", nv.name.c_str(), nv.value.c_str());
  }
  fputc('\n', out);
  fflush(out);
}

void erase_header(HeaderRef *hd) {
  hd->name = StringRef{};
  hd->token = -1;
}

StringRef rewrite_location_uri(BlockAllocator &balloc, const StringRef &uri,
                               const http_parser_url &u,
                               const StringRef &match_host,
                               const StringRef &request_authority,
                               const StringRef &upstream_scheme) {
  // We just rewrite scheme and authority.
  if ((u.field_set & (1 << UF_HOST)) == 0) {
    return StringRef{};
  }
  auto field = &u.field_data[UF_HOST];
  if (!util::starts_with(std::begin(match_host), std::end(match_host),
                         &uri[field->off], &uri[field->off] + field->len) ||
      (match_host.size() != field->len && match_host[field->len] != ':')) {
    return StringRef{};
  }

  auto len = 0;
  if (!request_authority.empty()) {
    len += upstream_scheme.size() + str_size("://") + request_authority.size();
  }

  if (u.field_set & (1 << UF_PATH)) {
    field = &u.field_data[UF_PATH];
    len += field->len;
  }

  if (u.field_set & (1 << UF_QUERY)) {
    field = &u.field_data[UF_QUERY];
    len += 1 + field->len;
  }

  if (u.field_set & (1 << UF_FRAGMENT)) {
    field = &u.field_data[UF_FRAGMENT];
    len += 1 + field->len;
  }

  auto iov = make_byte_ref(balloc, len + 1);
  auto p = iov.base;

  if (!request_authority.empty()) {
    p = std::copy(std::begin(upstream_scheme), std::end(upstream_scheme), p);
    p = util::copy_lit(p, "://");
    p = std::copy(std::begin(request_authority), std::end(request_authority),
                  p);
  }
  if (u.field_set & (1 << UF_PATH)) {
    field = &u.field_data[UF_PATH];
    p = std::copy_n(&uri[field->off], field->len, p);
  }
  if (u.field_set & (1 << UF_QUERY)) {
    field = &u.field_data[UF_QUERY];
    *p++ = '?';
    p = std::copy_n(&uri[field->off], field->len, p);
  }
  if (u.field_set & (1 << UF_FRAGMENT)) {
    field = &u.field_data[UF_FRAGMENT];
    *p++ = '#';
    p = std::copy_n(&uri[field->off], field->len, p);
  }

  *p = '\0';

  return StringRef{iov.base, p};
}

int parse_http_status_code(const StringRef &src) {
  if (src.size() != 3) {
    return -1;
  }

  int status = 0;
  for (auto c : src) {
    if (!isdigit(c)) {
      return -1;
    }
    status *= 10;
    status += c - '0';
  }

  if (status < 100) {
    return -1;
  }

  return status;
}

int lookup_token(const StringRef &name) {
  return lookup_token(name.byte(), name.size());
}

// This function was generated by genheaderfunc.py.  Inspired by h2o
// header lookup.  https://github.com/h2o/h2o
int lookup_token(const uint8_t *name, size_t namelen) {
  switch (namelen) {
  case 2:
    switch (name[1]) {
    case 'e':
      if (util::streq_l("t", name, 1)) {
        return HD_TE;
      }
      break;
    }
    break;
  case 3:
    switch (name[2]) {
    case 'a':
      if (util::streq_l("vi", name, 2)) {
        return HD_VIA;
      }
      break;
    }
    break;
  case 4:
    switch (name[3]) {
    case 'e':
      if (util::streq_l("dat", name, 3)) {
        return HD_DATE;
      }
      break;
    case 'k':
      if (util::streq_l("lin", name, 3)) {
        return HD_LINK;
      }
      break;
    case 't':
      if (util::streq_l("hos", name, 3)) {
        return HD_HOST;
      }
      break;
    }
    break;
  case 5:
    switch (name[4]) {
    case 'h':
      if (util::streq_l(":pat", name, 4)) {
        return HD__PATH;
      }
      break;
    case 't':
      if (util::streq_l(":hos", name, 4)) {
        return HD__HOST;
      }
      break;
    }
    break;
  case 6:
    switch (name[5]) {
    case 'e':
      if (util::streq_l("cooki", name, 5)) {
        return HD_COOKIE;
      }
      break;
    case 'r':
      if (util::streq_l("serve", name, 5)) {
        return HD_SERVER;
      }
      break;
    case 't':
      if (util::streq_l("expec", name, 5)) {
        return HD_EXPECT;
      }
      break;
    }
    break;
  case 7:
    switch (name[6]) {
    case 'c':
      if (util::streq_l("alt-sv", name, 6)) {
        return HD_ALT_SVC;
      }
      break;
    case 'd':
      if (util::streq_l(":metho", name, 6)) {
        return HD__METHOD;
      }
      break;
    case 'e':
      if (util::streq_l(":schem", name, 6)) {
        return HD__SCHEME;
      }
      if (util::streq_l("upgrad", name, 6)) {
        return HD_UPGRADE;
      }
      break;
    case 'r':
      if (util::streq_l("traile", name, 6)) {
        return HD_TRAILER;
      }
      break;
    case 's':
      if (util::streq_l(":statu", name, 6)) {
        return HD__STATUS;
      }
      break;
    }
    break;
  case 8:
    switch (name[7]) {
    case 'n':
      if (util::streq_l("locatio", name, 7)) {
        return HD_LOCATION;
      }
      break;
    case 'y':
      if (util::streq_l("priorit", name, 7)) {
        return HD_PRIORITY;
      }
      break;
    }
    break;
  case 9:
    switch (name[8]) {
    case 'd':
      if (util::streq_l("forwarde", name, 8)) {
        return HD_FORWARDED;
      }
      break;
    case 'l':
      if (util::streq_l(":protoco", name, 8)) {
        return HD__PROTOCOL;
      }
      break;
    }
    break;
  case 10:
    switch (name[9]) {
    case 'a':
      if (util::streq_l("early-dat", name, 9)) {
        return HD_EARLY_DATA;
      }
      break;
    case 'e':
      if (util::streq_l("keep-aliv", name, 9)) {
        return HD_KEEP_ALIVE;
      }
      break;
    case 'n':
      if (util::streq_l("connectio", name, 9)) {
        return HD_CONNECTION;
      }
      break;
    case 't':
      if (util::streq_l("user-agen", name, 9)) {
        return HD_USER_AGENT;
      }
      break;
    case 'y':
      if (util::streq_l(":authorit", name, 9)) {
        return HD__AUTHORITY;
      }
      break;
    }
    break;
  case 12:
    switch (name[11]) {
    case 'e':
      if (util::streq_l("content-typ", name, 11)) {
        return HD_CONTENT_TYPE;
      }
      break;
    }
    break;
  case 13:
    switch (name[12]) {
    case 'l':
      if (util::streq_l("cache-contro", name, 12)) {
        return HD_CACHE_CONTROL;
      }
      break;
    }
    break;
  case 14:
    switch (name[13]) {
    case 'h':
      if (util::streq_l("content-lengt", name, 13)) {
        return HD_CONTENT_LENGTH;
      }
      break;
    case 's':
      if (util::streq_l("http2-setting", name, 13)) {
        return HD_HTTP2_SETTINGS;
      }
      break;
    }
    break;
  case 15:
    switch (name[14]) {
    case 'e':
      if (util::streq_l("accept-languag", name, 14)) {
        return HD_ACCEPT_LANGUAGE;
      }
      break;
    case 'g':
      if (util::streq_l("accept-encodin", name, 14)) {
        return HD_ACCEPT_ENCODING;
      }
      break;
    case 'r':
      if (util::streq_l("x-forwarded-fo", name, 14)) {
        return HD_X_FORWARDED_FOR;
      }
      break;
    }
    break;
  case 16:
    switch (name[15]) {
    case 'n':
      if (util::streq_l("proxy-connectio", name, 15)) {
        return HD_PROXY_CONNECTION;
      }
      break;
    }
    break;
  case 17:
    switch (name[16]) {
    case 'e':
      if (util::streq_l("if-modified-sinc", name, 16)) {
        return HD_IF_MODIFIED_SINCE;
      }
      break;
    case 'g':
      if (util::streq_l("transfer-encodin", name, 16)) {
        return HD_TRANSFER_ENCODING;
      }
      break;
    case 'o':
      if (util::streq_l("x-forwarded-prot", name, 16)) {
        return HD_X_FORWARDED_PROTO;
      }
      break;
    case 'y':
      if (util::streq_l("sec-websocket-ke", name, 16)) {
        return HD_SEC_WEBSOCKET_KEY;
      }
      break;
    }
    break;
  case 20:
    switch (name[19]) {
    case 't':
      if (util::streq_l("sec-websocket-accep", name, 19)) {
        return HD_SEC_WEBSOCKET_ACCEPT;
      }
      break;
    }
    break;
  }
  return -1;
}

void init_hdidx(HeaderIndex &hdidx) {
  std::fill(std::begin(hdidx), std::end(hdidx), -1);
}

void index_header(HeaderIndex &hdidx, int32_t token, size_t idx) {
  if (token == -1) {
    return;
  }
  assert(token < HD_MAXIDX);
  hdidx[token] = idx;
}

const Headers::value_type *get_header(const HeaderIndex &hdidx, int32_t token,
                                      const Headers &nva) {
  auto i = hdidx[token];
  if (i == -1) {
    return nullptr;
  }
  return &nva[i];
}

Headers::value_type *get_header(const HeaderIndex &hdidx, int32_t token,
                                Headers &nva) {
  auto i = hdidx[token];
  if (i == -1) {
    return nullptr;
  }
  return &nva[i];
}

namespace {
template <typename InputIt> InputIt skip_lws(InputIt first, InputIt last) {
  for (; first != last; ++first) {
    switch (*first) {
    case ' ':
    case '\t':
      continue;
    default:
      return first;
    }
  }
  return first;
}
} // namespace

namespace {
template <typename InputIt>
InputIt skip_to_next_field(InputIt first, InputIt last) {
  for (; first != last; ++first) {
    switch (*first) {
    case ' ':
    case '\t':
    case ',':
      continue;
    default:
      return first;
    }
  }
  return first;
}
} // namespace

namespace {
// Skip to the right dquote ('"'), handling backslash escapes.
// Returns |last| if input is not terminated with '"'.
template <typename InputIt>
InputIt skip_to_right_dquote(InputIt first, InputIt last) {
  for (; first != last;) {
    switch (*first) {
    case '"':
      return first;
      // quoted-pair
    case '\\':
      ++first;
      if (first == last) {
        return first;
      }

      switch (*first) {
      case '\t':
      case ' ':
        break;
      default:
        if ((0x21 <= *first && *first <= 0x7e) /* VCHAR */ ||
            (0x80 <= *first && *first <= 0xff) /* obs-text */) {
          break;
        }

        return last;
      }

      break;
      // qdtext
    case '\t':
    case ' ':
    case '!':
      break;
    default:
      if ((0x23 <= *first && *first <= 0x5b) ||
          (0x5d <= *first && *first <= 0x7e)) {
        break;
      }

      return last;
    }
    ++first;
  }
  return first;
}
} // namespace

namespace {
// Returns true if link-param does not match pattern |pat| of length
// |patlen| or it has empty value ("").  |pat| should be parmname
// followed by "=".
bool check_link_param_empty(const char *first, const char *last,
                            const char *pat, size_t patlen) {
  if (first + patlen <= last) {
    if (std::equal(pat, pat + patlen, first, util::CaseCmp())) {
      // we only accept URI if pat is followd by "" (e.g.,
      // loadpolicy="") here.
      if (first + patlen + 2 <= last) {
        if (*(first + patlen) != '"' || *(first + patlen + 1) != '"') {
          return false;
        }
      } else {
        // here we got invalid production (anchor=") or anchor=?
        return false;
      }
    }
  }
  return true;
}
} // namespace

namespace {
// Returns true if link-param consists of only parmname, and it
// matches string [pat, pat + patlen).
bool check_link_param_without_value(const char *first, const char *last,
                                    const char *pat, size_t patlen) {
  if (first + patlen > last) {
    return false;
  }

  if (first + patlen == last) {
    return std::equal(pat, pat + patlen, first, util::CaseCmp());
  }

  switch (*(first + patlen)) {
  case ';':
  case ',':
    return std::equal(pat, pat + patlen, first, util::CaseCmp());
  }

  return false;
}
} // namespace

namespace {
std::pair<LinkHeader, const char *>
parse_next_link_header_once(const char *first, const char *last) {
  first = skip_to_next_field(first, last);
  if (first == last || *first != '<') {
    return {{StringRef{}}, last};
  }
  auto url_first = ++first;
  first = std::find(first, last, '>');
  if (first == last) {
    return {{StringRef{}}, first};
  }
  auto url_last = first++;
  if (first == last) {
    return {{StringRef{}}, first};
  }
  // we expect ';' or ',' here
  switch (*first) {
  case ',':
    return {{StringRef{}}, ++first};
  case ';':
    ++first;
    break;
  default:
    return {{StringRef{}}, last};
  }

  auto ok = false;
  auto ign = false;
  for (;;) {
    first = skip_lws(first, last);
    if (first == last) {
      return {{StringRef{}}, first};
    }
    // we expect link-param

    if (!ign) {
      if (!ok) {
        // rel can take several relations using quoted form.
        static constexpr char PLP[] = "rel=\"";
        static constexpr size_t PLPLEN = str_size(PLP);

        static constexpr char PLT[] = "preload";
        static constexpr size_t PLTLEN = str_size(PLT);
        if (first + PLPLEN < last && *(first + PLPLEN - 1) == '"' &&
            std::equal(PLP, PLP + PLPLEN, first, util::CaseCmp())) {
          // we have to search preload in whitespace separated list:
          // rel="preload something http://example.org/foo"
          first += PLPLEN;
          auto start = first;
          for (; first != last;) {
            if (*first != ' ' && *first != '"') {
              ++first;
              continue;
            }

            if (start == first) {
              return {{StringRef{}}, last};
            }

            if (!ok && start + PLTLEN == first &&
                std::equal(PLT, PLT + PLTLEN, start, util::CaseCmp())) {
              ok = true;
            }

            if (*first == '"') {
              break;
            }
            first = skip_lws(first, last);
            start = first;
          }
          if (first == last) {
            return {{StringRef{}}, last};
          }
          assert(*first == '"');
          ++first;
          if (first == last || *first == ',') {
            goto almost_done;
          }
          if (*first == ';') {
            ++first;
            // parse next link-param
            continue;
          }
          return {{StringRef{}}, last};
        }
      }
      // we are only interested in rel=preload parameter.  Others are
      // simply skipped.
      static constexpr char PL[] = "rel=preload";
      static constexpr size_t PLLEN = str_size(PL);
      if (first + PLLEN == last) {
        if (std::equal(PL, PL + PLLEN, first, util::CaseCmp())) {
          // ok = true;
          // this is the end of sequence
          return {{{url_first, url_last}}, last};
        }
      } else if (first + PLLEN + 1 <= last) {
        switch (*(first + PLLEN)) {
        case ',':
          if (!std::equal(PL, PL + PLLEN, first, util::CaseCmp())) {
            break;
          }
          // ok = true;
          // skip including ','
          first += PLLEN + 1;
          return {{{url_first, url_last}}, first};
        case ';':
          if (!std::equal(PL, PL + PLLEN, first, util::CaseCmp())) {
            break;
          }
          ok = true;
          // skip including ';'
          first += PLLEN + 1;
          // continue parse next link-param
          continue;
        }
      }
      // we have to reject URI if we have nonempty anchor parameter.
      static constexpr char ANCHOR[] = "anchor=";
      static constexpr size_t ANCHORLEN = str_size(ANCHOR);
      if (!ign && !check_link_param_empty(first, last, ANCHOR, ANCHORLEN)) {
        ign = true;
      }

      // reject URI if we have non-empty loadpolicy.  This could be
      // tightened up to just pick up "next" or "insert".
      static constexpr char LOADPOLICY[] = "loadpolicy=";
      static constexpr size_t LOADPOLICYLEN = str_size(LOADPOLICY);
      if (!ign &&
          !check_link_param_empty(first, last, LOADPOLICY, LOADPOLICYLEN)) {
        ign = true;
      }

      // reject URI if we have nopush attribute.
      static constexpr char NOPUSH[] = "nopush";
      static constexpr size_t NOPUSHLEN = str_size(NOPUSH);
      if (!ign &&
          check_link_param_without_value(first, last, NOPUSH, NOPUSHLEN)) {
        ign = true;
      }
    }

    auto param_first = first;
    for (; first != last;) {
      if (util::in_attr_char(*first)) {
        ++first;
        continue;
      }
      // '*' is only allowed at the end of parameter name and must be
      // followed by '='
      if (last - first >= 2 && first != param_first) {
        if (*first == '*' && *(first + 1) == '=') {
          ++first;
          break;
        }
      }
      if (*first == '=' || *first == ';' || *first == ',') {
        break;
      }
      return {{StringRef{}}, last};
    }
    if (param_first == first) {
      // empty parmname
      return {{StringRef{}}, last};
    }
    // link-param without value is acceptable (see link-extension) if
    // it is not followed by '='
    if (first == last || *first == ',') {
      goto almost_done;
    }
    if (*first == ';') {
      ++first;
      // parse next link-param
      continue;
    }
    // now parsing link-param value
    assert(*first == '=');
    ++first;
    if (first == last) {
      // empty value is not acceptable
      return {{StringRef{}}, first};
    }
    if (*first == '"') {
      // quoted-string
      first = skip_to_right_dquote(first + 1, last);
      if (first == last) {
        return {{StringRef{}}, first};
      }
      ++first;
      if (first == last || *first == ',') {
        goto almost_done;
      }
      if (*first == ';') {
        ++first;
        // parse next link-param
        continue;
      }
      return {{StringRef{}}, last};
    }
    // not quoted-string, skip to next ',' or ';'
    if (*first == ',' || *first == ';') {
      // empty value
      return {{StringRef{}}, last};
    }
    for (; first != last; ++first) {
      if (*first == ',' || *first == ';') {
        break;
      }
    }
    if (first == last || *first == ',') {
      goto almost_done;
    }
    assert(*first == ';');
    ++first;
    // parse next link-param
  }

almost_done:
  assert(first == last || *first == ',');

  if (first != last) {
    ++first;
  }
  if (ok && !ign) {
    return {{{url_first, url_last}}, first};
  }
  return {{StringRef{}}, first};
}
} // namespace

std::vector<LinkHeader> parse_link_header(const StringRef &src) {
  std::vector<LinkHeader> res;
  for (auto first = std::begin(src); first != std::end(src);) {
    auto rv = parse_next_link_header_once(first, std::end(src));
    first = rv.second;
    auto &link = rv.first;
    if (!link.uri.empty()) {
      res.push_back(link);
    }
  }
  return res;
}

std::string path_join(const StringRef &base_path, const StringRef &base_query,
                      const StringRef &rel_path, const StringRef &rel_query) {
  BlockAllocator balloc(1024, 1024);

  return path_join(balloc, base_path, base_query, rel_path, rel_query).str();
}

bool expect_response_body(int status_code) {
  return status_code == 101 ||
         (status_code / 100 != 1 && status_code != 304 && status_code != 204);
}

bool expect_response_body(const std::string &method, int status_code) {
  return method != "HEAD" && expect_response_body(status_code);
}

bool expect_response_body(int method_token, int status_code) {
  return method_token != HTTP_HEAD && expect_response_body(status_code);
}

int lookup_method_token(const StringRef &name) {
  return lookup_method_token(name.byte(), name.size());
}

// This function was generated by genmethodfunc.py.
int lookup_method_token(const uint8_t *name, size_t namelen) {
  switch (namelen) {
  case 3:
    switch (name[2]) {
    case 'L':
      if (util::streq_l("AC", name, 2)) {
        return HTTP_ACL;
      }
      break;
    case 'T':
      if (util::streq_l("GE", name, 2)) {
        return HTTP_GET;
      }
      if (util::streq_l("PU", name, 2)) {
        return HTTP_PUT;
      }
      break;
    }
    break;
  case 4:
    switch (name[3]) {
    case 'D':
      if (util::streq_l("BIN", name, 3)) {
        return HTTP_BIND;
      }
      if (util::streq_l("HEA", name, 3)) {
        return HTTP_HEAD;
      }
      break;
    case 'E':
      if (util::streq_l("MOV", name, 3)) {
        return HTTP_MOVE;
      }
      break;
    case 'K':
      if (util::streq_l("LIN", name, 3)) {
        return HTTP_LINK;
      }
      if (util::streq_l("LOC", name, 3)) {
        return HTTP_LOCK;
      }
      break;
    case 'T':
      if (util::streq_l("POS", name, 3)) {
        return HTTP_POST;
      }
      break;
    case 'Y':
      if (util::streq_l("COP", name, 3)) {
        return HTTP_COPY;
      }
      break;
    }
    break;
  case 5:
    switch (name[4]) {
    case 'E':
      if (util::streq_l("MERG", name, 4)) {
        return HTTP_MERGE;
      }
      if (util::streq_l("PURG", name, 4)) {
        return HTTP_PURGE;
      }
      if (util::streq_l("TRAC", name, 4)) {
        return HTTP_TRACE;
      }
      break;
    case 'H':
      if (util::streq_l("PATC", name, 4)) {
        return HTTP_PATCH;
      }
      break;
    case 'L':
      if (util::streq_l("MKCO", name, 4)) {
        return HTTP_MKCOL;
      }
      break;
    }
    break;
  case 6:
    switch (name[5]) {
    case 'D':
      if (util::streq_l("REBIN", name, 5)) {
        return HTTP_REBIND;
      }
      if (util::streq_l("UNBIN", name, 5)) {
        return HTTP_UNBIND;
      }
      break;
    case 'E':
      if (util::streq_l("DELET", name, 5)) {
        return HTTP_DELETE;
      }
      if (util::streq_l("SOURC", name, 5)) {
        return HTTP_SOURCE;
      }
      break;
    case 'H':
      if (util::streq_l("SEARC", name, 5)) {
        return HTTP_SEARCH;
      }
      break;
    case 'K':
      if (util::streq_l("UNLIN", name, 5)) {
        return HTTP_UNLINK;
      }
      if (util::streq_l("UNLOC", name, 5)) {
        return HTTP_UNLOCK;
      }
      break;
    case 'T':
      if (util::streq_l("REPOR", name, 5)) {
        return HTTP_REPORT;
      }
      break;
    case 'Y':
      if (util::streq_l("NOTIF", name, 5)) {
        return HTTP_NOTIFY;
      }
      break;
    }
    break;
  case 7:
    switch (name[6]) {
    case 'H':
      if (util::streq_l("MSEARC", name, 6)) {
        return HTTP_MSEARCH;
      }
      break;
    case 'S':
      if (util::streq_l("OPTION", name, 6)) {
        return HTTP_OPTIONS;
      }
      break;
    case 'T':
      if (util::streq_l("CONNEC", name, 6)) {
        return HTTP_CONNECT;
      }
      break;
    }
    break;
  case 8:
    switch (name[7]) {
    case 'D':
      if (util::streq_l("PROPFIN", name, 7)) {
        return HTTP_PROPFIND;
      }
      break;
    case 'T':
      if (util::streq_l("CHECKOU", name, 7)) {
        return HTTP_CHECKOUT;
      }
      break;
    }
    break;
  case 9:
    switch (name[8]) {
    case 'E':
      if (util::streq_l("SUBSCRIB", name, 8)) {
        return HTTP_SUBSCRIBE;
      }
      break;
    case 'H':
      if (util::streq_l("PROPPATC", name, 8)) {
        return HTTP_PROPPATCH;
      }
      break;
    }
    break;
  case 10:
    switch (name[9]) {
    case 'R':
      if (util::streq_l("MKCALENDA", name, 9)) {
        return HTTP_MKCALENDAR;
      }
      break;
    case 'Y':
      if (util::streq_l("MKACTIVIT", name, 9)) {
        return HTTP_MKACTIVITY;
      }
      break;
    }
    break;
  case 11:
    switch (name[10]) {
    case 'E':
      if (util::streq_l("UNSUBSCRIB", name, 10)) {
        return HTTP_UNSUBSCRIBE;
      }
      break;
    }
    break;
  }
  return -1;
}

StringRef to_method_string(int method_token) {
  // we happened to use same value for method with llhttp.
  return StringRef{
      llhttp_method_name(static_cast<llhttp_method>(method_token))};
}

StringRef get_pure_path_component(const StringRef &uri) {
  int rv;

  http_parser_url u{};
  rv = http_parser_parse_url(uri.c_str(), uri.size(), 0, &u);
  if (rv != 0) {
    return StringRef{};
  }

  if (u.field_set & (1 << UF_PATH)) {
    auto &f = u.field_data[UF_PATH];
    return StringRef{uri.c_str() + f.off, f.len};
  }

  return StringRef::from_lit("/");
}

int construct_push_component(BlockAllocator &balloc, StringRef &scheme,
                             StringRef &authority, StringRef &path,
                             const StringRef &base, const StringRef &uri) {
  int rv;
  StringRef rel, relq;

  if (uri.size() == 0) {
    return -1;
  }

  http_parser_url u{};

  rv = http_parser_parse_url(uri.c_str(), uri.size(), 0, &u);

  if (rv != 0) {
    if (uri[0] == '/') {
      return -1;
    }

    // treat link_url as relative URI.
    auto end = std::find(std::begin(uri), std::end(uri), '#');
    auto q = std::find(std::begin(uri), end, '?');

    rel = StringRef{std::begin(uri), q};
    if (q != end) {
      relq = StringRef{q + 1, std::end(uri)};
    }
  } else {
    if (u.field_set & (1 << UF_SCHEMA)) {
      scheme = util::get_uri_field(uri.c_str(), u, UF_SCHEMA);
    }

    if (u.field_set & (1 << UF_HOST)) {
      auto auth = util::get_uri_field(uri.c_str(), u, UF_HOST);
      auto len = auth.size();
      auto port_exists = u.field_set & (1 << UF_PORT);
      if (port_exists) {
        len += 1 + str_size("65535");
      }
      auto iov = make_byte_ref(balloc, len + 1);
      auto p = iov.base;
      p = std::copy(std::begin(auth), std::end(auth), p);
      if (port_exists) {
        *p++ = ':';
        p = util::utos(p, u.port);
      }
      *p = '\0';

      authority = StringRef{iov.base, p};
    }

    if (u.field_set & (1 << UF_PATH)) {
      auto &f = u.field_data[UF_PATH];
      rel = StringRef{uri.c_str() + f.off, f.len};
    } else {
      rel = StringRef::from_lit("/");
    }

    if (u.field_set & (1 << UF_QUERY)) {
      auto &f = u.field_data[UF_QUERY];
      relq = StringRef{uri.c_str() + f.off, f.len};
    }
  }

  path = http2::path_join(balloc, base, StringRef{}, rel, relq);

  return 0;
}

namespace {
template <typename InputIt> InputIt eat_file(InputIt first, InputIt last) {
  if (first == last) {
    *first++ = '/';
    return first;
  }

  if (*(last - 1) == '/') {
    return last;
  }

  auto p = last;
  for (; p != first && *(p - 1) != '/'; --p)
    ;
  if (p == first) {
    // this should not happened in normal case, where we expect path
    // starts with '/'
    *first++ = '/';
    return first;
  }

  return p;
}
} // namespace

namespace {
template <typename InputIt> InputIt eat_dir(InputIt first, InputIt last) {
  auto p = eat_file(first, last);

  --p;

  assert(*p == '/');

  return eat_file(first, p);
}
} // namespace

StringRef path_join(BlockAllocator &balloc, const StringRef &base_path,
                    const StringRef &base_query, const StringRef &rel_path,
                    const StringRef &rel_query) {
  auto res = make_byte_ref(
      balloc, std::max(static_cast<size_t>(1), base_path.size()) +
                  rel_path.size() + 1 +
                  std::max(base_query.size(), rel_query.size()) + 1);
  auto p = res.base;

  if (rel_path.empty()) {
    if (base_path.empty()) {
      *p++ = '/';
    } else {
      p = std::copy(std::begin(base_path), std::end(base_path), p);
    }
    if (rel_query.empty()) {
      if (!base_query.empty()) {
        *p++ = '?';
        p = std::copy(std::begin(base_query), std::end(base_query), p);
      }
      *p = '\0';
      return StringRef{res.base, p};
    }
    *p++ = '?';
    p = std::copy(std::begin(rel_query), std::end(rel_query), p);
    *p = '\0';
    return StringRef{res.base, p};
  }

  auto first = std::begin(rel_path);
  auto last = std::end(rel_path);

  if (rel_path[0] == '/') {
    *p++ = '/';
    ++first;
    for (; first != last && *first == '/'; ++first)
      ;
  } else if (base_path.empty()) {
    *p++ = '/';
  } else {
    p = std::copy(std::begin(base_path), std::end(base_path), p);
  }

  for (; first != last;) {
    if (*first == '.') {
      if (first + 1 == last) {
        if (*(p - 1) != '/') {
          p = eat_file(res.base, p);
        }
        break;
      }
      if (*(first + 1) == '/') {
        if (*(p - 1) != '/') {
          p = eat_file(res.base, p);
        }
        first += 2;
        continue;
      }
      if (*(first + 1) == '.') {
        if (first + 2 == last) {
          p = eat_dir(res.base, p);
          break;
        }
        if (*(first + 2) == '/') {
          p = eat_dir(res.base, p);
          first += 3;
          continue;
        }
      }
    }
    if (*(p - 1) != '/') {
      p = eat_file(res.base, p);
    }
    auto slash = std::find(first, last, '/');
    if (slash == last) {
      p = std::copy(first, last, p);
      break;
    }
    p = std::copy(first, slash + 1, p);
    first = slash + 1;
    for (; first != last && *first == '/'; ++first)
      ;
  }
  if (!rel_query.empty()) {
    *p++ = '?';
    p = std::copy(std::begin(rel_query), std::end(rel_query), p);
  }
  *p = '\0';
  return StringRef{res.base, p};
}

StringRef normalize_path(BlockAllocator &balloc, const StringRef &path,
                         const StringRef &query) {
  // First, decode %XX for unreserved characters, then do
  // http2::path_join

  // We won't find %XX if length is less than 3.
  if (path.size() < 3 ||
      std::find(std::begin(path), std::end(path), '%') == std::end(path)) {
    return path_join(balloc, StringRef{}, StringRef{}, path, query);
  }

  // includes last terminal NULL.
  auto result = make_byte_ref(balloc, path.size() + 1);
  auto p = result.base;

  auto it = std::begin(path);
  for (; it + 2 < std::end(path);) {
    if (*it == '%') {
      if (util::is_hex_digit(*(it + 1)) && util::is_hex_digit(*(it + 2))) {
        auto c =
            (util::hex_to_uint(*(it + 1)) << 4) + util::hex_to_uint(*(it + 2));
        if (util::in_rfc3986_unreserved_chars(c)) {
          *p++ = c;

          it += 3;

          continue;
        }
        *p++ = '%';
        *p++ = util::upcase(*(it + 1));
        *p++ = util::upcase(*(it + 2));

        it += 3;

        continue;
      }
    }
    *p++ = *it++;
  }

  p = std::copy(it, std::end(path), p);
  *p = '\0';

  return path_join(balloc, StringRef{}, StringRef{}, StringRef{result.base, p},
                   query);
}

StringRef normalize_path_colon(BlockAllocator &balloc, const StringRef &path,
                               const StringRef &query) {
  // First, decode %XX for unreserved characters and ':', then do
  // http2::path_join

  // We won't find %XX if length is less than 3.
  if (path.size() < 3 ||
      std::find(std::begin(path), std::end(path), '%') == std::end(path)) {
    return path_join(balloc, StringRef{}, StringRef{}, path, query);
  }

  // includes last terminal NULL.
  auto result = make_byte_ref(balloc, path.size() + 1);
  auto p = result.base;

  auto it = std::begin(path);
  for (; it + 2 < std::end(path);) {
    if (*it == '%') {
      if (util::is_hex_digit(*(it + 1)) && util::is_hex_digit(*(it + 2))) {
        auto c =
            (util::hex_to_uint(*(it + 1)) << 4) + util::hex_to_uint(*(it + 2));
        if (util::in_rfc3986_unreserved_chars(c) || c == ':') {
          *p++ = c;

          it += 3;

          continue;
        }
        *p++ = '%';
        *p++ = util::upcase(*(it + 1));
        *p++ = util::upcase(*(it + 2));

        it += 3;

        continue;
      }
    }
    *p++ = *it++;
  }

  p = std::copy(it, std::end(path), p);
  *p = '\0';

  return path_join(balloc, StringRef{}, StringRef{}, StringRef{result.base, p},
                   query);
}

std::string normalize_path(const StringRef &path, const StringRef &query) {
  BlockAllocator balloc(1024, 1024);

  return normalize_path(balloc, path, query).str();
}

StringRef rewrite_clean_path(BlockAllocator &balloc, const StringRef &src) {
  if (src.empty() || src[0] != '/') {
    return src;
  }
  // probably, not necessary most of the case, but just in case.
  auto fragment = std::find(std::begin(src), std::end(src), '#');
  auto raw_query = std::find(std::begin(src), fragment, '?');
  auto query = raw_query;
  if (query != fragment) {
    ++query;
  }
  return normalize_path(balloc, StringRef{std::begin(src), raw_query},
                        StringRef{query, fragment});
}

StringRef copy_lower(BlockAllocator &balloc, const StringRef &src) {
  auto iov = make_byte_ref(balloc, src.size() + 1);
  auto p = iov.base;
  p = std::copy(std::begin(src), std::end(src), p);
  *p = '\0';
  util::inp_strlower(iov.base, p);
  return StringRef{iov.base, p};
}

bool contains_trailers(const StringRef &s) {
  constexpr auto trailers = StringRef::from_lit("trailers");

  for (auto p = std::begin(s), end = std::end(s);; ++p) {
    p = std::find_if(p, end, [](char c) { return c != ' ' && c != '\t'; });
    if (p == end || static_cast<size_t>(end - p) < trailers.size()) {
      return false;
    }
    if (util::strieq(trailers, StringRef{p, p + trailers.size()})) {
      // Make sure that there is no character other than white spaces
      // before next "," or end of string.
      p = std::find_if(p + trailers.size(), end,
                       [](char c) { return c != ' ' && c != '\t'; });
      if (p == end || *p == ',') {
        return true;
      }
    }
    // Skip to next ",".
    p = std::find_if(p, end, [](char c) { return c == ','; });
    if (p == end) {
      return false;
    }
  }
}

StringRef make_websocket_accept_token(uint8_t *dest, const StringRef &key) {
  static constexpr uint8_t magic[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  std::array<uint8_t, base64::encode_length(16) + str_size(magic)> s;
  auto p = std::copy(std::begin(key), std::end(key), std::begin(s));
  std::copy_n(magic, str_size(magic), p);

  std::array<uint8_t, 20> h;
  if (util::sha1(h.data(), StringRef{std::begin(s), std::end(s)}) != 0) {
    return StringRef{};
  }

  auto end = base64::encode(std::begin(h), std::end(h), dest);
  return StringRef{dest, end};
}

bool legacy_http1(int major, int minor) {
  return major <= 0 || (major == 1 && minor == 0);
}

bool check_transfer_encoding(const StringRef &s) {
  if (s.empty()) {
    return false;
  }

  auto it = std::begin(s);

  for (;;) {
    // token
    if (!util::in_token(*it)) {
      return false;
    }

    ++it;

    for (; it != std::end(s) && util::in_token(*it); ++it)
      ;

    if (it == std::end(s)) {
      return true;
    }

    for (;;) {
      // OWS
      it = skip_lws(it, std::end(s));
      if (it == std::end(s)) {
        return false;
      }

      if (*it == ',') {
        ++it;

        it = skip_lws(it, std::end(s));
        if (it == std::end(s)) {
          return false;
        }

        break;
      }

      if (*it != ';') {
        return false;
      }

      ++it;

      // transfer-parameter follows

      // OWS
      it = skip_lws(it, std::end(s));
      if (it == std::end(s)) {
        return false;
      }

      // token
      if (!util::in_token(*it)) {
        return false;
      }

      ++it;

      for (; it != std::end(s) && util::in_token(*it); ++it)
        ;

      if (it == std::end(s)) {
        return false;
      }

      // No BWS allowed
      if (*it != '=') {
        return false;
      }

      ++it;

      if (util::in_token(*it)) {
        // token
        ++it;

        for (; it != std::end(s) && util::in_token(*it); ++it)
          ;
      } else if (*it == '"') {
        // quoted-string
        ++it;

        it = skip_to_right_dquote(it, std::end(s));
        if (it == std::end(s)) {
          return false;
        }

        ++it;
      } else {
        return false;
      }

      if (it == std::end(s)) {
        return true;
      }
    }
  }
}

} // namespace http2

} // namespace nghttp2
