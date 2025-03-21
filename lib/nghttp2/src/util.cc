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
#include "util.h"

#ifdef HAVE_TIME_H
#  include <time.h>
#endif // HAVE_TIME_H
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif // HAVE_SYS_SOCKET_H
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif // HAVE_NETDB_H
#include <sys/stat.h>
#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif // HAVE_FCNTL_H
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif // HAVE_NETINET_IN_H
#ifdef HAVE_NETINET_IP_H
#  include <netinet/ip.h>
#endif // HAVE_NETINET_IP_H
#include <netinet/udp.h>
#ifdef _WIN32
#  include <ws2tcpip.h>
#else // !_WIN32
#  include <netinet/tcp.h>
#endif // !_WIN32
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif // HAVE_ARPA_INET_H

#include <cmath>
#include <cerrno>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <fstream>
#include <iomanip>

#include <openssl/evp.h>

#include <nghttp2/nghttp2.h>

#include "ssl_compat.h"
#include "timegm.h"

namespace nghttp2 {

namespace util {

#ifndef _WIN32
namespace {
int nghttp2_inet_pton(int af, const char *src, void *dst) {
  return inet_pton(af, src, dst);
}
} // namespace
#else // _WIN32
namespace {
// inet_pton-wrapper for Windows
int nghttp2_inet_pton(int af, const char *src, void *dst) {
#  if _WIN32_WINNT >= 0x0600
  return InetPtonA(af, src, dst);
#  else
  // the function takes a 'char*', so we need to make a copy
  char addr[INET6_ADDRSTRLEN + 1];
  strncpy(addr, src, sizeof(addr));
  addr[sizeof(addr) - 1] = 0;

  int size = sizeof(struct in6_addr);

  if (WSAStringToAddress(addr, af, nullptr, (LPSOCKADDR)dst, &size) == 0)
    return 1;
  return 0;
#  endif
}
} // namespace
#endif // _WIN32

const char UPPER_XDIGITS[] = "0123456789ABCDEF";

bool in_rfc3986_unreserved_chars(const char c) {
  switch (c) {
  case '-':
  case '.':
  case '_':
  case '~':
    return true;
  }

  return is_alpha(c) || is_digit(c);
}

bool in_rfc3986_sub_delims(const char c) {
  switch (c) {
  case '!':
  case '$':
  case '&':
  case '\'':
  case '(':
  case ')':
  case '*':
  case '+':
  case ',':
  case ';':
  case '=':
    return true;
  }

  return false;
}

std::string percent_encode(const unsigned char *target, size_t len) {
  std::string dest;
  for (size_t i = 0; i < len; ++i) {
    unsigned char c = target[i];

    if (in_rfc3986_unreserved_chars(c)) {
      dest += c;
    } else {
      dest += '%';
      dest += UPPER_XDIGITS[c >> 4];
      dest += UPPER_XDIGITS[(c & 0x0f)];
    }
  }
  return dest;
}

std::string percent_encode(const std::string &target) {
  return percent_encode(reinterpret_cast<const unsigned char *>(target.c_str()),
                        target.size());
}

bool in_token(char c) {
  switch (c) {
  case '!':
  case '#':
  case '$':
  case '%':
  case '&':
  case '\'':
  case '*':
  case '+':
  case '-':
  case '.':
  case '^':
  case '_':
  case '`':
  case '|':
  case '~':
    return true;
  }

  return is_alpha(c) || is_digit(c);
}

bool in_attr_char(char c) {
  switch (c) {
  case '*':
  case '\'':
  case '%':
    return false;
  }

  return util::in_token(c);
}

StringRef percent_encode_token(BlockAllocator &balloc,
                               const StringRef &target) {
  auto iov = make_byte_ref(balloc, target.size() * 3 + 1);
  auto p = percent_encode_token(iov.base, target);

  *p = '\0';

  return StringRef{iov.base, p};
}

size_t percent_encode_tokenlen(const StringRef &target) {
  size_t n = 0;

  for (auto first = std::begin(target); first != std::end(target); ++first) {
    uint8_t c = *first;

    if (c != '%' && in_token(c)) {
      ++n;
      continue;
    }

    // percent-encoded character '%ff'
    n += 3;
  }

  return n;
}

uint32_t hex_to_uint(char c) {
  if (c <= '9') {
    return c - '0';
  }
  if (c <= 'Z') {
    return c - 'A' + 10;
  }
  if (c <= 'z') {
    return c - 'a' + 10;
  }
  return 256;
}

StringRef quote_string(BlockAllocator &balloc, const StringRef &target) {
  auto cnt = std::count(std::begin(target), std::end(target), '"');

  if (cnt == 0) {
    return make_string_ref(balloc, target);
  }

  auto iov = make_byte_ref(balloc, target.size() + cnt + 1);
  auto p = quote_string(iov.base, target);

  *p = '\0';

  return StringRef{iov.base, p};
}

size_t quote_stringlen(const StringRef &target) {
  size_t n = 0;

  for (auto c : target) {
    if (c == '"') {
      n += 2;
    } else {
      ++n;
    }
  }

  return n;
}

namespace {
template <typename Iterator>
Iterator cpydig(Iterator d, uint32_t n, size_t len) {
  auto p = d + len - 1;

  do {
    *p-- = (n % 10) + '0';
    n /= 10;
  } while (p >= d);

  return d + len;
}
} // namespace

namespace {
constexpr const char *MONTH[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
constexpr const char *DAY_OF_WEEK[] = {"Sun", "Mon", "Tue", "Wed",
                                       "Thu", "Fri", "Sat"};
} // namespace

std::string http_date(time_t t) {
  /* Sat, 27 Sep 2014 06:31:15 GMT */
  std::string res(29, 0);
  http_date(&res[0], t);
  return res;
}

char *http_date(char *res, time_t t) {
  struct tm tms;

  if (gmtime_r(&t, &tms) == nullptr) {
    return res;
  }

  auto p = res;

  auto s = DAY_OF_WEEK[tms.tm_wday];
  p = std::copy_n(s, 3, p);
  *p++ = ',';
  *p++ = ' ';
  p = cpydig(p, tms.tm_mday, 2);
  *p++ = ' ';
  s = MONTH[tms.tm_mon];
  p = std::copy_n(s, 3, p);
  *p++ = ' ';
  p = cpydig(p, tms.tm_year + 1900, 4);
  *p++ = ' ';
  p = cpydig(p, tms.tm_hour, 2);
  *p++ = ':';
  p = cpydig(p, tms.tm_min, 2);
  *p++ = ':';
  p = cpydig(p, tms.tm_sec, 2);
  s = " GMT";
  p = std::copy_n(s, 4, p);

  return p;
}

std::string common_log_date(time_t t) {
  // 03/Jul/2014:00:19:38 +0900
  std::string res(26, 0);
  common_log_date(&res[0], t);
  return res;
}

char *common_log_date(char *res, time_t t) {
  struct tm tms;

  if (localtime_r(&t, &tms) == nullptr) {
    return res;
  }

  auto p = res;

  p = cpydig(p, tms.tm_mday, 2);
  *p++ = '/';
  auto s = MONTH[tms.tm_mon];
  p = std::copy_n(s, 3, p);
  *p++ = '/';
  p = cpydig(p, tms.tm_year + 1900, 4);
  *p++ = ':';
  p = cpydig(p, tms.tm_hour, 2);
  *p++ = ':';
  p = cpydig(p, tms.tm_min, 2);
  *p++ = ':';
  p = cpydig(p, tms.tm_sec, 2);
  *p++ = ' ';

#ifdef HAVE_STRUCT_TM_TM_GMTOFF
  auto gmtoff = tms.tm_gmtoff;
#else  // !HAVE_STRUCT_TM_TM_GMTOFF
  auto gmtoff = nghttp2_timegm(&tms) - t;
#endif // !HAVE_STRUCT_TM_TM_GMTOFF
  if (gmtoff >= 0) {
    *p++ = '+';
  } else {
    *p++ = '-';
    gmtoff = -gmtoff;
  }

  p = cpydig(p, gmtoff / 3600, 2);
  p = cpydig(p, (gmtoff % 3600) / 60, 2);

  return p;
}

std::string iso8601_date(int64_t ms) {
  // 2014-11-15T12:58:24.741Z
  // 2014-11-15T12:58:24.741+09:00
  std::string res(29, 0);
  auto p = iso8601_date(&res[0], ms);
  res.resize(p - &res[0]);
  return res;
}

char *iso8601_date(char *res, int64_t ms) {
  time_t sec = ms / 1000;

  tm tms;
  if (localtime_r(&sec, &tms) == nullptr) {
    return res;
  }

  auto p = res;

  p = cpydig(p, tms.tm_year + 1900, 4);
  *p++ = '-';
  p = cpydig(p, tms.tm_mon + 1, 2);
  *p++ = '-';
  p = cpydig(p, tms.tm_mday, 2);
  *p++ = 'T';
  p = cpydig(p, tms.tm_hour, 2);
  *p++ = ':';
  p = cpydig(p, tms.tm_min, 2);
  *p++ = ':';
  p = cpydig(p, tms.tm_sec, 2);
  *p++ = '.';
  p = cpydig(p, ms % 1000, 3);

#ifdef HAVE_STRUCT_TM_TM_GMTOFF
  auto gmtoff = tms.tm_gmtoff;
#else  // !HAVE_STRUCT_TM_TM_GMTOFF
  auto gmtoff = nghttp2_timegm(&tms) - sec;
#endif // !HAVE_STRUCT_TM_TM_GMTOFF
  if (gmtoff == 0) {
    *p++ = 'Z';
  } else {
    if (gmtoff > 0) {
      *p++ = '+';
    } else {
      *p++ = '-';
      gmtoff = -gmtoff;
    }
    p = cpydig(p, gmtoff / 3600, 2);
    *p++ = ':';
    p = cpydig(p, (gmtoff % 3600) / 60, 2);
  }

  return p;
}

char *iso8601_basic_date(char *res, int64_t ms) {
  time_t sec = ms / 1000;

  tm tms;
  if (localtime_r(&sec, &tms) == nullptr) {
    return res;
  }

  auto p = res;

  p = cpydig(p, tms.tm_year + 1900, 4);
  p = cpydig(p, tms.tm_mon + 1, 2);
  p = cpydig(p, tms.tm_mday, 2);
  *p++ = 'T';
  p = cpydig(p, tms.tm_hour, 2);
  p = cpydig(p, tms.tm_min, 2);
  p = cpydig(p, tms.tm_sec, 2);
  *p++ = '.';
  p = cpydig(p, ms % 1000, 3);

#ifdef HAVE_STRUCT_TM_TM_GMTOFF
  auto gmtoff = tms.tm_gmtoff;
#else  // !HAVE_STRUCT_TM_TM_GMTOFF
  auto gmtoff = nghttp2_timegm(&tms) - sec;
#endif // !HAVE_STRUCT_TM_TM_GMTOFF
  if (gmtoff == 0) {
    *p++ = 'Z';
  } else {
    if (gmtoff > 0) {
      *p++ = '+';
    } else {
      *p++ = '-';
      gmtoff = -gmtoff;
    }
    p = cpydig(p, gmtoff / 3600, 2);
    p = cpydig(p, (gmtoff % 3600) / 60, 2);
  }

  return p;
}

time_t parse_http_date(const StringRef &s) {
  tm tm{};
#ifdef _WIN32
  // there is no strptime - use std::get_time
  std::stringstream sstr(s.str());
  sstr >> std::get_time(&tm, "%a, %d %b %Y %H:%M:%S GMT");
  if (sstr.fail()) {
    return 0;
  }
#else  // !_WIN32
  char *r = strptime(s.c_str(), "%a, %d %b %Y %H:%M:%S GMT", &tm);
  if (r == 0) {
    return 0;
  }
#endif // !_WIN32
  return nghttp2_timegm_without_yday(&tm);
}

time_t parse_openssl_asn1_time_print(const StringRef &s) {
  tm tm{};
  auto r = strptime(s.c_str(), "%b %d %H:%M:%S %Y GMT", &tm);
  if (r == nullptr) {
    return 0;
  }
  return nghttp2_timegm_without_yday(&tm);
}

char upcase(char c) {
  if ('a' <= c && c <= 'z') {
    return c - 'a' + 'A';
  } else {
    return c;
  }
}

std::string format_hex(const unsigned char *s, size_t len) {
  std::string res;
  res.resize(len * 2);

  for (size_t i = 0; i < len; ++i) {
    unsigned char c = s[i];

    res[i * 2] = LOWER_XDIGITS[c >> 4];
    res[i * 2 + 1] = LOWER_XDIGITS[c & 0x0f];
  }
  return res;
}

StringRef format_hex(BlockAllocator &balloc, const StringRef &s) {
  auto iov = make_byte_ref(balloc, s.size() * 2 + 1);
  auto p = iov.base;

  for (auto cc : s) {
    uint8_t c = cc;
    *p++ = LOWER_XDIGITS[c >> 4];
    *p++ = LOWER_XDIGITS[c & 0xf];
  }

  *p = '\0';

  return StringRef{iov.base, p};
}

void to_token68(std::string &base64str) {
  std::transform(std::begin(base64str), std::end(base64str),
                 std::begin(base64str), [](char c) {
                   switch (c) {
                   case '+':
                     return '-';
                   case '/':
                     return '_';
                   default:
                     return c;
                   }
                 });
  base64str.erase(std::find(std::begin(base64str), std::end(base64str), '='),
                  std::end(base64str));
}

StringRef to_base64(BlockAllocator &balloc, const StringRef &token68str) {
  // At most 3 padding '='
  auto len = token68str.size() + 3;
  auto iov = make_byte_ref(balloc, len + 1);
  auto p = iov.base;

  p = std::transform(std::begin(token68str), std::end(token68str), p,
                     [](char c) {
                       switch (c) {
                       case '-':
                         return '+';
                       case '_':
                         return '/';
                       default:
                         return c;
                       }
                     });

  auto rem = token68str.size() & 0x3;
  if (rem) {
    p = std::fill_n(p, 4 - rem, '=');
  }

  *p = '\0';

  return StringRef{iov.base, p};
}

namespace {
// Calculates Damerau–Levenshtein distance between c-string a and b
// with given costs.  swapcost, subcost, addcost and delcost are cost
// to swap 2 adjacent characters, substitute characters, add character
// and delete character respectively.
int levenshtein(const char *a, int alen, const char *b, int blen, int swapcost,
                int subcost, int addcost, int delcost) {
  auto dp = std::vector<std::vector<int>>(3, std::vector<int>(blen + 1));
  for (int i = 0; i <= blen; ++i) {
    dp[1][i] = i;
  }
  for (int i = 1; i <= alen; ++i) {
    dp[0][0] = i;
    for (int j = 1; j <= blen; ++j) {
      dp[0][j] = dp[1][j - 1] + (a[i - 1] == b[j - 1] ? 0 : subcost);
      if (i >= 2 && j >= 2 && a[i - 1] != b[j - 1] && a[i - 2] == b[j - 1] &&
          a[i - 1] == b[j - 2]) {
        dp[0][j] = std::min(dp[0][j], dp[2][j - 2] + swapcost);
      }
      dp[0][j] = std::min(dp[0][j],
                          std::min(dp[1][j] + delcost, dp[0][j - 1] + addcost));
    }
    std::rotate(std::begin(dp), std::begin(dp) + 2, std::end(dp));
  }
  return dp[1][blen];
}
} // namespace

void show_candidates(const char *unkopt, const option *options) {
  for (; *unkopt == '-'; ++unkopt)
    ;
  if (*unkopt == '\0') {
    return;
  }
  auto unkoptend = unkopt;
  for (; *unkoptend && *unkoptend != '='; ++unkoptend)
    ;
  auto unkoptlen = unkoptend - unkopt;
  if (unkoptlen == 0) {
    return;
  }
  int prefix_match = 0;
  auto cands = std::vector<std::pair<int, const char *>>();
  for (size_t i = 0; options[i].name != nullptr; ++i) {
    auto optnamelen = strlen(options[i].name);
    // Use cost 0 for prefix match
    if (istarts_with(options[i].name, options[i].name + optnamelen, unkopt,
                     unkopt + unkoptlen)) {
      if (optnamelen == static_cast<size_t>(unkoptlen)) {
        // Exact match, then we don't show any condidates.
        return;
      }
      ++prefix_match;
      cands.emplace_back(0, options[i].name);
      continue;
    }
    // Use cost 0 for suffix match, but match at least 3 characters
    if (unkoptlen >= 3 &&
        iends_with(options[i].name, options[i].name + optnamelen, unkopt,
                   unkopt + unkoptlen)) {
      cands.emplace_back(0, options[i].name);
      continue;
    }
    // cost values are borrowed from git, help.c.
    int sim =
        levenshtein(unkopt, unkoptlen, options[i].name, optnamelen, 0, 2, 1, 3);
    cands.emplace_back(sim, options[i].name);
  }
  if (prefix_match == 1 || cands.empty()) {
    return;
  }
  std::sort(std::begin(cands), std::end(cands));
  int threshold = cands[0].first;
  // threshold value is a magic value.
  if (threshold > 6) {
    return;
  }
  std::cerr << "\nDid you mean:\n";
  for (auto &item : cands) {
    if (item.first > threshold) {
      break;
    }
    std::cerr << "\t--" << item.second << "\n";
  }
}

bool has_uri_field(const http_parser_url &u, http_parser_url_fields field) {
  return u.field_set & (1 << field);
}

bool fieldeq(const char *uri1, const http_parser_url &u1, const char *uri2,
             const http_parser_url &u2, http_parser_url_fields field) {
  if (!has_uri_field(u1, field)) {
    if (!has_uri_field(u2, field)) {
      return true;
    } else {
      return false;
    }
  } else if (!has_uri_field(u2, field)) {
    return false;
  }
  if (u1.field_data[field].len != u2.field_data[field].len) {
    return false;
  }
  return memcmp(uri1 + u1.field_data[field].off,
                uri2 + u2.field_data[field].off, u1.field_data[field].len) == 0;
}

bool fieldeq(const char *uri, const http_parser_url &u,
             http_parser_url_fields field, const char *t) {
  return fieldeq(uri, u, field, StringRef{t});
}

bool fieldeq(const char *uri, const http_parser_url &u,
             http_parser_url_fields field, const StringRef &t) {
  if (!has_uri_field(u, field)) {
    return t.empty();
  }
  auto &f = u.field_data[field];
  return StringRef{uri + f.off, f.len} == t;
}

StringRef get_uri_field(const char *uri, const http_parser_url &u,
                        http_parser_url_fields field) {
  if (!util::has_uri_field(u, field)) {
    return StringRef{};
  }

  return StringRef{uri + u.field_data[field].off, u.field_data[field].len};
}

uint16_t get_default_port(const char *uri, const http_parser_url &u) {
  if (util::fieldeq(uri, u, UF_SCHEMA, "https")) {
    return 443;
  } else if (util::fieldeq(uri, u, UF_SCHEMA, "http")) {
    return 80;
  } else {
    return 443;
  }
}

bool porteq(const char *uri1, const http_parser_url &u1, const char *uri2,
            const http_parser_url &u2) {
  uint16_t port1, port2;
  port1 =
      util::has_uri_field(u1, UF_PORT) ? u1.port : get_default_port(uri1, u1);
  port2 =
      util::has_uri_field(u2, UF_PORT) ? u2.port : get_default_port(uri2, u2);
  return port1 == port2;
}

void write_uri_field(std::ostream &o, const char *uri, const http_parser_url &u,
                     http_parser_url_fields field) {
  if (util::has_uri_field(u, field)) {
    o.write(uri + u.field_data[field].off, u.field_data[field].len);
  }
}

bool numeric_host(const char *hostname) {
  return numeric_host(hostname, AF_INET) || numeric_host(hostname, AF_INET6);
}

bool numeric_host(const char *hostname, int family) {
  int rv;
  std::array<uint8_t, sizeof(struct in6_addr)> dst;

  rv = nghttp2_inet_pton(family, hostname, dst.data());

  return rv == 1;
}

std::string numeric_name(const struct sockaddr *sa, socklen_t salen) {
  std::array<char, NI_MAXHOST> host;
  auto rv = getnameinfo(sa, salen, host.data(), host.size(), nullptr, 0,
                        NI_NUMERICHOST);
  if (rv != 0) {
    return "unknown";
  }
  return host.data();
}

std::string to_numeric_addr(const Address *addr) {
  return to_numeric_addr(&addr->su.sa, addr->len);
}

std::string to_numeric_addr(const struct sockaddr *sa, socklen_t salen) {
  auto family = sa->sa_family;
#ifndef _WIN32
  if (family == AF_UNIX) {
    return reinterpret_cast<const sockaddr_un *>(sa)->sun_path;
  }
#endif // !_WIN32

  std::array<char, NI_MAXHOST> host;
  std::array<char, NI_MAXSERV> serv;
  auto rv = getnameinfo(sa, salen, host.data(), host.size(), serv.data(),
                        serv.size(), NI_NUMERICHOST | NI_NUMERICSERV);
  if (rv != 0) {
    return "unknown";
  }

  auto hostlen = strlen(host.data());
  auto servlen = strlen(serv.data());

  std::string s;
  char *p;
  if (family == AF_INET6) {
    s.resize(hostlen + servlen + 2 + 1);
    p = &s[0];
    *p++ = '[';
    p = std::copy_n(host.data(), hostlen, p);
    *p++ = ']';
  } else {
    s.resize(hostlen + servlen + 1);
    p = &s[0];
    p = std::copy_n(host.data(), hostlen, p);
  }
  *p++ = ':';
  std::copy_n(serv.data(), servlen, p);

  return s;
}

void set_port(Address &addr, uint16_t port) {
  switch (addr.su.storage.ss_family) {
  case AF_INET:
    addr.su.in.sin_port = htons(port);
    break;
  case AF_INET6:
    addr.su.in6.sin6_port = htons(port);
    break;
  }
}

std::string ascii_dump(const uint8_t *data, size_t len) {
  std::string res;

  for (size_t i = 0; i < len; ++i) {
    auto c = data[i];

    if (c >= 0x20 && c < 0x7f) {
      res += c;
    } else {
      res += '.';
    }
  }

  return res;
}

char *get_exec_path(int argc, char **const argv, const char *cwd) {
  if (argc == 0 || cwd == nullptr) {
    return nullptr;
  }

  auto argv0 = argv[0];
  auto len = strlen(argv0);

  char *path;

  if (argv0[0] == '/') {
    path = static_cast<char *>(malloc(len + 1));
    if (path == nullptr) {
      return nullptr;
    }
    memcpy(path, argv0, len + 1);
  } else {
    auto cwdlen = strlen(cwd);
    path = static_cast<char *>(malloc(len + 1 + cwdlen + 1));
    if (path == nullptr) {
      return nullptr;
    }
    memcpy(path, cwd, cwdlen);
    path[cwdlen] = '/';
    memcpy(path + cwdlen + 1, argv0, len + 1);
  }

  return path;
}

bool check_path(const std::string &path) {
  // We don't like '\' in path.
  return !path.empty() && path[0] == '/' &&
         path.find('\\') == std::string::npos &&
         path.find("/../") == std::string::npos &&
         path.find("/./") == std::string::npos &&
         !util::ends_with_l(path, "/..") && !util::ends_with_l(path, "/.");
}

int64_t to_time64(const timeval &tv) {
  return tv.tv_sec * 1000000 + tv.tv_usec;
}

bool check_h2_is_selected(const StringRef &proto) {
  return streq(NGHTTP2_H2, proto) || streq(NGHTTP2_H2_16, proto) ||
         streq(NGHTTP2_H2_14, proto);
}

namespace {
bool select_proto(const unsigned char **out, unsigned char *outlen,
                  const unsigned char *in, unsigned int inlen,
                  const StringRef &key) {
  for (auto p = in, end = in + inlen; p + key.size() <= end; p += *p + 1) {
    if (std::equal(std::begin(key), std::end(key), p)) {
      *out = p + 1;
      *outlen = *p;
      return true;
    }
  }
  return false;
}
} // namespace

bool select_h2(const unsigned char **out, unsigned char *outlen,
               const unsigned char *in, unsigned int inlen) {
  return select_proto(out, outlen, in, inlen, NGHTTP2_H2_ALPN) ||
         select_proto(out, outlen, in, inlen, NGHTTP2_H2_16_ALPN) ||
         select_proto(out, outlen, in, inlen, NGHTTP2_H2_14_ALPN);
}

bool select_protocol(const unsigned char **out, unsigned char *outlen,
                     const unsigned char *in, unsigned int inlen,
                     std::vector<std::string> proto_list) {
  for (const auto &proto : proto_list) {
    if (select_proto(out, outlen, in, inlen, StringRef{proto})) {
      return true;
    }
  }

  return false;
}

std::vector<unsigned char> get_default_alpn() {
  auto res = std::vector<unsigned char>(NGHTTP2_H2_ALPN.size() +
                                        NGHTTP2_H2_16_ALPN.size() +
                                        NGHTTP2_H2_14_ALPN.size());
  auto p = std::begin(res);

  p = std::copy_n(std::begin(NGHTTP2_H2_ALPN), NGHTTP2_H2_ALPN.size(), p);
  p = std::copy_n(std::begin(NGHTTP2_H2_16_ALPN), NGHTTP2_H2_16_ALPN.size(), p);
  p = std::copy_n(std::begin(NGHTTP2_H2_14_ALPN), NGHTTP2_H2_14_ALPN.size(), p);

  return res;
}

std::vector<StringRef> split_str(const StringRef &s, char delim) {
  size_t len = 1;
  auto last = std::end(s);
  StringRef::const_iterator d;
  for (auto first = std::begin(s); (d = std::find(first, last, delim)) != last;
       ++len, first = d + 1)
    ;

  auto list = std::vector<StringRef>(len);

  len = 0;
  for (auto first = std::begin(s);; ++len) {
    auto stop = std::find(first, last, delim);
    list[len] = StringRef{first, stop};
    if (stop == last) {
      break;
    }
    first = stop + 1;
  }
  return list;
}

std::vector<StringRef> split_str(const StringRef &s, char delim, size_t n) {
  if (n == 0) {
    return split_str(s, delim);
  }

  if (n == 1) {
    return {s};
  }

  size_t len = 1;
  auto last = std::end(s);
  StringRef::const_iterator d;
  for (auto first = std::begin(s);
       len < n && (d = std::find(first, last, delim)) != last;
       ++len, first = d + 1)
    ;

  auto list = std::vector<StringRef>(len);

  len = 0;
  for (auto first = std::begin(s);; ++len) {
    if (len == n - 1) {
      list[len] = StringRef{first, last};
      break;
    }

    auto stop = std::find(first, last, delim);
    list[len] = StringRef{first, stop};
    if (stop == last) {
      break;
    }
    first = stop + 1;
  }
  return list;
}

std::vector<std::string> parse_config_str_list(const StringRef &s, char delim) {
  auto sublist = split_str(s, delim);
  auto res = std::vector<std::string>();
  res.reserve(sublist.size());
  for (const auto &s : sublist) {
    res.emplace_back(std::begin(s), std::end(s));
  }
  return res;
}

int make_socket_closeonexec(int fd) {
#ifdef _WIN32
  (void)fd;
  return 0;
#else  // !_WIN32
  int flags;
  int rv;
  while ((flags = fcntl(fd, F_GETFD)) == -1 && errno == EINTR)
    ;
  while ((rv = fcntl(fd, F_SETFD, flags | FD_CLOEXEC)) == -1 && errno == EINTR)
    ;
  return rv;
#endif // !_WIN32
}

int make_socket_nonblocking(int fd) {
  int rv;

#ifdef _WIN32
  u_long mode = 1;

  rv = ioctlsocket(fd, FIONBIO, &mode);
#else  // !_WIN32
  int flags;
  while ((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR)
    ;
  while ((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
    ;
#endif // !_WIN32

  return rv;
}

int make_socket_nodelay(int fd) {
  int val = 1;
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char *>(&val),
                 sizeof(val)) == -1) {
    return -1;
  }
  return 0;
}

int create_nonblock_socket(int family) {
#ifdef SOCK_NONBLOCK
  auto fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

  if (fd == -1) {
    return -1;
  }
#else  // !SOCK_NONBLOCK
  auto fd = socket(family, SOCK_STREAM, 0);

  if (fd == -1) {
    return -1;
  }

  make_socket_nonblocking(fd);
  make_socket_closeonexec(fd);
#endif // !SOCK_NONBLOCK

  if (family == AF_INET || family == AF_INET6) {
    make_socket_nodelay(fd);
  }

  return fd;
}

int create_nonblock_udp_socket(int family) {
#ifdef SOCK_NONBLOCK
  auto fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

  if (fd == -1) {
    return -1;
  }
#else  // !SOCK_NONBLOCK
  auto fd = socket(family, SOCK_DGRAM, 0);

  if (fd == -1) {
    return -1;
  }

  make_socket_nonblocking(fd);
  make_socket_closeonexec(fd);
#endif // !SOCK_NONBLOCK

  return fd;
}

int bind_any_addr_udp(int fd, int family) {
  addrinfo hints{};
  addrinfo *res, *rp;
  int rv;

  hints.ai_family = family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  rv = getaddrinfo(nullptr, "0", &hints, &res);
  if (rv != 0) {
    return -1;
  }

  for (rp = res; rp; rp = rp->ai_next) {
    if (bind(fd, rp->ai_addr, rp->ai_addrlen) != -1) {
      break;
    }
  }

  freeaddrinfo(res);

  if (!rp) {
    return -1;
  }

  return 0;
}

bool check_socket_connected(int fd) {
  int error;
  socklen_t len = sizeof(error);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len) != 0) {
    return false;
  }

  return error == 0;
}

int get_socket_error(int fd) {
  int error;
  socklen_t len = sizeof(error);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&error, &len) != 0) {
    return -1;
  }

  return error;
}

bool ipv6_numeric_addr(const char *host) {
  uint8_t dst[16];
  return nghttp2_inet_pton(AF_INET6, host, dst) == 1;
}

namespace {
std::pair<int64_t, size_t> parse_uint_digits(const void *ss, size_t len) {
  const uint8_t *s = static_cast<const uint8_t *>(ss);
  int64_t n = 0;
  size_t i;
  if (len == 0) {
    return {-1, 0};
  }
  constexpr int64_t max = std::numeric_limits<int64_t>::max();
  for (i = 0; i < len; ++i) {
    if ('0' <= s[i] && s[i] <= '9') {
      if (n > max / 10) {
        return {-1, 0};
      }
      n *= 10;
      if (n > max - (s[i] - '0')) {
        return {-1, 0};
      }
      n += s[i] - '0';
      continue;
    }
    break;
  }
  if (i == 0) {
    return {-1, 0};
  }
  return {n, i};
}
} // namespace

int64_t parse_uint_with_unit(const char *s) {
  return parse_uint_with_unit(reinterpret_cast<const uint8_t *>(s), strlen(s));
}

int64_t parse_uint_with_unit(const StringRef &s) {
  return parse_uint_with_unit(s.byte(), s.size());
}

int64_t parse_uint_with_unit(const uint8_t *s, size_t len) {
  int64_t n;
  size_t i;
  std::tie(n, i) = parse_uint_digits(s, len);
  if (n == -1) {
    return -1;
  }
  if (i == len) {
    return n;
  }
  if (i + 1 != len) {
    return -1;
  }
  int mul = 1;
  switch (s[i]) {
  case 'K':
  case 'k':
    mul = 1 << 10;
    break;
  case 'M':
  case 'm':
    mul = 1 << 20;
    break;
  case 'G':
  case 'g':
    mul = 1 << 30;
    break;
  default:
    return -1;
  }
  constexpr int64_t max = std::numeric_limits<int64_t>::max();
  if (n > max / mul) {
    return -1;
  }
  return n * mul;
}

int64_t parse_uint(const char *s) {
  return parse_uint(reinterpret_cast<const uint8_t *>(s), strlen(s));
}

int64_t parse_uint(const std::string &s) {
  return parse_uint(reinterpret_cast<const uint8_t *>(s.c_str()), s.size());
}

int64_t parse_uint(const StringRef &s) {
  return parse_uint(s.byte(), s.size());
}

int64_t parse_uint(const uint8_t *s, size_t len) {
  int64_t n;
  size_t i;
  std::tie(n, i) = parse_uint_digits(s, len);
  if (n == -1 || i != len) {
    return -1;
  }
  return n;
}

double parse_duration_with_unit(const char *s) {
  return parse_duration_with_unit(reinterpret_cast<const uint8_t *>(s),
                                  strlen(s));
}

double parse_duration_with_unit(const StringRef &s) {
  return parse_duration_with_unit(s.byte(), s.size());
}

double parse_duration_with_unit(const uint8_t *s, size_t len) {
  constexpr auto max = std::numeric_limits<int64_t>::max();
  int64_t n;
  size_t i;

  std::tie(n, i) = parse_uint_digits(s, len);
  if (n == -1) {
    goto fail;
  }
  if (i == len) {
    return static_cast<double>(n);
  }
  switch (s[i]) {
  case 'S':
  case 's':
    // seconds
    if (i + 1 != len) {
      goto fail;
    }
    return static_cast<double>(n);
  case 'M':
  case 'm':
    if (i + 1 == len) {
      // minutes
      if (n > max / 60) {
        goto fail;
      }
      return static_cast<double>(n) * 60;
    }

    if (i + 2 != len || (s[i + 1] != 's' && s[i + 1] != 'S')) {
      goto fail;
    }
    // milliseconds
    return static_cast<double>(n) / 1000.;
  case 'H':
  case 'h':
    // hours
    if (i + 1 != len) {
      goto fail;
    }
    if (n > max / 3600) {
      goto fail;
    }
    return static_cast<double>(n) * 3600;
  }
fail:
  return std::numeric_limits<double>::infinity();
}

std::string duration_str(double t) {
  if (t == 0.) {
    return "0";
  }
  auto frac = static_cast<int64_t>(t * 1000) % 1000;
  if (frac > 0) {
    return utos(static_cast<int64_t>(t * 1000)) + "ms";
  }
  auto v = static_cast<int64_t>(t);
  if (v % 60) {
    return utos(v) + "s";
  }
  v /= 60;
  if (v % 60) {
    return utos(v) + "m";
  }
  v /= 60;
  return utos(v) + "h";
}

std::string format_duration(const std::chrono::microseconds &u) {
  const char *unit = "us";
  int d = 0;
  auto t = u.count();
  if (t >= 1000000) {
    d = 1000000;
    unit = "s";
  } else if (t >= 1000) {
    d = 1000;
    unit = "ms";
  } else {
    return utos(t) + unit;
  }
  return dtos(static_cast<double>(t) / d) + unit;
}

std::string format_duration(double t) {
  const char *unit = "us";
  if (t >= 1.) {
    unit = "s";
  } else if (t >= 0.001) {
    t *= 1000.;
    unit = "ms";
  } else {
    t *= 1000000.;
    return utos(static_cast<int64_t>(t)) + unit;
  }
  return dtos(t) + unit;
}

std::string dtos(double n) {
  auto m = llround(100. * n);
  auto f = utos(m % 100);
  return utos(m / 100) + "." + (f.size() == 1 ? "0" : "") + f;
}

StringRef make_http_hostport(BlockAllocator &balloc, const StringRef &host,
                             uint16_t port) {
  auto iov = make_byte_ref(balloc, host.size() + 2 + 1 + 5 + 1);
  return make_http_hostport(iov.base, host, port);
}

StringRef make_hostport(BlockAllocator &balloc, const StringRef &host,
                        uint16_t port) {
  auto iov = make_byte_ref(balloc, host.size() + 2 + 1 + 5 + 1);
  return make_hostport(iov.base, host, port);
}

namespace {
void hexdump8(FILE *out, const uint8_t *first, const uint8_t *last) {
  auto stop = std::min(first + 8, last);
  for (auto k = first; k != stop; ++k) {
    fprintf(out, "%02x ", *k);
  }
  // each byte needs 3 spaces (2 hex value and space)
  for (; stop != first + 8; ++stop) {
    fputs("   ", out);
  }
  // we have extra space after 8 bytes
  fputc(' ', out);
}
} // namespace

void hexdump(FILE *out, const uint8_t *src, size_t len) {
  if (len == 0) {
    return;
  }
  size_t buflen = 0;
  auto repeated = false;
  std::array<uint8_t, 16> buf{};
  auto end = src + len;
  auto i = src;
  for (;;) {
    auto nextlen =
        std::min(static_cast<size_t>(16), static_cast<size_t>(end - i));
    if (nextlen == buflen &&
        std::equal(std::begin(buf), std::begin(buf) + buflen, i)) {
      // as long as adjacent 16 bytes block are the same, we just
      // print single '*'.
      if (!repeated) {
        repeated = true;
        fputs("*\n", out);
      }
      i += nextlen;
      continue;
    }
    repeated = false;
    fprintf(out, "%08lx", static_cast<unsigned long>(i - src));
    if (i == end) {
      fputc('\n', out);
      break;
    }
    fputs("  ", out);
    hexdump8(out, i, end);
    hexdump8(out, i + 8, std::max(i + 8, end));
    fputc('|', out);
    auto stop = std::min(i + 16, end);
    buflen = stop - i;
    auto p = buf.data();
    for (; i != stop; ++i) {
      *p++ = *i;
      if (0x20 <= *i && *i <= 0x7e) {
        fputc(*i, out);
      } else {
        fputc('.', out);
      }
    }
    fputs("|\n", out);
  }
}

void put_uint16be(uint8_t *buf, uint16_t n) {
  uint16_t x = htons(n);
  memcpy(buf, &x, sizeof(uint16_t));
}

void put_uint32be(uint8_t *buf, uint32_t n) {
  uint32_t x = htonl(n);
  memcpy(buf, &x, sizeof(uint32_t));
}

uint16_t get_uint16(const uint8_t *data) {
  uint16_t n;
  memcpy(&n, data, sizeof(uint16_t));
  return ntohs(n);
}

uint32_t get_uint32(const uint8_t *data) {
  uint32_t n;
  memcpy(&n, data, sizeof(uint32_t));
  return ntohl(n);
}

uint64_t get_uint64(const uint8_t *data) {
  uint64_t n = 0;
  n += static_cast<uint64_t>(data[0]) << 56;
  n += static_cast<uint64_t>(data[1]) << 48;
  n += static_cast<uint64_t>(data[2]) << 40;
  n += static_cast<uint64_t>(data[3]) << 32;
  n += static_cast<uint64_t>(data[4]) << 24;
  n += data[5] << 16;
  n += data[6] << 8;
  n += data[7];
  return n;
}

int read_mime_types(std::map<std::string, std::string> &res,
                    const char *filename) {
  std::ifstream infile(filename);
  if (!infile) {
    return -1;
  }

  auto delim_pred = [](char c) { return c == ' ' || c == '\t'; };

  std::string line;
  while (std::getline(infile, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }

    auto type_end = std::find_if(std::begin(line), std::end(line), delim_pred);
    if (type_end == std::begin(line)) {
      continue;
    }

    auto ext_end = type_end;
    for (;;) {
      auto ext_start = std::find_if_not(ext_end, std::end(line), delim_pred);
      if (ext_start == std::end(line)) {
        break;
      }
      ext_end = std::find_if(ext_start, std::end(line), delim_pred);
#ifdef HAVE_STD_MAP_EMPLACE
      res.emplace(std::string(ext_start, ext_end),
                  std::string(std::begin(line), type_end));
#else  // !HAVE_STD_MAP_EMPLACE
      res.insert(std::make_pair(std::string(ext_start, ext_end),
                                std::string(std::begin(line), type_end)));
#endif // !HAVE_STD_MAP_EMPLACE
    }
  }

  return 0;
}

StringRef percent_decode(BlockAllocator &balloc, const StringRef &src) {
  auto iov = make_byte_ref(balloc, src.size() * 3 + 1);
  auto p = iov.base;
  for (auto first = std::begin(src); first != std::end(src); ++first) {
    if (*first != '%') {
      *p++ = *first;
      continue;
    }

    if (first + 1 != std::end(src) && first + 2 != std::end(src) &&
        is_hex_digit(*(first + 1)) && is_hex_digit(*(first + 2))) {
      *p++ = (hex_to_uint(*(first + 1)) << 4) + hex_to_uint(*(first + 2));
      first += 2;
      continue;
    }

    *p++ = *first;
  }
  *p = '\0';
  return StringRef{iov.base, p};
}

// Returns x**y
double int_pow(double x, size_t y) {
  auto res = 1.;
  for (; y; --y) {
    res *= x;
  }
  return res;
}

uint32_t hash32(const StringRef &s) {
  /* 32 bit FNV-1a: http://isthe.com/chongo/tech/comp/fnv/ */
  uint32_t h = 2166136261u;
  size_t i;

  for (i = 0; i < s.size(); ++i) {
    h ^= s[i];
    h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
  }

  return h;
}

#if !OPENSSL_1_1_API
namespace {
EVP_MD_CTX *EVP_MD_CTX_new(void) { return EVP_MD_CTX_create(); }
} // namespace

namespace {
void EVP_MD_CTX_free(EVP_MD_CTX *ctx) { EVP_MD_CTX_destroy(ctx); }
} // namespace
#endif // !OPENSSL_1_1_API

namespace {
int message_digest(uint8_t *res, const EVP_MD *meth, const StringRef &s) {
  int rv;

  auto ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    return -1;
  }

  auto ctx_deleter = defer(EVP_MD_CTX_free, ctx);

  rv = EVP_DigestInit_ex(ctx, meth, nullptr);
  if (rv != 1) {
    return -1;
  }

  rv = EVP_DigestUpdate(ctx, s.c_str(), s.size());
  if (rv != 1) {
    return -1;
  }

  unsigned int mdlen = EVP_MD_size(meth);

  rv = EVP_DigestFinal_ex(ctx, res, &mdlen);
  if (rv != 1) {
    return -1;
  }

  return 0;
}
} // namespace

int sha256(uint8_t *res, const StringRef &s) {
  return message_digest(res, EVP_sha256(), s);
}

int sha1(uint8_t *res, const StringRef &s) {
  return message_digest(res, EVP_sha1(), s);
}

bool is_hex_string(const StringRef &s) {
  if (s.size() % 2) {
    return false;
  }

  for (auto c : s) {
    if (!is_hex_digit(c)) {
      return false;
    }
  }

  return true;
}

StringRef decode_hex(BlockAllocator &balloc, const StringRef &s) {
  auto iov = make_byte_ref(balloc, s.size() + 1);
  auto p = decode_hex(iov.base, s);
  *p = '\0';
  return StringRef{iov.base, p};
}

StringRef extract_host(const StringRef &hostport) {
  if (hostport[0] == '[') {
    // assume this is IPv6 numeric address
    auto p = std::find(std::begin(hostport), std::end(hostport), ']');
    if (p == std::end(hostport)) {
      return StringRef{};
    }
    if (p + 1 < std::end(hostport) && *(p + 1) != ':') {
      return StringRef{};
    }
    return StringRef{std::begin(hostport), p + 1};
  }

  auto p = std::find(std::begin(hostport), std::end(hostport), ':');
  if (p == std::begin(hostport)) {
    return StringRef{};
  }
  return StringRef{std::begin(hostport), p};
}

std::pair<StringRef, StringRef> split_hostport(const StringRef &hostport) {
  if (hostport.empty()) {
    return {};
  }
  if (hostport[0] == '[') {
    // assume this is IPv6 numeric address
    auto p = std::find(std::begin(hostport), std::end(hostport), ']');
    if (p == std::end(hostport)) {
      return {};
    }
    if (p + 1 == std::end(hostport)) {
      return {StringRef{std::begin(hostport) + 1, p}, {}};
    }
    if (*(p + 1) != ':' || p + 2 == std::end(hostport)) {
      return {};
    }
    return {StringRef{std::begin(hostport) + 1, p},
            StringRef{p + 2, std::end(hostport)}};
  }

  auto p = std::find(std::begin(hostport), std::end(hostport), ':');
  if (p == std::begin(hostport)) {
    return {};
  }
  if (p == std::end(hostport)) {
    return {StringRef{std::begin(hostport), p}, {}};
  }
  if (p + 1 == std::end(hostport)) {
    return {};
  }

  return {StringRef{std::begin(hostport), p},
          StringRef{p + 1, std::end(hostport)}};
}

std::mt19937 make_mt19937() {
  std::random_device rd;
  return std::mt19937(rd());
}

int daemonize(int nochdir, int noclose) {
#ifdef __APPLE__
  pid_t pid;
  pid = fork();
  if (pid == -1) {
    return -1;
  } else if (pid > 0) {
    _exit(EXIT_SUCCESS);
  }
  if (setsid() == -1) {
    return -1;
  }
  pid = fork();
  if (pid == -1) {
    return -1;
  } else if (pid > 0) {
    _exit(EXIT_SUCCESS);
  }
  if (nochdir == 0) {
    if (chdir("/") == -1) {
      return -1;
    }
  }
  if (noclose == 0) {
    if (freopen("/dev/null", "r", stdin) == nullptr) {
      return -1;
    }
    if (freopen("/dev/null", "w", stdout) == nullptr) {
      return -1;
    }
    if (freopen("/dev/null", "w", stderr) == nullptr) {
      return -1;
    }
  }
  return 0;
#else  // !__APPLE__
  return daemon(nochdir, noclose);
#endif // !__APPLE__
}

StringRef rstrip(BlockAllocator &balloc, const StringRef &s) {
  auto it = std::rbegin(s);
  for (; it != std::rend(s) && (*it == ' ' || *it == '\t'); ++it)
    ;

  auto len = it - std::rbegin(s);
  if (len == 0) {
    return s;
  }

  return make_string_ref(balloc, StringRef{s.c_str(), s.size() - len});
}

#ifdef ENABLE_HTTP3
int msghdr_get_local_addr(Address &dest, msghdr *msg, int family) {
  switch (family) {
  case AF_INET:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
        in_pktinfo pktinfo;
        memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));
        dest.len = sizeof(dest.su.in);
        auto &sa = dest.su.in;
        sa.sin_family = AF_INET;
        sa.sin_addr = pktinfo.ipi_addr;

        return 0;
      }
    }

    return -1;
  case AF_INET6:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
        in6_pktinfo pktinfo;
        memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));
        dest.len = sizeof(dest.su.in6);
        auto &sa = dest.su.in6;
        sa.sin6_family = AF_INET6;
        sa.sin6_addr = pktinfo.ipi6_addr;
        return 0;
      }
    }

    return -1;
  }

  return -1;
}

uint8_t msghdr_get_ecn(msghdr *msg, int family) {
  switch (family) {
  case AF_INET:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IP &&
#  ifdef __APPLE__
          cmsg->cmsg_type == IP_RECVTOS
#  else  // !__APPLE__
          cmsg->cmsg_type == IP_TOS
#  endif // !__APPLE__
          && cmsg->cmsg_len) {
        return *reinterpret_cast<uint8_t *>(CMSG_DATA(cmsg)) & IPTOS_ECN_MASK;
      }
    }

    return 0;
  case AF_INET6:
    for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS &&
          cmsg->cmsg_len) {
        unsigned int tos;

        memcpy(&tos, CMSG_DATA(cmsg), sizeof(tos));

        return tos & IPTOS_ECN_MASK;
      }
    }

    return 0;
  }

  return 0;
}

size_t msghdr_get_udp_gro(msghdr *msg) {
  uint16_t gso_size = 0;

#  ifdef UDP_GRO
  for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
    if (cmsg->cmsg_level == SOL_UDP && cmsg->cmsg_type == UDP_GRO) {
      memcpy(&gso_size, CMSG_DATA(cmsg), sizeof(gso_size));

      break;
    }
  }
#  endif // UDP_GRO

  return gso_size;
}
#endif // ENABLE_HTTP3

} // namespace util

} // namespace nghttp2
