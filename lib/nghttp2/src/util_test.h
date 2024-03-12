/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
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
#ifndef UTIL_TEST_H
#define UTIL_TEST_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif // HAVE_CONFIG_H

namespace shrpx {

void test_util_streq(void);
void test_util_strieq(void);
void test_util_inp_strlower(void);
void test_util_to_base64(void);
void test_util_to_token68(void);
void test_util_percent_encode_token(void);
void test_util_percent_decode(void);
void test_util_quote_string(void);
void test_util_utox(void);
void test_util_http_date(void);
void test_util_select_h2(void);
void test_util_ipv6_numeric_addr(void);
void test_util_utos(void);
void test_util_make_string_ref_uint(void);
void test_util_utos_unit(void);
void test_util_utos_funit(void);
void test_util_parse_uint_with_unit(void);
void test_util_parse_uint(void);
void test_util_parse_duration_with_unit(void);
void test_util_duration_str(void);
void test_util_format_duration(void);
void test_util_starts_with(void);
void test_util_ends_with(void);
void test_util_parse_http_date(void);
void test_util_localtime_date(void);
void test_util_get_uint64(void);
void test_util_parse_config_str_list(void);
void test_util_make_http_hostport(void);
void test_util_make_hostport(void);
void test_util_strifind(void);
void test_util_random_alpha_digit(void);
void test_util_format_hex(void);
void test_util_is_hex_string(void);
void test_util_decode_hex(void);
void test_util_extract_host(void);
void test_util_split_hostport(void);
void test_util_split_str(void);
void test_util_rstrip(void);

} // namespace shrpx

#endif // UTIL_TEST_H
