/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_UNICODE
#define FLB_UNICODE

#include <stddef.h>
#include <fluent-bit/unicode/flb_wchar.h>
#include <fluent-bit/unicode/flb_conv.h>

/* Supported encoding converters */
enum flb_unicode_generic_enc_type {
    FLB_GENERIC_ASCII          = FLB_STR_ASCII,      /* ASCII */
    FLB_GENERIC_WIN1256        = FLB_WIN1256,        /* windows-1256 */
    FLB_GENERIC_WIN866         = FLB_WIN866,         /* (MS-DOS CP866) */
    FLB_GENERIC_WIN874         = FLB_WIN874,         /* windows-874 */
    FLB_GENERIC_WIN1251        = FLB_WIN1251,        /* windows-1251 */
    FLB_GENERIC_WIN1252        = FLB_WIN1252,        /* windows-1252 */
    FLB_GENERIC_WIN1250        = FLB_WIN1250,        /* windows-1250 */
    FLB_GENERIC_WIN1253        = FLB_WIN1253,        /* windows-1253 */
    FLB_GENERIC_WIN1254        = FLB_WIN1254,        /* windows-1254 */
    FLB_GENERIC_WIN1255        = FLB_WIN1255,        /* windows-1255 */
    FLB_GENERIC_SJIS           = FLB_SJIS,           /* Shift JIS (Windows-932) */
    FLB_GENERIC_BIG5           = FLB_BIG5,           /* Big5 (Windows-950) */
    FLB_GENERIC_GBK            = FLB_GBK,            /* GBK (Windows-936) */
    FLB_GENERIC_UHC            = FLB_UHC,            /* UHC (Windows-949) */
    FLB_GENERIC_GB18030        = FLB_GB18030,        /* GB18030 */
    _FLB_GENERIC_LAST_ENCODING_ /* mark only */
};

#ifdef FLB_HAVE_UNICODE_ENCODER
#include <fluent-bit/simdutf/flb_simdutf_connector.h>

#define FLB_UNICODE_CONVERT_OK          FLB_SIMDUTF_CONNECTOR_CONVERT_OK
#define FLB_UNICODE_CONVERT_NOP         FLB_SIMDUTF_CONNECTOR_CONVERT_NOP
#define FLB_UNICODE_CONVERT_UNSUPPORTED FLB_SIMDUTF_CONNECTOR_CONVERT_UNSUPPORTED
#define FLB_UNICODE_CONVERT_ERROR       FLB_SIMDUTF_CONNECTOR_CONVERT_ERROR

enum flb_unicode_encoding_type {
    FLB_UNICODE_ENCODING_UTF8     = FLB_SIMDUTF_ENCODING_TYPE_UTF8,     /* BOM 0xef 0xbb 0xbf */
    FLB_UNICODE_ENCODING_UTF16_LE = FLB_SIMDUTF_ENCODING_TYPE_UTF16_LE, /* BOM 0xff 0xfe */
    FLB_UNICODE_ENCODING_UTF16_BE = FLB_SIMDUTF_ENCODING_TYPE_UTF16_BE, /* BOM 0xfe 0xff */
    FLB_UNICODE_ENCODING_UTF32_LE = FLB_SIMDUTF_ENCODING_TYPE_UTF32_LE, /* BOM 0xff 0xfe 0x00 0x00 */
    FLB_UNICODE_ENCODING_UTF32_BE = FLB_SIMDUTF_ENCODING_TYPE_UTF32_BE, /* BOM 0x00 0x00 0xfe 0xff */
    FLB_UNICODE_ENCODING_Latin1   = FLB_SIMDUTF_ENCODING_TYPE_Latin1,

    FLB_UNICODE_ENCODING_UNSPECIFIED = FLB_SIMDUTF_ENCODING_TYPE_UNSPECIFIED,
    FLB_UNICODE_ENCODING_AUTO        = FLB_SIMDUTF_ENCODING_TYPE_UNICODE_AUTO, /* Automatically detecting flag*/
};

#else

#define FLB_UNICODE_CONVERT_OK           0
#define FLB_UNICODE_CONVERT_UNSUPPORTED -2

#endif

/* Mainly converting from UTF-16LE/BE to UTF-8 */
int flb_unicode_convert(int preferred_encoding, const char *input, size_t length,
                        char **output, size_t *out_size);
int flb_unicode_validate(const char *record, size_t size);

int flb_unicode_generic_supported_encoding(const char *encoding_name);
int flb_unicode_generic_convert_to_utf8(const char *encoding_name,
                                        const unsigned char *input, unsigned char **output, size_t length);
int flb_unicode_generic_convert_from_utf8(const char *encoding_name,
                                          const unsigned char *input, unsigned char **output, size_t length);

#endif
