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

#ifndef FLB_SIMDUTF_CONNECTOR_H
#define FLB_SIMDUTF_CONNECTOR_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef __APPLE__
#include <stdint.h>
#include <stddef.h>
typedef int_least16_t CHAR16_T;
#else
#include <uchar.h>
typedef char16_t CHAR16_T;
#endif

#define FLB_SIMDUTF_CONNECTOR_CONVERT_OK           0
#define FLB_SIMDUTF_CONNECTOR_CONVERT_NOP         -1
#define FLB_SIMDUTF_CONNECTOR_CONVERT_UNSUPPORTED -2
#define FLB_SIMDUTF_CONNECTOR_CONVERT_ERROR       -3

/* Just copy and pasted from amalugamated simdutf.h to remove C++ namespace */
enum flb_simdutf_encoding_type {
    FLB_SIMDUTF_ENCODING_TYPE_UTF8 = 1,       /* BOM 0xef 0xbb 0xbf */
    FLB_SIMDUTF_ENCODING_TYPE_UTF16_LE = 2,   /* BOM 0xff 0xfe */
    FLB_SIMDUTF_ENCODING_TYPE_UTF16_BE = 4,   /* BOM 0xfe 0xff */
    FLB_SIMDUTF_ENCODING_TYPE_UTF32_LE = 8,   /* BOM 0xff 0xfe 0x00 0x00 */
    FLB_SIMDUTF_ENCODING_TYPE_UTF32_BE = 16,  /* BOM 0x00 0x00 0xfe 0xff */
    FLB_SIMDUTF_ENCODING_TYPE_Latin1 = 32,

    FLB_SIMDUTF_ENCODING_TYPE_UNSPECIFIED = 0,
    FLB_SIMDUTF_ENCODING_TYPE_UNICODE_AUTO = 1 << 10, /* Automatically detecting flag*/
};

enum flb_simdutf_error_code {
    FLB_SIMDUTF_ERROR_CODE_SUCCESS = FLB_SIMDUTF_CONNECTOR_CONVERT_OK,
    FLB_SIMDUTF_ERROR_CODE_HEADER_BITS,
    FLB_SIMDUTF_ERROR_CODE_TOO_SHORT,
    FLB_SIMDUTF_ERROR_CODE_TOO_LONG,
    FLB_SIMDUTF_ERROR_CODE_OVERLONG,
    FLB_SIMDUTF_ERROR_CODE_TOO_LARGE,
    FLB_SIMDUTF_ERROR_CODE_SURROGATE,
    FLB_SIMDUTF_ERROR_CODE_INVALID_BASE64_CHARACTER,
    FLB_SIMDUTF_ERROR_CODE_BASE64_INPUT_REMAINDER,
    FLB_SIMDUTF_ERROR_CODE_OUTPUT_BUFFER_TOO_SMALL,
    FLB_SIMDUTF_ERROR_CODE_OTHER,
};

int flb_simdutf_connector_utf8_length_from_utf16le(const CHAR16_T *buf, size_t len);
int flb_simdutf_connector_utf8_length_from_utf16be(const CHAR16_T *buf, size_t len);
int flb_simdutf_connector_utf8_length_from_utf16(const CHAR16_T *buf, size_t len);
int flb_simdutf_connector_validate_utf8(const char *buf, size_t len);
int flb_simdutf_connector_validate_utf16le(const CHAR16_T *buf, size_t len);
int flb_simdutf_connector_validate_utf16be(const CHAR16_T *buf, size_t len);
int flb_simdutf_connector_validate_utf16(const CHAR16_T *buf, size_t len);
int flb_simdutf_connector_convert_utf16le_to_utf8(const CHAR16_T *buf, size_t len,
                                                  char **utf8_output, size_t *out_size);
int flb_simdutf_connector_convert_utf16be_to_utf8(const CHAR16_T *buf, size_t len,
                                                  char **utf8_output, size_t *out_size);
int flb_simdutf_connector_convert_utf16_to_utf8(const CHAR16_T *buf, size_t len,
                                                char **utf8_output, size_t *out_size);
void flb_simdutf_connector_change_endianness_utf16(const CHAR16_T *input, size_t length, CHAR16_T *output);
int flb_simdutf_connector_detect_encodings(const char *input, size_t length);
int flb_simdutf_connector_convert_from_unicode(int preferred_encoding,
                                               const char *input, size_t length,
                                               char **output, size_t *out_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
