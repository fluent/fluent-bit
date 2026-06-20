/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2025-2026 The Fluent Bit Authors
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

#ifndef FLB_CONV_H
#define FLB_CONV_H

#include <stddef.h>
#include <stdbool.h>

#include <monkey/mk_core.h>

#define FLB_CONV_MAX_ALIAS_LENGTH 4

#define FLB_CONV_CONVERT_OK           0
#define FLB_CONV_CONVERTER_NOT_FOUND -1
#define FLB_CONV_ALLOCATION_FAILED   -2
#define FLB_CONV_CONVERSION_FAILED   -3

/* Unspecified encoding type */
#define FLB_CONV_ENCODING_UNSPECIFIED -1

struct flb_unicode_converter {
    const char *name;
    const char *aliases[FLB_CONV_MAX_ALIAS_LENGTH];
    const char *desc;
    int encoding;
    int max_width; /* Maximum width of character from local to UTF-8 */

    /* callbacks */
    int (*cb_to_utf8) (const unsigned char *src, unsigned char **dest,
                       size_t len, bool no_error, int encoding);
    int (*cb_from_utf8) (const unsigned char *src, unsigned char **dest,
                         size_t len, bool no_error, int encoding);

    struct mk_list _head;
};

struct flb_unicode_converter *flb_conv_select_converter(const char *encoding_name);
int flb_conv_supported_encoding(const char *encoding_name);
int flb_conv_select_encoding_type(const char *encoding_name);
int flb_conv_convert_to_utf8(const char *encoding_name,
                             const unsigned char *src, unsigned char **dest,
                             size_t len, bool no_error);
int flb_conv_convert_from_utf8(const char *encoding_name,
                               const unsigned char *src, unsigned char **dest,
                               size_t len, bool no_error);

extern struct flb_unicode_converter sjis_converter;
extern struct flb_unicode_converter gb18030_converter;
extern struct flb_unicode_converter uhc_converter;
extern struct flb_unicode_converter big5_converter;
extern struct flb_unicode_converter win866_converter;
extern struct flb_unicode_converter win874_converter;
extern struct flb_unicode_converter win1250_converter;
extern struct flb_unicode_converter win1251_converter;
extern struct flb_unicode_converter win1252_converter;
extern struct flb_unicode_converter win1253_converter;
extern struct flb_unicode_converter win1254_converter;
extern struct flb_unicode_converter win1255_converter;
extern struct flb_unicode_converter win1256_converter;
extern struct flb_unicode_converter gbk_converter;

#endif
