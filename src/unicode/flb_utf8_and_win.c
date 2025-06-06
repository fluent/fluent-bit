/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2025 The Fluent Bit Authors
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

#include <fluent-bit/flb_log.h>
#include <fluent-bit/unicode/flb_wchar.h>
#include <fluent-bit/unicode/flb_conv.h>
#include "maps/utf8_to_win1250.map"
#include "maps/utf8_to_win1251.map"
#include "maps/utf8_to_win1252.map"
#include "maps/utf8_to_win1253.map"
#include "maps/utf8_to_win1254.map"
#include "maps/utf8_to_win1255.map"
#include "maps/utf8_to_win1256.map"
#include "maps/utf8_to_win866.map"
#include "maps/utf8_to_win874.map"
#include "maps/win1250_to_utf8.map"
#include "maps/win1251_to_utf8.map"
#include "maps/win1252_to_utf8.map"
#include "maps/win1253_to_utf8.map"
#include "maps/win1254_to_utf8.map"
#include "maps/win1255_to_utf8.map"
#include "maps/win1256_to_utf8.map"
#include "maps/win866_to_utf8.map"
#include "maps/win874_to_utf8.map"

/* ----------
 * Returns the number of bytes successfully converted.
 * ----------
 */

typedef struct
{
    flb_enc         encoding;
    const flb_mb_radix_tree *map1;  /* to UTF8 map name */
    const flb_mb_radix_tree *map2;  /* from UTF8 map name */
} flb_conv_map;

static const flb_conv_map maps[] = {
    {FLB_WIN866, &win866_to_unicode_tree, &win866_from_unicode_tree},
    {FLB_WIN874, &win874_to_unicode_tree, &win874_from_unicode_tree},
    {FLB_WIN1250, &win1250_to_unicode_tree, &win1250_from_unicode_tree},
    {FLB_WIN1251, &win1251_to_unicode_tree, &win1251_from_unicode_tree},
    {FLB_WIN1252, &win1252_to_unicode_tree, &win1252_from_unicode_tree},
    {FLB_WIN1253, &win1253_to_unicode_tree, &win1253_from_unicode_tree},
    {FLB_WIN1254, &win1254_to_unicode_tree, &win1254_from_unicode_tree},
    {FLB_WIN1255, &win1255_to_unicode_tree, &win1255_from_unicode_tree},
    {FLB_WIN1256, &win1256_to_unicode_tree, &win1256_from_unicode_tree},
};

int
flb_win_to_utf8(const unsigned char *src, unsigned char **dest,
                size_t len, bool no_error, int encoding)
{
    int converted = -1;
    int i;

    for (i = 0; i < sizeof(maps)/sizeof(maps[0]); i++) {
        if (encoding == maps[i].encoding) {
            converted = flb_convert_to_utf_internal(src, len, *dest,
                                                    maps[i].map1,
                                                    NULL, 0,
                                                    NULL,
                                                    encoding,
                                                    no_error);
            return converted;
        }
    }

    flb_error("[utf8_and_win] unexpected encoding ID %d for WIN character sets",
              encoding);

    return converted;
}

int
flb_utf8_to_win(const unsigned char *src, unsigned char **dest,
                size_t len, bool no_error, int encoding)
{
    int converted = -1;
    int i;

    for (i = 0; i < sizeof(maps)/sizeof(maps[0]); i++) {
        if (encoding == maps[i].encoding) {
            converted = flb_convert_to_local_internal(src, len, *dest,
                                                      maps[i].map2,
                                                      NULL, 0,
                                                      NULL,
                                                      encoding,
                                                      no_error);
            return converted;
        }
    }

    flb_error("[utf8_and_win] unexpected encoding ID %d for WIN character sets",
              encoding);

    return converted;
}

struct flb_unicode_converter win866_converter = {
    .name = "Win866",
    .aliases = {"CP866", NULL},
    .desc = "Windows code pages' converters",
    .encoding = FLB_WIN866,
    .max_width = 2,
    .cb_to_utf8 = flb_win_to_utf8,
    .cb_from_utf8 = flb_utf8_to_win,
};

struct flb_unicode_converter win874_converter = {
    .name = "Win874",
    .aliases = {"CP874", NULL},
    .desc = "Windows code pages' converters",
    .encoding = FLB_WIN874,
    .max_width = 3,
    .cb_to_utf8 = flb_win_to_utf8,
    .cb_from_utf8 = flb_utf8_to_win,
};

struct flb_unicode_converter win1250_converter = {
    .name = "Win1250",
    .aliases = {"CP1250", NULL},
    .desc = "Windows code pages' converters",
    .encoding = FLB_WIN1250,
    .max_width = 3,
    .cb_to_utf8 = flb_win_to_utf8,
    .cb_from_utf8 = flb_utf8_to_win,
};

struct flb_unicode_converter win1251_converter = {
    .name = "Win1251",
    .aliases = {"CP1251", NULL},
    .desc = "Windows code pages' converters",
    .encoding = FLB_WIN1251,
    .max_width = 3,
    .cb_to_utf8 = flb_win_to_utf8,
    .cb_from_utf8 = flb_utf8_to_win,
};

struct flb_unicode_converter win1252_converter = {
    .name = "Win1252",
    .aliases = {"CP1252", NULL},
    .desc = "Windows code pages' converters",
    .encoding = FLB_WIN1252,
    .max_width = 3,
    .cb_to_utf8 = flb_win_to_utf8,
    .cb_from_utf8 = flb_utf8_to_win,
};

struct flb_unicode_converter win1253_converter = {
    .name = "Win1253",
    .aliases = {"CP1253", NULL},
    .desc = "Windows code pages' converters",
    .encoding = FLB_WIN1253,
    .max_width = 3,
    .cb_to_utf8 = flb_win_to_utf8,
    .cb_from_utf8 = flb_utf8_to_win,
};

struct flb_unicode_converter win1254_converter = {
    .name = "Win1254",
    .aliases = {"CP1254", NULL},
    .desc = "Windows code pages' converters",
    .encoding = FLB_WIN1254,
    .max_width = 3,
    .cb_to_utf8 = flb_win_to_utf8,
    .cb_from_utf8 = flb_utf8_to_win,
};

struct flb_unicode_converter win1255_converter = {
    .name = "Win1255",
    .aliases = {"CP1255", NULL},
    .desc = "Windows code pages' converters",
    .encoding = FLB_WIN1255,
    .max_width = 3,
    .cb_to_utf8 = flb_win_to_utf8,
    .cb_from_utf8 = flb_utf8_to_win,
};

struct flb_unicode_converter win1256_converter = {
    .name = "Win1256",
    .aliases = {"CP1256", NULL},
    .desc = "Windows code pages' converters",
    .encoding = FLB_WIN1256,
    .max_width = 3,
    .cb_to_utf8 = flb_win_to_utf8,
    .cb_from_utf8 = flb_utf8_to_win,
};
