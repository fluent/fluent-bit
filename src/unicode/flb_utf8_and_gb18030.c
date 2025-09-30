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


#include <fluent-bit/unicode/flb_wchar.h>
#include <fluent-bit/unicode/flb_conv.h>
#include "maps/gb18030_to_utf8.map"
#include "maps/utf8_to_gb18030.map"

/*
 * Convert 4-byte GB18030 characters to and from a linear code space
 *
 * The first and third bytes can range from 0x81 to 0xfe (126 values),
 * while the second and fourth bytes can range from 0x30 to 0x39 (10 values).
 */
static inline uint32_t
flb_gb_linear(uint32_t gb)
{
    uint32_t    b0 = (gb & 0xff000000) >> 24;
    uint32_t    b1 = (gb & 0x00ff0000) >> 16;
    uint32_t    b2 = (gb & 0x0000ff00) >> 8;
    uint32_t    b3 = (gb & 0x000000ff);

    return b0 * 12600 + b1 * 1260 + b2 * 10 + b3 -
        (0x81 * 12600 + 0x30 * 1260 + 0x81 * 10 + 0x30);
}

static inline uint32_t
flb_gb_unlinear(uint32_t lin)
{
    uint32_t    r0 = 0x81 + lin / 12600;
    uint32_t    r1 = 0x30 + (lin / 1260) % 10;
    uint32_t    r2 = 0x81 + (lin / 10) % 126;
    uint32_t    r3 = 0x30 + lin % 10;

    return (r0 << 24) | (r1 << 16) | (r2 << 8) | r3;
}

/*
 * Convert word-formatted UTF8 to and from Unicode code points
 *
 * Probably this should be somewhere else ...
 */
static inline uint32_t
flb_unicode_to_utf8word(uint32_t c)
{
    uint32_t        word;

    if (c <= 0x7F)
    {
        word = c;
    }
    else if (c <= 0x7FF)
    {
        word = (0xC0 | ((c >> 6) & 0x1F)) << 8;
        word |= 0x80 | (c & 0x3F);
    }
    else if (c <= 0xFFFF)
    {
        word = (0xE0 | ((c >> 12) & 0x0F)) << 16;
        word |= (0x80 | ((c >> 6) & 0x3F)) << 8;
        word |= 0x80 | (c & 0x3F);
    }
    else
    {
        word = (0xF0 | ((c >> 18) & 0x07)) << 24;
        word |= (0x80 | ((c >> 12) & 0x3F)) << 16;
        word |= (0x80 | ((c >> 6) & 0x3F)) << 8;
        word |= 0x80 | (c & 0x3F);
    }

    return word;
}

static inline uint32_t
flb_utf8word_to_unicode(uint32_t c)
{
    uint32_t        ucs;

    if (c <= 0x7F)
    {
        ucs = c;
    }
    else if (c <= 0xFFFF)
    {
        ucs = ((c >> 8) & 0x1F) << 6;
        ucs |= c & 0x3F;
    }
    else if (c <= 0xFFFFFF)
    {
        ucs = ((c >> 16) & 0x0F) << 12;
        ucs |= ((c >> 8) & 0x3F) << 6;
        ucs |= c & 0x3F;
    }
    else
    {
        ucs = ((c >> 24) & 0x07) << 18;
        ucs |= ((c >> 16) & 0x3F) << 12;
        ucs |= ((c >> 8) & 0x3F) << 6;
        ucs |= c & 0x3F;
    }

    return ucs;
}

/*
 * Perform mapping of GB18030 ranges to UTF8
 *
 * The ranges we need to convert are specified in gb-18030-2000.xml.
 * All are ranges of 4-byte GB18030 codes.
 */
static uint32_t
flb_conv_18030_to_utf8(uint32_t code)
{
#define conv18030(minunicode, mincode, maxcode) \
    if (code >= mincode && code <= maxcode) \
        return flb_unicode_to_utf8word(flb_gb_linear(code) - flb_gb_linear(mincode) + minunicode)

    conv18030(0x0452, 0x8130D330, 0x8136A531);
    conv18030(0x2643, 0x8137A839, 0x8138FD38);
    conv18030(0x361B, 0x8230A633, 0x8230F237);
    conv18030(0x3CE1, 0x8231D438, 0x8232AF32);
    conv18030(0x4160, 0x8232C937, 0x8232F837);
    conv18030(0x44D7, 0x8233A339, 0x8233C931);
    conv18030(0x478E, 0x8233E838, 0x82349638);
    conv18030(0x49B8, 0x8234A131, 0x8234E733);
    conv18030(0x9FA6, 0x82358F33, 0x8336C738);
    conv18030(0xE865, 0x8336D030, 0x84308534);
    conv18030(0xFA2A, 0x84309C38, 0x84318537);
    conv18030(0xFFE6, 0x8431A234, 0x8431A439);
    conv18030(0x10000, 0x90308130, 0xE3329A35);
    /* No mapping exists */
    return 0;
}

/*
 * Perform mapping of UTF8 ranges to GB18030
 */
static uint32_t
flb_conv_utf8_to_18030(uint32_t code)
{
    uint32_t        ucs = flb_utf8word_to_unicode(code);

#define convutf8(minunicode, maxunicode, mincode) \
    if (ucs >= minunicode && ucs <= maxunicode) \
        return flb_gb_unlinear(ucs - minunicode + flb_gb_linear(mincode))

    convutf8(0x0452, 0x200F, 0x8130D330);
    convutf8(0x2643, 0x2E80, 0x8137A839);
    convutf8(0x361B, 0x3917, 0x8230A633);
    convutf8(0x3CE1, 0x4055, 0x8231D438);
    convutf8(0x4160, 0x4336, 0x8232C937);
    convutf8(0x44D7, 0x464B, 0x8233A339);
    convutf8(0x478E, 0x4946, 0x8233E838);
    convutf8(0x49B8, 0x4C76, 0x8234A131);
    convutf8(0x9FA6, 0xD7FF, 0x82358F33);
    convutf8(0xE865, 0xF92B, 0x8336D030);
    convutf8(0xFA2A, 0xFE2F, 0x84309C38);
    convutf8(0xFFE6, 0xFFFF, 0x8431A234);
    convutf8(0x10000, 0x10FFFF, 0x90308130);
    /* No mapping exists */
    return 0;
}

/*
 * Returns the number of bytes successfully converted.
 * ----------
 */
int
flb_gb18030_to_utf8(const unsigned char *src, unsigned char **dest,
                    size_t len, bool no_error, int encoding)
{
    int converted = -1;

    converted = flb_convert_to_utf_internal(src, len, *dest,
                                            &gb18030_to_unicode_tree,
                                            NULL, 0,
                                            flb_conv_18030_to_utf8,
                                            FLB_GB18030,
                                            no_error);

    return converted;
}

int
flb_utf8_to_gb18030(const unsigned char *src, unsigned char **dest,
                    size_t len, bool no_error, int encoding)
{
    int converted = -1;

    converted = flb_convert_to_local_internal(src, len, *dest,
                                              &gb18030_from_unicode_tree,
                                              NULL, 0,
                                              flb_conv_utf8_to_18030,
                                              FLB_GB18030,
                                              no_error);

    return converted;
}

struct flb_unicode_converter gb18030_converter = {
    .name = "GB18030",
    .aliases = {NULL},
    .desc = "GB18030 encoding converter",
    .encoding = FLB_GB18030,
    .max_width = 4,
    .cb_to_utf8 = flb_gb18030_to_utf8,
    .cb_from_utf8 = flb_utf8_to_gb18030,
};
