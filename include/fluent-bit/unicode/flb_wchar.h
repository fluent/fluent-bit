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

#ifndef FLB_WCHAR_H
#define FLB_WCHAR_H

#include <stddef.h>
#include <stdbool.h>

#include <fluent-bit/flb_log.h>

/* msb for char */
#define HIGHBIT                     (0x80)
#define IS_HIGHBIT_SET(ch)      ((unsigned char)(ch) & HIGHBIT)

/*
 * The FLB_wchar type
 */
typedef unsigned int flb_wchar;

/*
 * Maximum byte length of multibyte characters in any backend encoding
 */
#define MAX_MULTIBYTE_CHAR_LEN  4

/*
 * SJIS validation macros
 */
#define ISSJISHEAD(c) (((c) >= 0x81 && (c) <= 0x9f) || ((c) >= 0xe0 && (c) <= 0xfc))
#define ISSJISTAIL(c) (((c) >= 0x40 && (c) <= 0x7e) || ((c) >= 0x80 && (c) <= 0xfc))

#include <fluent-bit/flb_macros.h>

/*
 * Encoding identifiers
 */
typedef enum flb_enc
{
    FLB_STR_ASCII = 0,          /* STR/ASCII */
    FLB_UTF8,                   /* Unicode UTF8 */
    FLB_WIN1256,                    /* windows-1256 */
    FLB_WIN866,                     /* (MS-DOS CP866) */
    FLB_WIN874,                     /* windows-874 */
    FLB_WIN1251,                    /* windows-1251 */
    FLB_WIN1252,                    /* windows-1252 */
    FLB_WIN1250,                    /* windows-1250 */
    FLB_WIN1253,                    /* windows-1253 */
    FLB_WIN1254,                    /* windows-1254 */
    FLB_WIN1255,                    /* windows-1255 */
    FLB_SJIS,                   /* Shift JIS (Windows-932) */
    FLB_BIG5,                   /* Big5 (Windows-950) */
    FLB_GBK,                        /* GBK (Windows-936) */
    FLB_UHC,                        /* UHC (Windows-949) */
    FLB_GB18030,                    /* GB18030 */
    _FLB_LAST_ENCODING_             /* mark only */

} flb_enc;

#define FLB_VALID_ENCODING(_enc) \
        ((_enc) >= 0 && (_enc) < _FLB_LAST_ENCODING_)

/* On FE are possible all encodings */
#define FLB_VALID_FE_ENCODING(_enc)     FLB_VALID_ENCODING(_enc)

/*
 * flb_wchar stuff
 */
typedef int (*mb2wchar_with_len_converter) (const unsigned char *from,
                                            flb_wchar *to,
                                            int len);

typedef int (*wchar2mb_with_len_converter) (const flb_wchar *from,
                                            unsigned char *to,
                                            int len);

typedef int (*mblen_converter) (const unsigned char *mbstr);
typedef int (*mbdisplaylen_converter) (const unsigned char *mbstr);
typedef bool (*mbcharacter_incrementer) (unsigned char *mbstr, int len);
typedef int (*mbchar_verifier) (const unsigned char *mbstr, int len);
typedef int (*mbstr_verifier) (const unsigned char *mbstr, int len);

typedef struct
{
    mb2wchar_with_len_converter mb2wchar_with_len;  /* convert a multibyte
                                                     * string to a wchar */
    wchar2mb_with_len_converter wchar2mb_with_len;  /* convert a wchar string
                                                     * to a multibyte */
    mblen_converter mblen;      /* get byte length of a char */
    mbdisplaylen_converter dsplen;  /* get display width of a char */
    mbchar_verifier mbverifychar;   /* verify multibyte character */
    mbstr_verifier mbverifystr; /* verify multibyte string */
    int             maxmblen;       /* max bytes for a char in this encoding */
} flb_wchar_tbl;

extern const flb_wchar_tbl flb_wchar_table[];

/*
 * Radix tree for character conversion.
 *
 */
typedef struct {
    const uint16_t *chars16;
    const uint32_t *chars32;

    /* Radix tree for 1-byte inputs */
    uint32_t        b1root;
    uint8_t         b1_lower;
    uint8_t         b1_upper;

    /* Radix tree for 2-byte inputs */
    uint32_t        b2root;
    uint8_t         b2_1_lower;
    uint8_t         b2_1_upper;
    uint8_t         b2_2_lower;
    uint8_t         b2_2_upper;

    /* Radix tree for 3-byte inputs */
    uint32_t        b3root;
    uint8_t         b3_1_lower;
    uint8_t         b3_1_upper;
    uint8_t         b3_2_lower;
    uint8_t         b3_2_upper;
    uint8_t         b3_3_lower;
    uint8_t         b3_3_upper;

    /* Radix tree for 4-byte inputs */
    uint32_t        b4root;
    uint8_t         b4_1_lower;
    uint8_t         b4_1_upper;
    uint8_t         b4_2_lower;
    uint8_t         b4_2_upper;
    uint8_t         b4_3_lower;
    uint8_t         b4_3_upper;
    uint8_t         b4_4_lower;
    uint8_t         b4_4_upper;

} flb_mb_radix_tree;

/*
 * UTF-8 to local code conversion map (for combined characters)
 */
typedef struct {
    uint32_t        utf1;
    uint32_t        utf2;
    uint32_t        code;
} flb_utf_to_local_combined;

/*
 * local code to UTF-8 conversion map (for combined characters)
 */
typedef struct {
    uint32_t        code;
    uint32_t        utf1;
    uint32_t        utf2;
} flb_local_to_utf_combined;

/*
 * @brief callback function for algorithmic encoding conversions (in either direction)
 *
 * if function returns zero, it does not know how to convert the code
 */
typedef uint32_t (*utf_local_conversion_func) (uint32_t code);

extern void flb_encoding_set_invalid(int encoding, char *dst);
extern int  flb_encoding_mblen(int encoding, const char *mbstr);
extern int  flb_encoding_mblen_or_incomplete(int encoding, const char *mbstr,
                                            size_t remaining);
extern int  flb_encoding_mblen_bounded(int encoding, const char *mbstr);
extern int  flb_encoding_dsplen(int encoding, const char *mbstr);
extern int  flb_encoding_verifymbchar(int encoding, const char *mbstr, int len);
extern int  flb_encoding_verifymbstr(int encoding, const char *mbstr, int len);
extern int  flb_encoding_max_length(int encoding);

extern bool flb_utf8_islegal(const unsigned char *source, int length);
extern int  flb_utf_mblen(const unsigned char *s);

/* Those of converting functions is not public APIs in flb_conv.h. */
extern int  flb_convert_to_local_internal(const unsigned char *utf, int len,
                                          unsigned char *iso,
                                          const flb_mb_radix_tree *map,
                                          const flb_utf_to_local_combined *cmap, int cmapsize,
                                          utf_local_conversion_func conv_func,
                                          int encoding, bool noError);
extern int  flb_convert_to_utf_internal(const unsigned char *iso, int len,
                                        unsigned char *utf,
                                         const flb_mb_radix_tree *map,
                                        const flb_local_to_utf_combined *cmap, int cmapsize,
                                        utf_local_conversion_func conv_func,
                                        int encoding, bool noError);

extern bool flb_verifymbstr(const char *mbstr, int len, bool noError);
extern bool flb_verify_mbstr(int encoding, const char *mbstr, int len,
                            bool noError);
extern int  flb_verify_mbstr_len(int encoding, const char *mbstr, int len,
                                bool noError);

extern void flb_report_invalid_encoding(int encoding, const char *mbstr, int len);
extern void flb_report_untranslatable_char(int src_encoding, int dest_encoding,
                                           const char *mbstr, int len);

#endif /* FLB_WCHAR_H */
