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
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/unicode/flb_wchar.h>
#include <fluent-bit/unicode/flb_conv.h>

/* Helper macros for min/max */
#define max(a, b)  (((a) > (b)) ? (a) : (b))
#define min(a, b)  (((a) < (b)) ? (a) : (b))

/**
 * @brief Helper function to format a byte sequence into a hex string.
 *
 * This function safely formats a sequence of bytes into a human-readable
 * hex string (e.g., "0xde 0xad 0xbe 0xef ..."). It prevents buffer overflows
 * by using snprintf and appends an ellipsis if the source sequence is longer
 * than the display limit.
 *
 * @param buf The output buffer for the hex string.
 * @param buf_size The total size of the output buffer.
 * @param mbstr Pointer to the byte sequence to format.
 * @param str_len The length of the byte sequence.
 */
static void
format_byte_sequence_for_display(char *buf, size_t buf_size, const unsigned char *mbstr, int str_len)
{
    char *ptr = buf;
    const char *end = buf + buf_size;
    const int display_limit = 16;
    int i;

    int bytes_to_show = min(str_len, display_limit);

    for (i = 0; i < bytes_to_show; i++)
    {
        const char *prefix = (i == 0) ? "" : " ";

        int written = snprintf(ptr, end - ptr, "%s0x%02x", prefix, mbstr[i]);

        if (written < 0 || written >= (end - ptr)) {
            break;
        }
        ptr += written;
    }

    if (bytes_to_show < str_len) {
        snprintf(ptr, end - ptr, " ...");
    }
}

/**
 * @brief Reports an invalid multibyte character sequence.
 *
 * This function determines the length of the invalid character and formats
 * it as a hex string for logging, safely handling sequences of any length.
 *
 * @param encoding The character encoding being processed.
 * @param mbstr    Pointer to the start of the invalid character.
 * @param len      The remaining length of the string.
 */
void
flb_report_invalid_encoding(int encoding, const char *mbstr, int len)
{
    char buf[128];
    int char_len = flb_encoding_mblen_or_incomplete(encoding, mbstr, len);

    if (char_len == INT_MAX || char_len > len) {
        char_len = len;
    }

    format_byte_sequence_for_display(buf, sizeof(buf), (const unsigned char *)mbstr, char_len);

    flb_error("[wchar] invalid byte sequence for encoding code \"%d\": %s",
              encoding,
              buf);
}

/**
 * @brief Reports a character that cannot be translated between encodings.
 *
 * This function formats the untranslatable character as a hex string for
 * logging, safely handling sequences of any length.
 *
 * @param src_encoding  The source character encoding.
 * @param dest_encoding The destination character encoding.
 * @param mbstr         Pointer to the start of the untranslatable character.
 * @param len           The remaining length of the string.
 */
void
flb_report_untranslatable_char(int src_encoding, int dest_encoding,
                               const char *mbstr, int len)
{
    char buf[128];

    int char_len = flb_encoding_mblen_or_incomplete(src_encoding, mbstr, len);
    if (char_len == INT_MAX || char_len > len) {
        char_len = len;
    }

    format_byte_sequence_for_display(buf, sizeof(buf), (const unsigned char *)mbstr, char_len);

    flb_error("[wchar] character with byte sequence %s in encoding code \"%d\""
              " has no equivalent in encoding code \"%d\"",
              buf,
              src_encoding,
              dest_encoding);
}

#undef max
#undef min

/*
 * ============================================================================
 * Radix Tree Conversion
 * ============================================================================
 */

/**
 * @brief Convert a character using a conversion radix tree.
 *
 * This function is refactored to use a macro, which avoids duplicating the
 * entire switch statement for both 16-bit and 32-bit table lookups. This
 * makes the logic more concise and easier to maintain.
 *
 * @param rt Pointer to the radix tree.
 * @param l  The length of the input character in bytes (1-4).
 * @param b1 First byte of the character (used for 4-byte sequences).
 * @param b2 Second byte (used for 3 and 4-byte sequences).
 * @param b3 Third byte (used for 2, 3, and 4-byte sequences).
 * @param b4 Fourth byte (used for all lengths).
 * @return The converted character as a 32-bit integer, or 0 on error.
 */
static inline uint32_t
flb_mb_radix_conv(const flb_mb_radix_tree *rt,
                  int l,
                  unsigned char b1,
                  unsigned char b2,
                  unsigned char b3,
                  unsigned char b4)
{
/*
 * This macro contains the core lookup logic. It's called twice, once for
 * the 32-bit table and once for the 16-bit table. This avoids repeating
 * the large switch statement.
 * T = data type (uint32_t or uint16_t)
 * table = the lookup table (rt->chars32 or rt->chars16)
 */
#define DO_RADIX_LOOKUP(T, table)                                             \
    do {                                                                      \
        T idx;                                                                \
        switch (l)                                                            \
        {                                                                     \
            case 4:                                                           \
                if (b1 < rt->b4_1_lower || b1 > rt->b4_1_upper ||              \
                    b2 < rt->b4_2_lower || b2 > rt->b4_2_upper ||              \
                    b3 < rt->b4_3_lower || b3 > rt->b4_3_upper ||              \
                    b4 < rt->b4_4_lower || b4 > rt->b4_4_upper) {              \
                    return 0;                                                \
                }                                                             \
                idx = rt->b4root;                                             \
                idx = table[b1 + idx - rt->b4_1_lower];                       \
                idx = table[b2 + idx - rt->b4_2_lower];                       \
                idx = table[b3 + idx - rt->b4_3_lower];                       \
                return table[b4 + idx - rt->b4_4_lower];                      \
            case 3:                                                           \
                if (b2 < rt->b3_1_lower || b2 > rt->b3_1_upper ||              \
                    b3 < rt->b3_2_lower || b3 > rt->b3_2_upper ||              \
                    b4 < rt->b3_3_lower || b4 > rt->b3_3_upper) {             \
                    return 0;                                                 \
                }                                                            \
                idx = rt->b3root;                                             \
                idx = table[b2 + idx - rt->b3_1_lower];                       \
                idx = table[b3 + idx - rt->b3_2_lower];                       \
                return table[b4 + idx - rt->b3_3_lower];                      \
            case 2:                                                           \
                if (b3 < rt->b2_1_lower || b3 > rt->b2_1_upper ||              \
                    b4 < rt->b2_2_lower || b4 > rt->b2_2_upper) {             \
                    return 0;                                                 \
                }                                                             \
                idx = rt->b2root;                                             \
                idx = table[b3 + idx - rt->b2_1_lower];                       \
                return table[b4 + idx - rt->b2_2_lower];                      \
            case 1:                                                           \
                if (b4 < rt->b1_lower || b4 > rt->b1_upper) {                 \
                                                                              \
                    return 0;                                                 \
                }                                                             \
                return table[b4 + rt->b1root - rt->b1_lower];                 \
        }                                                                     \
    } while (0)

    if (rt->chars32) {
        DO_RADIX_LOOKUP(uint32_t, rt->chars32);
    }
    else {
        DO_RADIX_LOOKUP(uint16_t, rt->chars16);
    }

#undef DO_RADIX_LOOKUP
    return 0; /* Should not happen if length 'l' is valid (1-4) */
}

/*
 * ============================================================================
 * Helper Functions
 * ============================================================================
 */

/**
 * @brief Reads a multi-byte character and packs it into a uint32_t.
 *
 * @param src_ptr Pointer to the source string pointer.
 * @param len The length of the character in bytes.
 * @param[out] b1-b4 Pointers to store the individual bytes.
 * @return The character packed into a uint32_t.
 */
static uint32_t
collect_char_as_int(const unsigned char **src_ptr, int len,
                    unsigned char *b1, unsigned char *b2, unsigned char *b3, unsigned char *b4)
{
    const unsigned char *p = *src_ptr;
    *b1 = *b2 = *b3 = *b4 = 0;

    switch (len)
    {
        case 4: *b1 = *p++; *b2 = *p++; *b3 = *p++; *b4 = *p++; break;
        case 3: *b2 = *p++; *b3 = *p++; *b4 = *p++; break;
        case 2: *b3 = *p++; *b4 = *p++; break;
        case 1: *b4 = *p++; break;
        default:
            flb_error("[conv] unsupported character length %d", len);
            return 0;
    }

    *src_ptr = p;
    return (*b1 << 24 | *b2 << 16 | *b3 << 8 | *b4);
}

/**
 * @brief Writes a uint32_t character code to a multibyte stream.
 * @return A pointer to the position after the written character.
 */
static inline unsigned char *
store_coded_char(unsigned char *dest, uint32_t code)
{
    if (code & 0xff000000) {
        *dest++ = code >> 24;
    }
    if (code & 0x00ff0000) {
        *dest++ = code >> 16;
    }
    if (code & 0x0000ff00) {
        *dest++ = code >> 8;
    }
    if (code & 0x000000ff) {
        *dest++ = code;
    }
    return dest;
}

/**
 * @brief Comparison function for bsearch() on the combined UTF-8 to local map.
 */
static int
compare3(const void *p1, const void *p2)
{
    const uint32_t *key = (const uint32_t *)p1;
    const flb_utf_to_local_combined *entry = (const flb_utf_to_local_combined *)p2;

    if (key[0] != entry->utf1) {
        return key[0] > entry->utf1 ? 1 : -1;
    }
    if (key[1] != entry->utf2) {
        return key[1] > entry->utf2 ? 1 : -1;
    }
    return 0;
}

/**
 * @brief Comparison function for bsearch() on the local to combined UTF-8 map.
 */
static int
compare4(const void *p1, const void *p2)
{
    uint32_t key = *(const uint32_t *)p1;
    uint32_t entry_code = ((const flb_local_to_utf_combined *)p2)->code;
    return (key > entry_code) ? 1 : ((key < entry_code) ? -1 : 0);
}

/**
 * @brief Handles lookahead and conversion for combined UTF-8 characters.
 * @return Number of source bytes consumed (if a conversion was made), otherwise 0.
 */
static int
try_combined_conversion_from_utf8(const unsigned char **utf_ptr, int *len_ptr,
                                  unsigned char **iso_ptr, uint32_t first_char_code,
                                  const flb_utf_to_local_combined *cmap, int cmapsize,
                                  bool no_error)
{
    const unsigned char * const original_pos = *utf_ptr;
    int first_char_len = flb_utf_mblen(original_pos);
    const unsigned char *next_char_pos = NULL;
    int next_char_len = 0;
    unsigned char b1, b2, b3, b4;
    uint32_t second_char_code;
    const flb_utf_to_local_combined *cp = NULL;
    uint32_t combined_key[2] = {0};

    if (*len_ptr <= first_char_len) {
        return 0;
    }

    next_char_pos = original_pos + first_char_len;
    next_char_len = flb_utf_mblen(next_char_pos);

    if (*len_ptr - first_char_len < next_char_len) {
        return 0;
    }

    if (!flb_utf8_islegal(next_char_pos, next_char_len)) {
        if (!no_error) {
            flb_report_invalid_encoding(FLB_UTF8, (const char *)next_char_pos, *len_ptr - first_char_len);
        }
        return -1;
    }

    /* ASCII cannot be part of a combined character */
    if (next_char_len > 1) {
        second_char_code = collect_char_as_int(&next_char_pos, next_char_len, &b1, &b2, &b3, &b4);
        combined_key[0] = first_char_code;
        combined_key[1] = second_char_code;

        cp = bsearch(combined_key, cmap, cmapsize,
                     sizeof(flb_utf_to_local_combined), compare3);

        if (cp) {
            *iso_ptr = store_coded_char(*iso_ptr, cp->code);
            *utf_ptr = next_char_pos;
            *len_ptr -= (first_char_len + next_char_len);
            return first_char_len + next_char_len;
        }
    }

    /* No combined character match found, do nothing. */
    return 0;
}

/*
 * ============================================================================
 * Main Conversion Functions
 * ============================================================================
 */

/**
 * @brief Converts a string from UTF-8 to a specified local encoding.
 * @return The number of bytes WRITTEN to the destination `iso` buffer.
 */
int
flb_convert_to_local_internal(const unsigned char *utf, int len,
                              unsigned char *iso,
                              const flb_mb_radix_tree *map,
                              const flb_utf_to_local_combined *cmap, int cmapsize,
                              utf_local_conversion_func conv_func,
                              int encoding, bool no_error)
{
    const unsigned char *p_utf = utf;
    unsigned char *p_iso = iso;
    const unsigned char * const start_iso = iso;
    int l;
    const unsigned char *char_start_ptr = NULL;
    unsigned char b1, b2, b3, b4;
    uint32_t char_code;
    int consumed;
    bool converted;
    uint32_t result;

    if (!FLB_VALID_ENCODING(encoding))
        flb_error("[conv] invalid encoding number: %d", encoding);

    while (len > 0) {
        char_start_ptr = p_utf;
        if (*p_utf == '\0') {
            break;
        }

        if (!IS_HIGHBIT_SET(*p_utf)) {
            *p_iso++ = *p_utf++;
            len--;
            continue;
        }

        l = flb_utf_mblen(p_utf);
        if (len < l) {
            break;
        }
        if (!flb_utf8_islegal(p_utf, l)) {
            break;
        }

        char_code = collect_char_as_int(&p_utf, l, &b1, &b2, &b3, &b4);

        if (cmap) {
            consumed = try_combined_conversion_from_utf8(&char_start_ptr, &len, &iso, char_code,
                                                         cmap, cmapsize, no_error);
            if (consumed > 0) {
                utf = char_start_ptr;
                continue;
            }
            if (consumed < 0) {
                break;
            }
        }

        converted = false;
        if (map) {
            result = flb_mb_radix_conv(map, l, b1, b2, b3, b4);
            if (result) {
                p_iso = store_coded_char(p_iso, result);
                converted = true;
            }
        }
        if (!converted && conv_func) {
            result = (*conv_func)(char_code);
            if (result) {
                p_iso = store_coded_char(p_iso, result);
                converted = true;
            }
        }

        if (converted) {
            len -= l;
            continue;
        }

        if (!no_error) {
            flb_report_untranslatable_char(FLB_UTF8, encoding, (const char *)char_start_ptr, len);
        }
        break;
    }

    *p_iso = '\0';
    return p_iso - start_iso; /* FIX: Return bytes written to destination */
}

/**
 * @brief Converts a string from a local encoding to UTF-8.
 * @return The number of bytes WRITTEN to the destination `utf` buffer.
 */
int
flb_convert_to_utf_internal(const unsigned char *iso, int len,
                            unsigned char *utf,
                            const flb_mb_radix_tree *map,
                            const flb_local_to_utf_combined *cmap, int cmapsize,
                            utf_local_conversion_func conv_func,
                            int encoding, bool no_error)
{
    const unsigned char *p_iso = iso;
    unsigned char *p_utf = utf;
    const unsigned char * const start_utf = utf;
    unsigned char b1, b2, b3, b4;
    int l;
    uint32_t char_code;
    bool converted = false;
    uint32_t result;
    const flb_local_to_utf_combined *cp;

    if (!FLB_VALID_ENCODING(encoding)) {
        flb_error("[conv] invalid encoding number: %d", encoding);
    }

    while (len > 0) {
        const unsigned char *char_start_ptr = p_iso;
        if (*p_iso == '\0') {
            break;
        }

        if (!IS_HIGHBIT_SET(*p_iso)) {
            *p_utf++ = *p_iso++;
            len--;
            continue;
        }

        l = flb_encoding_verifymbchar(encoding, (const char *)p_iso, len);
        if (l < 0) {
            break;
        }

        char_code = collect_char_as_int(&p_iso, l, &b1, &b2, &b3, &b4);

        converted = false;
        if (map) {
            result = flb_mb_radix_conv(map, l, b1, b2, b3, b4);
            if (result) {
                p_utf = store_coded_char(p_utf, result);
                converted = true;
            }
        }
        if (!converted && cmap) {
            cp = bsearch(&char_code, cmap, cmapsize, sizeof(flb_local_to_utf_combined), compare4);
            if (cp) {
                p_utf = store_coded_char(p_utf, cp->utf1);
                p_utf = store_coded_char(p_utf, cp->utf2);
                converted = true;
            }
        }
        if (!converted && conv_func) {
            result = (*conv_func)(char_code);
            if (result) {
                p_utf = store_coded_char(p_utf, result);
                converted = true;
            }
        }

        if (converted) {
            len -= l;
            continue;
        }

        /* Conversion failed, stop processing */
        if (!no_error) {
            flb_report_untranslatable_char(encoding, FLB_UTF8, (const char *)char_start_ptr, len);
        }
        break;
    }

    *p_utf = '\0';
    return p_utf - start_utf; /* FIX: Return bytes written to destination */
}

struct flb_unicode_converter *flb_conv_select_converter(const char *encoding_name)
{
    struct mk_list converters;
    struct flb_unicode_converter *conv;
    struct mk_list *head;
    int i;

    mk_list_init(&converters);
    mk_list_add(&sjis_converter._head, &converters);
    mk_list_add(&gb18030_converter._head, &converters);
    mk_list_add(&uhc_converter._head, &converters);
    mk_list_add(&big5_converter._head, &converters);
    mk_list_add(&win866_converter._head, &converters);
    mk_list_add(&win874_converter._head, &converters);
    mk_list_add(&win1250_converter._head, &converters);
    mk_list_add(&win1251_converter._head, &converters);
    mk_list_add(&win1252_converter._head, &converters);
    mk_list_add(&win1253_converter._head, &converters);
    mk_list_add(&win1254_converter._head, &converters);
    mk_list_add(&win1255_converter._head, &converters);
    mk_list_add(&win1256_converter._head, &converters);
    mk_list_add(&gbk_converter._head, &converters);

    mk_list_foreach(head, &converters) {
        conv = mk_list_entry(head, struct flb_unicode_converter, _head);
        if (strlen(encoding_name) == strlen(conv->name) &&
            strncasecmp(encoding_name, conv->name, strlen(conv->name)) == 0) {
            return conv;
        }
        else if (conv->aliases != NULL) {
            for (i = 0; conv->aliases[i] != NULL; i++) {
                if (strlen(encoding_name) == strlen(conv->aliases[i]) &&
                    strncasecmp(encoding_name, conv->aliases[i], strlen(conv->aliases[i])) == 0) {
                    return conv;
                }
            }
        }
    }

    return NULL;
}

int flb_conv_supported_encoding(const char *encoding_name)
{
    return flb_conv_select_converter(encoding_name) != NULL;
}

int flb_conv_convert_to_utf8(const char *encoding_name,
                             const unsigned char *src, unsigned char **dest,
                             size_t len, bool no_error)
{
    struct flb_unicode_converter *conv;
    int converted = -1;
    size_t dlen = 0;

    conv = flb_conv_select_converter(encoding_name);
    if (conv == NULL) {
        return FLB_CONV_CONVERTER_NOT_FOUND;
    }

    dlen = len * conv->max_width + 1;
    *dest = flb_calloc(1, dlen);
    if (*dest == NULL) {
        flb_errno();
        return FLB_CONV_ALLOCATION_FAILED;
    }

    converted = conv->cb_to_utf8(src, dest, len, no_error, conv->encoding);
    if (converted <= 0) {
        flb_free(*dest);
        return FLB_CONV_CONVERSION_FAILED;
    }

    return converted;
}

int flb_conv_convert_from_utf8(const char *encoding_name,
                               const unsigned char *src, unsigned char **dest,
                               size_t len, bool no_error)
{
    struct flb_unicode_converter *conv;
    int converted = -1;
    size_t dlen = 0;

    conv = flb_conv_select_converter(encoding_name);
    if (conv == NULL) {
        return FLB_CONV_CONVERTER_NOT_FOUND;
    }

    dlen = len + 1;
    *dest = flb_calloc(1, dlen);
    if (*dest == NULL) {
        flb_errno();
        return FLB_CONV_ALLOCATION_FAILED;
    }

    converted = conv->cb_from_utf8(src, dest, len, no_error, conv->encoding);
    if (converted <= 0) {
        flb_free(*dest);
        *dest = NULL;
        return FLB_CONV_CONVERSION_FAILED;
    }

    return converted;
}
