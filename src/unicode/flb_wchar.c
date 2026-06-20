/*-------------------------------------------------------------------------
 *
 * wchar.c
 *	  Functions for working with multibyte characters in various encodings.
 *
 * Portions Copyright (c) 1998-2025, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  src/common/wchar.c
 *
 *-------------------------------------------------------------------------
 */

#include <limits.h>

#include <fluent-bit/unicode/flb_wchar.h>

/*
 * In today's multibyte encodings other than UTF8, this two-byte sequence
 * ensures flb_encoding_mblen() == 2 && flb_encoding_verifymbstr() == 0.
 *
 * For historical reasons, several verifychar implementations opt to reject
 * this pair specifically.  Byte pair range constraints, in encoding
 * originator documentation, always excluded this pair.  No core conversion
 * could translate it.  However, longstanding verifychar implementations
 * accepted any non-NUL byte.  big5_to_euc_tw and big5_to_mic even translate
 * pairs not valid per encoding originator documentation.  To avoid tightening
 * core or non-core conversions in a security patch, we sought this one pair.
 *
 */
#define NONUTF8_INVALID_BYTE0 (0x8d)
#define NONUTF8_INVALID_BYTE1 (' ')


/*
 * ============================================================================
 * ASCII Encoding Functions
 * ============================================================================
 */

/**
 * @brief Converts an ASCII string to a wide character string.
 * @param from The source ASCII string.
 * @param to   The destination buffer for the wide character string.
 * @param len  The maximum number of bytes to read from the source.
 * @return The number of characters converted.
 */
static int
flb_ascii2wchar_with_len(const unsigned char *from, flb_wchar *to, int len)
{
    int converted_count = 0;

    while (len > 0 && *from != '\0') {
        *to++ = *from++;
        len--;
        converted_count++;
    }
    *to = 0; /* Null-terminate the destination string */
    return converted_count;
}

/**
 * @brief Returns the display width of an ASCII character.
 * @param s Pointer to the character.
 * @return 0 for NUL, -1 for control characters, 1 for printable characters.
 */
static int
flb_ascii_dsplen(const unsigned char *s)
{
    if (*s == '\0') {
        return 0; /* NUL character is zero-width */
    }

    /* C0 control characters and DEL are non-printable */
    if (*s < 0x20 || *s == 0x7f) {
        return -1;
    }

    return 1;
}

/*
 * ============================================================================
 * UTF-8 Encoding Functions
 * ============================================================================
 */

/**
 * @brief Returns the byte length of a UTF-8 character based on its first byte.
 * @param s Pointer to the start of the character.
 * @return The number of bytes in the character (1-4). Returns 1 for invalid
 * or unsupported (5+ byte) lead bytes.
 */
int
flb_utf_mblen(const unsigned char *s)
{
    unsigned char lead_byte = *s;

    /* 0xxxxxxx: 1-byte ASCII */
    if ((lead_byte & 0x80) == 0) {
        return 1;
    }
    /* 110xxxxx: 2-byte sequence */
    else if ((lead_byte & 0xE0) == 0xC0) {
        return 2;
    }
    /* 1110xxxx: 3-byte sequence */
    else if ((lead_byte & 0xF0) == 0xE0) {
        return 3;
    }
    /* 11110xxx: 4-byte sequence */
    else if ((lead_byte & 0xF8) == 0xF0) {
        return 4;
    }
    else {
        /* Invalid or unsupported (5/6-byte) lead byte, treat as a 1-byte error */
        return 1;
    }
}

/*
 * ============================================================================
 * Latin-1 (ISO-8859-1) and Single-Byte Helper Functions
 * ============================================================================
 */

/**
 * @brief Converts a Latin-1 string to a wide character string.
 * @param from The source Latin-1 string.
 * @param to   The destination buffer for the wide character string.
 * @param len  The maximum number of bytes to read from the source.
 * @return The number of characters converted.
 */
static int
flb_latin12wchar_with_len(const unsigned char *from, flb_wchar *to, int len)
{
    /* For Latin-1, this is identical to the ASCII conversion */
    return flb_ascii2wchar_with_len(from, to, len);
}

/**
 * @brief Converts a wide character string to a single-byte encoding by truncation.
 * @param from The source wide character string.
 * @param to   The destination buffer for the single-byte string.
 * @param len  The maximum number of wide characters to read from the source.
 * @return The number of characters converted.
 */
static int
flb_wchar2single_with_len(const flb_wchar *from, unsigned char *to, int len)
{
    int converted_count = 0;

    while (len > 0 && *from != 0) {
        /* Simply truncates the wide character to a single byte */
        *to++ = (unsigned char)(*from++);
        len--;
        converted_count++;
    }
    *to = '\0'; /* Null-terminate the destination string */
    return converted_count;
}

/**
 * @brief Returns the byte length of a Latin-1 character (always 1).
 * @param s Pointer to the character.
 * @return Always returns 1.
 */
static int
flb_latin1_mblen(const unsigned char *s)
{
    return 1;
}

/**
 * @brief Returns the display width of a Latin-1 character.
 * @param s Pointer to the character.
 * @return The display width, determined by ASCII rules.
 */
static int
flb_latin1_dsplen(const unsigned char *s)
{
    /* Display length for Latin-1 is the same as for ASCII */
    return flb_ascii_dsplen(s);
}


/*
 * ============================================================================
 * Generic Verification Functions for Legacy Encodings
 * ============================================================================
 */

/**
 * @brief Generic function to verify a single-byte encoding string.
 * @param s   Pointer to the string.
 * @param len Length of the string.
 * @return The offset of the first null byte, or `len` if none is found.
 */
static int flb_single_byte_verifystr(const unsigned char *s, int len)
{
    const unsigned char *null_position = memchr(s, 0, len);

    if (null_position == NULL) {
        return len; /* The entire string is valid */
    }
    else {
        return null_position - s; /* Return length up to the null byte */
    }
}

/**
 * @brief Generic function to verify a legacy multi-byte string.
 * @param s       Pointer to the string.
 * @param len     Length of the string.
 * @param verify_char_func A function pointer to verify a single character
 * in the specific encoding.
 * @return The number of valid bytes from the start of the string.
 */
static int flb_legacy_verifystr(const unsigned char *s, int len,
                                int (*verify_char_func)(const unsigned char *, int))
{
    const unsigned char *start = s;
    const unsigned char *end = s + len;

    while (s < end)
    {
        /* Fast path for common ASCII characters */
        if (!IS_HIGHBIT_SET(*s))
        {
            if (*s == '\0') {
                break; /* End of string */
            }
            s++;
        }
        else /* Potentially a multi-byte character */
        {
            int char_len = verify_char_func(s, end - s);
            if (char_len == -1) {
                break; /* Invalid character found */
            }
            s += char_len;
        }
    }
    return s - start;
}


/*
 * ============================================================================
 * Shift JIS (SJIS) Encoding Functions
 * ============================================================================
 */

/**
 * @brief Returns the byte length of an SJIS character.
 * @param s Pointer to the character.
 * @return 1 for ASCII or single-byte Kana, 2 for Kanji.
 */
static int
flb_sjis_mblen(const unsigned char *s)
{
    unsigned char c = *s;
    /* Half-width (single-byte) Katakana */
    if (c >= 0xa1 && c <= 0xdf) {
        return 1;
    }
    /* Full-width (two-byte) Kanji or other characters */
    if (IS_HIGHBIT_SET(c)) {
        return 2;
    }
    /* ASCII */
    return 1;
}

/**
 * @brief Returns the display width of an SJIS character.
 * @param s Pointer to the character.
 * @return 1 for single-byte, 2 for two-byte, or ASCII-defined width.
 */
static int
flb_sjis_dsplen(const unsigned char *s)
{
    unsigned char c = *s;
    if (c >= 0xa1 && c <= 0xdf) {
        return 1; /* Half-width Katakana is 1 column wide */
    }
    if (IS_HIGHBIT_SET(c)) {
        return 2; /* Full-width characters are 2 columns wide */
    }
    return flb_ascii_dsplen(s);
}

/**
 * @brief Verifies if a single SJIS character at `s` is valid.
 * @param s   Pointer to the start of the character.
 * @param len Remaining length of the string buffer.
 * @return The character's byte length if valid, otherwise -1.
 */
static int
flb_sjis_verifychar(const unsigned char *s, int len)
{
    int char_len = flb_sjis_mblen(s);

    if (len < char_len)
        return -1; /* Not enough bytes left in string */

    if (char_len == 1)
    {
        /* flb_sjis_mblen already confirmed it's valid single-byte */
        return 1;
    }
    else /* char_len == 2 */
    {
        unsigned char c1 = s[0];
        unsigned char c2 = s[1];

        /* Check for valid lead and tail byte ranges for two-byte characters */
        bool is_head_valid = (c1 >= 0x81 && c1 <= 0x9f) || (c1 >= 0xe0 && c1 <= 0xef);
        bool is_tail_valid = (c2 >= 0x40 && c2 <= 0xfc && c2 != 0x7f);

        if (is_head_valid && is_tail_valid) {
            return 2;
        }
    }
    return -1; /* Invalid sequence */
}

static int
flb_sjis_verifystr(const unsigned char *s, int len)
{
    return flb_legacy_verifystr(s, len, flb_sjis_verifychar);
}


/*
 * ============================================================================
 * Big5, GBK, UHC Encoding Functions (Shared Logic)
 * ============================================================================
 * These encodings share very similar structures for mblen, dsplen,
 * and verification.
 */

/**
 * @brief Returns the byte length for Big5/GBK/UHC (1 for ASCII, 2 otherwise).
 */
static int
flb_cjk_mblen(const unsigned char *s)
{
    return IS_HIGHBIT_SET(*s) ? 2 : 1;
}

/**
 * @brief Returns the display width for Big5/GBK/UHC (2 for multi-byte).
 */
static int
flb_cjk_dsplen(const unsigned char *s)
{
    return IS_HIGHBIT_SET(*s) ? 2 : flb_ascii_dsplen(s);
}

/**
 * @brief Verifies a 2-byte legacy character, checking for embedded nulls.
 * @return Character length (2) if valid, otherwise -1.
 */
static int
flb_2byte_verifychar(const unsigned char *s, int len)
{
    if (len < 2)
        return -1;

    /* Disallow a specific invalid byte sequence used for error marking */
    if (s[0] == NONUTF8_INVALID_BYTE0 && s[1] == NONUTF8_INVALID_BYTE1)
        return -1;

    /* A valid 2-byte char cannot contain a null in the second byte */
    if (s[1] == '\0')
        return -1;

    return 2;
}

/* Big5 */
static int flb_big5_mblen(const unsigned char *s) {
    return flb_cjk_mblen(s);
}
static int flb_big5_dsplen(const unsigned char *s) {
    return flb_cjk_dsplen(s);
}
static int flb_big5_verifychar(const unsigned char *s, int len) {
    return flb_2byte_verifychar(s, len);
}
static int flb_big5_verifystr(const unsigned char *s, int len) {
    return flb_legacy_verifystr(s, len, flb_big5_verifychar);
}

/* GBK */
static int flb_gbk_mblen(const unsigned char *s) {
    return flb_cjk_mblen(s);
}
static int flb_gbk_dsplen(const unsigned char *s) {
    return flb_cjk_dsplen(s);
}
static int flb_gbk_verifychar(const unsigned char *s, int len) {
    return flb_2byte_verifychar(s, len);
}
static int flb_gbk_verifystr(const unsigned char *s, int len) {
    return flb_legacy_verifystr(s, len, flb_gbk_verifychar);
}

/* UHC */
static int flb_uhc_mblen(const unsigned char *s) {
    return flb_cjk_mblen(s);
}
static int flb_uhc_dsplen(const unsigned char *s) {
    return flb_cjk_dsplen(s);
}
static int flb_uhc_verifychar(const unsigned char *s, int len) {
    return flb_2byte_verifychar(s, len);
}
static int flb_uhc_verifystr(const unsigned char *s, int len) {
    return flb_legacy_verifystr(s, len, flb_uhc_verifychar);
}

/*
 * ============================================================================
 * GB18030 Encoding Functions
 * ============================================================================
 */

/**
 * @brief Returns the byte length of a GB18030 character (1, 2, or 4).
 * @param s Pointer to the character.
 * @return The character length in bytes.
 */
static int
flb_gb18030_mblen(const unsigned char *s)
{
    if (!IS_HIGHBIT_SET(*s))
        return 1; /* ASCII */

    /* 4-byte sequences have a second byte in the range 0x30-0x39 */
    if (s[1] >= 0x30 && s[1] <= 0x39)
        return 4;

    /* Otherwise, it's a 2-byte sequence */
    return 2;
}

/**
 * @brief Returns the display width of a GB18030 character.
 * @param s Pointer to the character.
 * @return 2 for multi-byte characters, or ASCII-defined width.
 */
static int
flb_gb18030_dsplen(const unsigned char *s)
{
    return IS_HIGHBIT_SET(*s) ? 2 : flb_ascii_dsplen(s);
}

/**
 * @brief Verifies if a single GB18030 character at `s` is valid.
 * @param s   Pointer to the start of the character.
 * @param len Remaining length of the string buffer.
 * @return The character's byte length if valid, otherwise -1.
 */
static int
flb_gb18030_verifychar(const unsigned char *s, int len)
{
    unsigned char b1 = s[0];

    /* Case 1: ASCII character */
    if (!IS_HIGHBIT_SET(b1)) {
        return 1;
    }

    /* At this point, we know it's a multi-byte character */
    if (len < 2) return -1; /* Must have at least 2 bytes */
    unsigned char b2 = s[1];

    /* Case 2: 4-byte character */
    if (b2 >= 0x30 && b2 <= 0x39) {
        if (len < 4) return -1; /* Not enough bytes for a 4-byte char */
        unsigned char b3 = s[2];
        unsigned char b4 = s[3];

        bool is_b1_valid = (b1 >= 0x81 && b1 <= 0xfe);
        bool is_b3_valid = (b3 >= 0x81 && b3 <= 0xfe);
        bool is_b4_valid = (b4 >= 0x30 && b4 <= 0x39);

        if (is_b1_valid && is_b3_valid && is_b4_valid) {
            return 4;
        }
    }
    /* Case 3: 2-byte character */
    else {
        bool is_b1_valid = (b1 >= 0x81 && b1 <= 0xfe);
        bool is_b2_valid = (b2 >= 0x40 && b2 <= 0xfe && b2 != 0x7f);

        if (is_b1_valid && is_b2_valid) {
            return 2;
        }
    }

    return -1; /* Invalid sequence */
}


static int
flb_gb18030_verifystr(const unsigned char *s, int len)
{
    return flb_legacy_verifystr(s, len, flb_gb18030_verifychar);
}

/* This is a simple verification function for Latin1 */
static int flb_latin1_verifychar(const unsigned char *s, int len)
{
    return 1;
}

static int flb_latin1_verifystr(const unsigned char *s, int len)
{
    return flb_single_byte_verifystr(s, len);
}

/* A helper macro to check if a byte is a valid continuation byte (10xxxxxx) */
#define IS_VALID_CONTINUATION_BYTE(b) ((b) >= 0x80 && (b) <= 0xBF)

/**
 * @brief Checks if a UTF-8 character of a given length is valid.
 *
 * This function is structured for readability, with separate logic
 * for each possible byte length of a UTF-8 character.
 *
 * @param source Pointer to the start of the character.
 * @param length The length of the character in bytes.
 * @return true if the character is a valid UTF-8 sequence, false otherwise.
 */
bool
flb_utf8_islegal(const unsigned char *source, int length)
{
    const unsigned char byte1 = source[0];
    unsigned char byte2, byte3, byte4;

    if (length == 1) {
        /* 1-byte sequences must be standard ASCII (0-127) */
        return byte1 <= 0x7F;
    }
    else if (length == 2) {
        /* 2-byte sequence: 110xxxxx 10xxxxxx */
        byte2 = source[1];
        /* byte1 must be in range C2-DF to avoid overlong forms of ASCII */
        if (byte1 < 0xC2 || byte1 > 0xDF) {
            return false;
        }
        return IS_VALID_CONTINUATION_BYTE(byte2);
    }
    else if (length == 3) {
        /* 3-byte sequence: 1110xxxx 10xxxxxx 10xxxxxx */
        byte2 = source[1];
        byte3 = source[2];

        if (!IS_VALID_CONTINUATION_BYTE(byte2) || !IS_VALID_CONTINUATION_BYTE(byte3)) {
            return false;
        }

        /* Check for overlong forms and surrogates */
        if (byte1 == 0xE0 && byte2 < 0xA0) {
            return false; /* Overlong 2-byte form */
        }
        if (byte1 == 0xED && byte2 > 0x9F) {
            return false; /* UTF-16 surrogate pair */
        }

        return true;
    }
    else if (length == 4) {
        /* 4-byte sequence: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
        byte2 = source[1];
        byte3 = source[2];
        byte4 = source[3];

        if (!IS_VALID_CONTINUATION_BYTE(byte2) ||
            !IS_VALID_CONTINUATION_BYTE(byte3) ||
            !IS_VALID_CONTINUATION_BYTE(byte4)) {
            return false;
        }

        /* Check for overlong forms and values beyond Unicode's range */
        if (byte1 == 0xF0 && byte2 < 0x90) {
            return false; /* Overlong 3-byte form */
        }
        if (byte1 > 0xF4 || (byte1 == 0xF4 && byte2 > 0x8F)) {
            return false; /* Exceeds U+10FFFF */
        }

        return true;
    }

    /* Any other length (0, 5, 6, etc.) is invalid for a single character */
    return false;
}

/**
 * @brief Fills a buffer with a 2-byte sequence representing an invalid character.
 * @param encoding The target encoding.
 * @param dst      The destination buffer (must be at least 2 bytes).
 */
void
flb_encoding_set_invalid(int encoding, char *dst)
{
    /* For UTF-8, 0xC0 is an invalid overlong 2-byte sequence start. */
    /* For others, use a predefined, non-character sequence. */
    dst[0] = (encoding == FLB_UTF8 ? 0xc0 : NONUTF8_INVALID_BYTE0);
    dst[1] = NONUTF8_INVALID_BYTE1;
}

/* A macro to define the set of functions for all single-byte encodings. */
#define FLB_SINGLE_BYTE_ENCODING_FUNCS \
    { flb_latin12wchar_with_len, flb_wchar2single_with_len, flb_latin1_mblen, flb_latin1_dsplen, flb_latin1_verifychar, flb_latin1_verifystr, 1 }

/*
 * The lookup table for encoding functions. Using a macro for the common
 * single-byte encodings makes this table much more compact and maintainable.
 */
const flb_wchar_tbl flb_wchar_table[] = {
    [FLB_STR_ASCII]      = FLB_SINGLE_BYTE_ENCODING_FUNCS,
    [FLB_WIN1256]        = FLB_SINGLE_BYTE_ENCODING_FUNCS,
    [FLB_WIN866]         = FLB_SINGLE_BYTE_ENCODING_FUNCS,
    [FLB_WIN874]         = FLB_SINGLE_BYTE_ENCODING_FUNCS,
    [FLB_WIN1251]        = FLB_SINGLE_BYTE_ENCODING_FUNCS,
    [FLB_WIN1252]        = FLB_SINGLE_BYTE_ENCODING_FUNCS,
    [FLB_WIN1250]        = FLB_SINGLE_BYTE_ENCODING_FUNCS,
    [FLB_WIN1253]        = FLB_SINGLE_BYTE_ENCODING_FUNCS,
    [FLB_WIN1254]        = FLB_SINGLE_BYTE_ENCODING_FUNCS,
    [FLB_WIN1255]        = FLB_SINGLE_BYTE_ENCODING_FUNCS,
    [FLB_WIN1256]        = FLB_SINGLE_BYTE_ENCODING_FUNCS,
    [FLB_SJIS]           = {0, 0, flb_sjis_mblen, flb_sjis_dsplen, flb_sjis_verifychar, flb_sjis_verifystr, 2},
    [FLB_BIG5]           = {0, 0, flb_big5_mblen, flb_big5_dsplen, flb_big5_verifychar, flb_big5_verifystr, 2},
    [FLB_GBK]            = {0, 0, flb_gbk_mblen, flb_gbk_dsplen, flb_gbk_verifychar, flb_gbk_verifystr, 2},
    [FLB_UHC]            = {0, 0, flb_uhc_mblen, flb_uhc_dsplen, flb_uhc_verifychar, flb_uhc_verifystr, 2},
    [FLB_GB18030]        = {0, 0, flb_gb18030_mblen, flb_gb18030_dsplen, flb_gb18030_verifychar, flb_gb18030_verifystr, 4},
};

/**
 * @brief Returns a pointer to the function table for the given encoding.
 * @param encoding The encoding identifier (e.g., FLB_UTF8).
 * @return A pointer to the corresponding flb_wchar_tbl struct. Defaults to
 * ASCII if the encoding is invalid.
 */
static inline const flb_wchar_tbl*
get_wchar_table_entry(int encoding)
{
    if (encoding >= 0 && encoding < (sizeof(flb_wchar_table) / sizeof(flb_wchar_tbl))) {
        return &flb_wchar_table[encoding];
    }
    return &flb_wchar_table[FLB_STR_ASCII]; /* Default to ASCII */
}

/**
 * @brief Returns the byte length of a character in the given encoding.
 */
int
flb_encoding_mblen(int encoding, const char *mbstr)
{
    return get_wchar_table_entry(encoding)->mblen((const unsigned char *) mbstr);
}

/**
 * @brief Returns the byte length of a character, or INT_MAX if not enough bytes remain.
 */
int
flb_encoding_mblen_or_incomplete(int encoding, const char *mbstr, size_t remaining)
{
    /* GB18030 is special: it may need to read two bytes to determine length. */
    bool is_gb18030_multibyte = (encoding == FLB_GB18030 && IS_HIGHBIT_SET(*mbstr));

    if (remaining < 1 || (is_gb18030_multibyte && remaining < 2)) {
        return INT_MAX;
    }

    return flb_encoding_mblen(encoding, mbstr);
}

/**
 * @brief Returns the byte length of a character, bounded by a null terminator.
 */
int
flb_encoding_mblen_bounded(int encoding, const char *mbstr)
{
    /* strnlen is a safe way to get min(actual_length, mblen) */
    return strnlen(mbstr, flb_encoding_mblen(encoding, mbstr));
}

/**
 * @brief Returns the display width of a character in the given encoding.
 */
int
flb_encoding_dsplen(int encoding, const char *mbstr)
{
    return get_wchar_table_entry(encoding)->dsplen((const unsigned char *) mbstr);
}

/**
 * @brief Verifies the first character in a string for the given encoding.
 * @return Character length if valid, -1 if invalid.
 */
int
flb_encoding_verifymbchar(int encoding, const char *mbstr, int len)
{
    return get_wchar_table_entry(encoding)->mbverifychar((const unsigned char *) mbstr, len);
}

/**
 * @brief Verifies an entire string in the given encoding.
 * @return The number of valid bytes from the start of the string.
 */
int
flb_encoding_verifymbstr(int encoding, const char *mbstr, int len)
{
    return get_wchar_table_entry(encoding)->mbverifystr((const unsigned char *) mbstr, len);
}

/**
 * @brief Returns the maximum byte length of a character for the given encoding.
 */
int
flb_encoding_max_length(int encoding)
{
    return get_wchar_table_entry(encoding)->maxmblen;
}
