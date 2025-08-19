// This file is used to test string processing and Unicode encoding validation.
// This file must be compiled with UTF-8 encoding.

#include "yyjson.h"
#include "yy_test_utils.h"



/// A string value with length.
typedef struct {
    const char *str;
    usize len;
} string_val;

/// A string set for different flags.
typedef struct {
    string_val str;         // raw string
    string_val esc_non;     // json string
    string_val esc_sla;     // json string escape slashes
    string_val esc_uni;     // json string escape unicode
    string_val esc_all;     // json string escape unicode and slashes
    bool invalid_unicode;   // flag `ALLOW_INVALID_UNICODE`
} string_set;



/*==============================================================================
 * MARK: - Standard Reader/Writer
 *============================================================================*/

/// Validate roundtrip: `write(read(str)) == str`.
static void validate_roundtrip(char *str, usize len, yyjson_write_flag flg) {
#if !YYJSON_DISABLE_READER && !YYJSON_DISABLE_WRITER
#if YYJSON_DISABLE_UTF8_VALIDATION
    if (str && !yy_str_is_utf8(str, len)) return;
#endif
    
    yyjson_doc *doc;
    usize ret_len = 0;
    char *ret;
    
    // str == write(read(str))
    doc = yyjson_read(str, len, YYJSON_READ_ALLOW_INVALID_UNICODE);
    ret = yyjson_write(doc, flg, &ret_len);
    yy_assert(ret);
    yy_assert(ret_len == len);
    yy_assert(memcmp(ret, str, len) == 0);
    free(ret);
    yyjson_doc_free(doc);
    
    // test no read/write flag
    doc = yyjson_read(str, len, 0);
    ret = yyjson_write(doc, flg, NULL);
    free(ret);
    yyjson_doc_free(doc);
    
    // test no write flag
    doc = yyjson_read(str, len, YYJSON_READ_ALLOW_INVALID_UNICODE);
    ret = yyjson_write(doc, 0, NULL);
    free(ret);
    yyjson_doc_free(doc);
    
    // test pretty flag
    doc = yyjson_read(str, len, YYJSON_READ_ALLOW_INVALID_UNICODE);
    ret = yyjson_write(doc, YYJSON_WRITE_PRETTY, NULL);
    free(ret);
    yyjson_doc_free(doc);
#endif
}

/// Validate read: `read(src) == dst`.
static void validate_str_read(string_val *src, string_val *dst, yyjson_read_flag flg) {
#if !YYJSON_DISABLE_READER
#if YYJSON_DISABLE_UTF8_VALIDATION
    if (src->str && !yy_str_is_utf8(src->str, src->len)) return;
#endif
    
    string_val empty = { NULL, 0 };
    if (!src || !src->str) return;
    if (!dst) dst = &empty;
    
    usize buf_len = src->len + 2;
    char *buf = malloc(buf_len);
    buf[0] = '"';
    memcpy(buf + 1, src->str, src->len);
    buf[buf_len - 1] = '"';
    
    yyjson_doc *doc = yyjson_read(buf, buf_len, flg);
    if (dst->str) {
        yy_assertf(doc,
                   "read fail,\ninput: \"%s\" len:%u\nexpect:\"%s\" len:%u\noutput:NULL doc\n",
                   src->str, (u32)src->len, dst->str, (u32)dst->len);
        yyjson_val *val = yyjson_doc_get_root(doc);
        yy_assertf(yyjson_is_str(val),
                   "read fail,\ninput: \"%s\" len:%u\nexpect:\"%s\" len:%u\noutput:root not string\n",
                   src->str, (u32)src->len, dst->str, (u32)dst->len);
        yy_assertf(yyjson_equals_strn(val, dst->str, dst->len),
                   "read fail,\ninput: \"%s\" len:%u\nexpect:\"%s\" len:%u\noutput:\"%s\" len:%u\n",
                   src->str, (u32)src->len, dst->str, (u32)dst->len,
                   yyjson_get_str(val), (u32)yyjson_get_len(val));
    } else {
        yy_assertf(!doc,
                   "input string should be rejected by reader, but accepted: \"%s\"\n",
                   src->str);
    }
    free(buf);
    yyjson_doc_free(doc);
    
#endif
}

/// Validate write: `write(src) == dst`.
static void validate_str_write(string_val *src, string_val *dst, yyjson_write_flag flg) {
#if !YYJSON_DISABLE_WRITER
#if YYJSON_DISABLE_UTF8_VALIDATION
    if (src->str && !yy_str_is_utf8(src->str, src->len)) return;
#endif
    
    string_val empty = { NULL, 0 };
    if (!src || !src->str) return;
    if (!dst) dst = &empty;
    
    char *buf = src->len ? malloc(src->len) : (char *)1;
    memcpy(buf, src->str, src->len);
    
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *val = yyjson_mut_strn(doc, buf, src->len);
    yyjson_mut_doc_set_root(doc, val);
    
    // single value
    usize ret_len = 0;
    char *ret = yyjson_mut_write_opts(doc, flg, NULL, &ret_len, NULL);
    if (dst->str) {
        yy_assertf(ret,
                   "write fail,\ninput: \"%s\" len:%u\nexpect:\"%s\" len:%u\noutput:NULL\n",
                   src->str, (u32)src->len, dst->str, (u32)dst->len);
        yy_assertf((ret_len == dst->len + 2) && (memcmp(ret + 1, dst->str, dst->len) == 0),
                   "write fail,\ninput: \"%s\" len:%u\nexpect:\"%s\" len:%u\noutput:%s len:%u\n",
                   src->str, (u32)src->len, dst->str, (u32)dst->len, ret, (u32)ret_len - 2);
        validate_roundtrip(ret, ret_len, flg);
        free((void *)ret);
    } else {
        yy_assertf(!ret,
                   "input string should be rejected by writer, but accepted: \"%s\"\n",
                   src->str);
    }
    
    // string in array (minify)
    yyjson_mut_val *arr = yyjson_mut_arr(doc);
    yyjson_mut_arr_append(arr, val);
    yyjson_mut_doc_set_root(doc, arr);
    ret = yyjson_mut_write_opts(doc, flg, NULL, &ret_len, NULL);
    if (dst->str) {
        yy_assertf(ret,
                   "write fail,\ninput: \"%s\" len:%u\nexpect:\"%s\" len:%u\noutput:NULL\n",
                   src->str, (u32)src->len, dst->str, (u32)dst->len);
        yy_assertf((ret_len == dst->len + 4) && (memcmp(ret + 2, dst->str, dst->len) == 0),
                   "write fail,\ninput: \"%s\" len:%u\nexpect:\"%s\" len:%u\noutput:%s len:%u\n",
                   src->str, (u32)src->len, dst->str, (u32)dst->len, ret, (u32)ret_len - 4);
        validate_roundtrip(ret, ret_len, flg);
        free((void *)ret);
    } else {
        yy_assertf(!ret,
                   "input string should be rejected by writer, but accepted: \"%s\"\n",
                   src->str);
    }
    
    // string in array (pretty)
    ret = yyjson_mut_write_opts(doc, flg | YYJSON_WRITE_PRETTY, NULL, &ret_len, NULL);
    if (dst->str) {
        yy_assertf(ret,
                   "write fail,\ninput: \"%s\" len:%u\nexpect:\"%s\" len:%u\noutput:NULL\n",
                   src->str, (u32)src->len, dst->str, (u32)dst->len);
        yy_assertf((ret_len == dst->len + 10) && (memcmp(ret + 7, dst->str, dst->len) == 0),
                   "write fail,\ninput: \"%s\" len:%u\nexpect:\"%s\" len:%u\noutput:%s len:%u\n",
                   src->str, (u32)src->len, dst->str, (u32)dst->len, ret, (u32)ret_len - 10);
        validate_roundtrip(ret, ret_len, flg | YYJSON_WRITE_PRETTY);
        free((void *)ret);
    } else {
        yy_assertf(!ret,
                   "input string should be rejected by writer, but accepted: \"%s\"\n",
                   src->str);
    }
    
    
    yyjson_mut_doc_free(doc);
    if (src->len) free(buf);
#endif
}

/// Validate string read:
///     `read(esc_non) -> str`
///     `read(esc_sla) -> str`
///     `read(esc_uni) -> str`
///     `read(esc_all) -> str`
static void validate_read(string_set set) {
    yyjson_read_flag flg = YYJSON_READ_ALLOW_INVALID_UNICODE;
    
    if (set.invalid_unicode) {
        validate_str_read(&set.esc_non, NULL, 0);
        validate_str_read(&set.esc_sla, NULL, 0);
#if YYJSON_DISABLE_NON_STANDARD
        validate_str_read(&set.esc_non, NULL, flg);
        validate_str_read(&set.esc_sla, NULL, flg);
#else
        validate_str_read(&set.esc_non, &set.str, flg);
        validate_str_read(&set.esc_sla, &set.str, flg);
#endif
        validate_str_read(&set.esc_uni, &set.str, flg);
        validate_str_read(&set.esc_all, &set.str, flg);
    } else {
        validate_str_read(&set.esc_non, &set.str, 0);
        validate_str_read(&set.esc_sla, &set.str, 0);
        validate_str_read(&set.esc_uni, &set.str, 0);
        validate_str_read(&set.esc_all, &set.str, 0);
        
        validate_str_read(&set.esc_non, &set.str, flg);
        validate_str_read(&set.esc_sla, &set.str, flg);
        validate_str_read(&set.esc_uni, &set.str, flg);
        validate_str_read(&set.esc_all, &set.str, flg);
    }
}

/// Validate string encode:
///     `write(str) -> esc_non (NOFLAG)`
///     `write(str) -> esc_sla (ESCAPE_SLASHES)`
///     `write(str) -> esc_uni (ESCAPE_UNICODE)`
///     `write(str) -> esc_all (ESCAPE_SLASHES | ESCAPE_UNICODE)`
static void validate_write(string_set set) {
    yyjson_write_flag flg_non = YYJSON_WRITE_NOFLAG;
    yyjson_write_flag flg_sla = YYJSON_WRITE_ESCAPE_SLASHES;
    yyjson_write_flag flg_uni = YYJSON_WRITE_ESCAPE_UNICODE;
    yyjson_write_flag flg_all = YYJSON_WRITE_ESCAPE_UNICODE | YYJSON_WRITE_ESCAPE_SLASHES;
    yyjson_write_flag flg_inv = YYJSON_WRITE_ALLOW_INVALID_UNICODE;
    
    if (set.invalid_unicode) {
        validate_str_write(&set.str, NULL, flg_non);
        validate_str_write(&set.str, NULL, flg_sla);
        validate_str_write(&set.str, NULL, flg_uni);
        validate_str_write(&set.str, NULL, flg_all);
#if YYJSON_DISABLE_NON_STANDARD
        validate_str_write(&set.str, NULL, flg_non | flg_inv);
        validate_str_write(&set.str, NULL, flg_sla | flg_inv);
        validate_str_write(&set.str, NULL, flg_uni | flg_inv);
        validate_str_write(&set.str, NULL, flg_all | flg_inv);
#else
        validate_str_write(&set.str, &set.esc_non, flg_non | flg_inv);
        validate_str_write(&set.str, &set.esc_sla, flg_sla | flg_inv);
        validate_str_write(&set.str, &set.esc_uni, flg_uni | flg_inv);
        validate_str_write(&set.str, &set.esc_all, flg_all | flg_inv);
#endif
    } else {
        validate_str_write(&set.str, &set.esc_non, flg_non);
        validate_str_write(&set.str, &set.esc_sla, flg_sla);
        validate_str_write(&set.str, &set.esc_uni, flg_uni);
        validate_str_write(&set.str, &set.esc_all, flg_all);
        
        validate_str_write(&set.str, &set.esc_non, flg_non | flg_inv);
        validate_str_write(&set.str, &set.esc_sla, flg_sla | flg_inv);
        validate_str_write(&set.str, &set.esc_uni, flg_uni | flg_inv);
        validate_str_write(&set.str, &set.esc_all, flg_all | flg_inv);
    }
}

static void validate_read_write(string_set set) {
    validate_read(set);
    validate_write(set);
}

static void test_read_write(void) {
    validate_read_write((string_set) {
        { "", 0 },
        { "", 0 },
        { "", 0 },
        { "", 0 },
        { "", 0 },
    });
    
    validate_read_write((string_set) {
        { "a", 1 },
        { "a", 1 },
        { "a", 1 },
        { "a", 1 },
        { "a", 1 },
    });
    
    validate_read_write((string_set) {
        { "abc", 3 },
        { "abc", 3 },
        { "abc", 3 },
        { "abc", 3 },
        { "abc", 3 },
    });
    
    validate_read_write((string_set) {
        { "\0", 1 },
        { "\\u0000", 6, },
        { "\\u0000", 6, },
        { "\\u0000", 6, },
        { "\\u0000", 6, },
    });
    
    validate_read_write((string_set) {
        { "abc\0", 4 },
        { "abc\\u0000", 9 },
        { "abc\\u0000", 9 },
        { "abc\\u0000", 9 },
        { "abc\\u0000", 9 },
    });
    
    validate_read_write((string_set) {
        { "\0abc", 4 },
        { "\\u0000abc", 9 },
        { "\\u0000abc", 9 },
        { "\\u0000abc", 9 },
        { "\\u0000abc", 9 },
    });
    
    validate_read_write((string_set) {
        { "abc\0def", 7 },
        { "abc\\u0000def", 12 },
        { "abc\\u0000def", 12 },
        { "abc\\u0000def", 12 },
        { "abc\\u0000def", 12 },
    });
    
    validate_read_write((string_set) {
        { "a\\b", 3 },
        { "a\\\\b", 4 },
        { "a\\\\b", 4 },
        { "a\\\\b", 4 },
        { "a\\\\b", 4 },
    });
    
    validate_read_write((string_set) {
        { "a/b", 3 },
        { "a/b", 3 },
        { "a\\/b", 4 },
        { "a/b", 3 },
        { "a\\/b", 4 },
    });
    
    validate_read((string_set) {
        { "abc\x20\x7F", 5 },
        { "abc\x20\x7F", 5 },
        { "abc\x20\x7F", 5 },
        { "abc\x20\x7F", 5 },
        { "abc\x20\x7F", 5 },
    });
    
    validate_read_write((string_set) {
        { "\"\\/\b\f\n\r\t", 8 },
        { "\\\"\\\\/\\b\\f\\n\\r\\t", 15 },
        { "\\\"\\\\\\/\\b\\f\\n\\r\\t", 16 },
        { "\\\"\\\\/\\b\\f\\n\\r\\t", 15 },
        { "\\\"\\\\\\/\\b\\f\\n\\r\\t", 16 },
    });
    
    validate_read_write((string_set) {
        { "Alizée", 7 },
        { "Alizée", 7 },
        { "Alizée", 7 },
        { "Aliz\\u00E9e", 11 },
        { "Aliz\\u00E9e", 11 },
    });
    
    validate_read_write((string_set) {
        { "Hello世界", 11 },
        { "Hello世界", 11 },
        { "Hello世界", 11 },
        { "Hello\\u4E16\\u754C", 17 },
        { "Hello\\u4E16\\u754C", 17 },
    });
    
    validate_read((string_set) {
        { "Hello世界", 11 },
        { "Hello世界", 11 },
        { "Hello世界", 11 },
        { "Hello\\u4e16\\u754c", 17 },
        { "Hello\\u4e16\\u754c", 17 },
    });
    
    validate_read_write((string_set) {
        { "Emoji😊", 9 },
        { "Emoji😊", 9 },
        { "Emoji😊", 9 },
        { "Emoji\\uD83D\\uDE0A", 17 },
        { "Emoji\\uD83D\\uDE0A", 17 },
    });
    
    validate_read_write((string_set) {
        { "🐱\t🐶", 9 },
        { "🐱\\t🐶", 10 },
        { "🐱\\t🐶", 10 },
        { "\\uD83D\\uDC31\\t\\uD83D\\uDC36", 26 },
        { "\\uD83D\\uDC31\\t\\uD83D\\uDC36", 26 },
    });
    
    validate_read_write((string_set) {
        { "Check✅©\t2020®яблоко////แอปเปิ้ล\\\\リンゴ|تفاحة|蘋果|사과|", 97 },
        { "Check✅©\\t2020®яблоко////แอปเปิ้ล\\\\\\\\リンゴ|تفاحة|蘋果|사과|", 100 },
        { "Check✅©\\t2020®яблоко\\/\\/\\/\\/แอปเปิ้ล\\\\\\\\リンゴ|تفاحة|蘋果|사과|", 104 },
        { "Check\\u2705\\u00A9\\t2020\\u00AE\\u044F\\u0431\\u043B\\u043E\\u043A\\u043E////\\u0E41\\u0E2D\\u0E1B\\u0E40\\u0E1B\\u0E34\\u0E49\\u0E25\\\\\\\\\\u30EA\\u30F3\\u30B4|\\u062A\\u0641\\u0627\\u062D\\u0629|\\u860B\\u679C|\\uC0AC\\uACFC|\\uF8FF", 203 },
        { "Check\\u2705\\u00A9\\t2020\\u00AE\\u044F\\u0431\\u043B\\u043E\\u043A\\u043E\\/\\/\\/\\/\\u0E41\\u0E2D\\u0E1B\\u0E40\\u0E1B\\u0E34\\u0E49\\u0E25\\\\\\\\\\u30EA\\u30F3\\u30B4|\\u062A\\u0641\\u0627\\u062D\\u0629|\\u860B\\u679C|\\uC0AC\\uACFC|\\uF8FF", 207 },
    });
    
    
    // string with different length
    char rand_str[65] = { 0 };
    for (int i = 0; i < 64; i++) {
        rand_str[i] = 'a' + (i % 26);
    }
    for (int len = 1; len <= 64; len++) {
        validate_read_write((string_set) {
            { rand_str, len },
            { rand_str, len },
            { rand_str, len },
            { rand_str, len },
            { rand_str, len },
        });
    }
    for (int len = 0; len <= 64; len++) {
        // escape first char
        char buf1[1 + 64];
        char buf2[2 + 64];
        buf1[0] = '\t';
        memcpy(buf1 + 1, rand_str, len);
        buf2[0] = '\\';
        buf2[1] = 't';
        memcpy(buf2 + 2, rand_str, len);
        validate_read_write((string_set) {
            { buf1, len + 1 },
            { buf2, len + 2 },
            { buf2, len + 2 },
            { buf2, len + 2 },
            { buf2, len + 2 },
        });
    }
    
    
    // 1 byte invalid UTF-8
    for (int len = 0; len <= 6; len++) {
        validate_write((string_set) {
            { "\x80qwerty", 1 + len },
            { "\x80qwerty", 1 + len },
            { "\x80qwerty", 1 + len },
            { "\\uFFFDqwerty", 6 + len },
            { "\\uFFFDqwerty", 6 + len },
            true
        });
        validate_read((string_set) {
            { "\x80qwerty", 1 + len },
            { "\x80qwerty", 1 + len },
            { "\x80qwerty", 1 + len },
            { NULL, 0 },
            { NULL, 0 },
            true
        });
        validate_write((string_set) {
            { "\x80\x8Fqwerty", 2 + len },
            { "\x80\x8Fqwerty", 2 + len },
            { "\x80\x8Fqwerty", 2 + len },
            { "\\uFFFD\\uFFFDqwerty", 12 + len },
            { "\\uFFFD\\uFFFDqwerty", 12 + len },
            true
        });
        validate_read((string_set) {
            { "\x80\x8Fqwerty", 2 + len },
            { "\x80\x8Fqwerty", 2 + len },
            { "\x80\x8Fqwerty", 2 + len },
            { NULL, 0 },
            { NULL, 0 },
            true
        });
    }
    
    
    // 2 byte invalid UTF-8
    for (int len = 0; len <= 6; len++) {
        validate_write((string_set) {
            { "\xC0qwerty", 1 + len },
            { "\xC0qwerty", 1 + len },
            { "\xC0qwerty", 1 + len },
            { "\\uFFFDqwerty", 6 + len },
            { "\\uFFFDqwerty", 6 + len },
            true
        });
        validate_read((string_set) {
            { "\xC0qwerty", 1 + len },
            { "\xC0qwerty", 1 + len },
            { "\xC0qwerty", 1 + len },
            { NULL, 0 },
            { NULL, 0 },
            true
        });
        validate_write((string_set) {
            { "\xC0\xC0qwerty", 2 + len },
            { "\xC0\xC0qwerty", 2 + len },
            { "\xC0\xC0qwerty", 2 + len },
            { "\\uFFFD\\uFFFDqwerty", 12 + len },
            { "\\uFFFD\\uFFFDqwerty", 12 + len },
            true
        });
        validate_read((string_set) {
            { "\xC0\xC0qwerty", 2 + len },
            { "\xC0\xC0qwerty", 2 + len },
            { "\xC0\xC0qwerty", 2 + len },
            { NULL, 0 },
            { NULL, 0 },
            true
        });
        validate_write((string_set) {
            { "\xC0\tqwerty", 2 + len },
            { "\xC0\\tqwerty", 3 + len },
            { "\xC0\\tqwerty", 3 + len },
            { "\\uFFFD\\tqwerty", 8 + len },
            { "\\uFFFD\\tqwerty", 8 + len },
            true
        });
        validate_read((string_set) {
            { "\xC0\tqwerty", 2 + len },
            { "\xC0\tqwerty", 2 + len },
            { "\xC0\\tqwerty", 3 + len },
            { NULL, 0 },
            { NULL, 0 },
            true
        });
    }
    
    
    // 3 byte invalid UTF-8
    for (int len = 0; len <= 6; len++) {
        validate_write((string_set) {
            { "\xE0qwerty", 1 + len },
            { "\xE0qwerty", 1 + len },
            { "\xE0qwerty", 1 + len },
            { "\\uFFFDqwerty", 6 + len },
            { "\\uFFFDqwerty", 6 + len },
            true
        });
        validate_read((string_set) {
            { "\xE0qwerty", 1 + len },
            { "\xE0qwerty", 1 + len },
            { "\xE0qwerty", 1 + len },
            { NULL, 0 },
            { NULL, 0 },
            true
        });
        validate_write((string_set) {
            { "\xE0\x81\x81qwerty", 3 + len },
            { "\xE0\x81\x81qwerty", 3 + len },
            { "\xE0\x81\x81qwerty", 3 + len },
            { "\\uFFFD\\uFFFD\\uFFFDqwerty", 18 + len },
            { "\\uFFFD\\uFFFD\\uFFFDqwerty", 18 + len },
            true
        });
        validate_read((string_set) {
            { "\xE0\x81\x81qwerty", 3 + len },
            { "\xE0\x81\x81qwerty", 3 + len },
            { "\xE0\x81\x81qwerty", 3 + len },
            { NULL, 0 },
            { NULL, 0 },
            true
        });
    }
    
    
    // 4 byte invalid UTF-8
    for (int len = 0; len <= 6; len++) {
        validate_write((string_set) {
            { "\xF0qwerty", 1 + len },
            { "\xF0qwerty", 1 + len },
            { "\xF0qwerty", 1 + len },
            { "\\uFFFDqwerty", 6 + len },
            { "\\uFFFDqwerty", 6 + len },
            true
        });
        validate_read((string_set) {
            { "\xF0qwerty", 1 + len },
            { "\xF0qwerty", 1 + len },
            { "\xF0qwerty", 1 + len },
            { NULL, 0 },
            { NULL, 0 },
            true
        });
        validate_write((string_set) {
            { "\xF0\x81\x81\x81qwerty", 4 + len },
            { "\xF0\x81\x81\x81qwerty", 4 + len },
            { "\xF0\x81\x81\x81qwerty", 4 + len },
            { "\\uFFFD\\uFFFD\\uFFFD\\uFFFDqwerty", 24 + len },
            { "\\uFFFD\\uFFFD\\uFFFD\\uFFFDqwerty", 24 + len },
            true
        });
        validate_read((string_set) {
            { "\xF0\x81\x81\x81qwerty", 4 + len },
            { "\xF0\x81\x81\x81qwerty", 4 + len },
            { "\xF0\x81\x81\x81qwerty", 4 + len },
            { NULL, 0 },
            { NULL, 0 },
            true
        });
    }
    
    
    // special case
    validate_read((string_set) {
        { "qwerty\0", 7 },
        { "qwerty\0", 7 },
        { "qwerty\0", 7 },
        { NULL, 0 },
        { NULL, 0 },
        true
    });
    validate_read((string_set) {
        { "qwerty\0abc", 10 },
        { "qwerty\0abc", 10 },
        { "qwerty\0abc", 10 },
        { NULL, 0 },
        { NULL, 0 },
        true
    });
    validate_read((string_set) {
        { "\tqwerty\0", 8 },
        { "\\tqwerty\0", 9 },
        { "\\tqwerty\0", 9 },
        { NULL, 0 },
        { NULL, 0 },
        true
    });
    validate_read((string_set) {
        { "\tqwerty\0abc", 11 },
        { "\\tqwerty\0abc", 12 },
        { "\\tqwerty\0abc", 12 },
        { NULL, 0 },
        { NULL, 0 },
        true
    });
    validate_read((string_set) {
        { "\tqwerty\x80", 8 },
        { "\\tqwerty\x80", 9 },
        { "\\tqwerty\x80", 9 },
        { NULL, 0 },
        { NULL, 0 },
        true
    });
    validate_read((string_set) {
        { "\tqwerty\x80xyz", 11 },
        { "\\tqwerty\x80xyz", 12 },
        { "\\tqwerty\x80xyz", 12 },
        { NULL, 0 },
        { NULL, 0 },
        true
    });
    
    
    // invalid escape
    validate_read((string_set) {
        { NULL, 0 },
        { "\\T", 2 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\U00E9", 2 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\a", 2 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\e", 2 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\v", 2 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\'", 2 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\?", 2 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\000", 4 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\101", 4 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\x00", 4 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\x41", 4 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\U1234", 6 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\u123Z", 6 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\x1234", 6 },
    });
    
    
    // invalid high surrogate
    validate_read((string_set) {
        { NULL, 0 },
        { "\\uDE0A", 6 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\uDE0A\\u0000", 12 },
    });
    
    
    // no matched low surrogate
    validate_read((string_set) {
        { NULL, 0 },
        { "\\uD83D", 6 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\uD83D\\", 7 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\uD83D\\u", 8 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\uD83DAAAA", 10 },
    });
    
    
    // invalid low surrogate
    validate_read((string_set) {
        { NULL, 0 },
        { "\\uD83D\\u0000", 12 },
    });
    validate_read((string_set) {
        { NULL, 0 },
        { "\\uD83D\\uD83D", 12 },
    });
    
    
    // truncated escape sequence
    for (int len = 1; len < 12; len++) {
        if (len == 6) continue;
        const char *str = "\\u0024\\u0024";
        validate_read((string_set) {
            { NULL, 0 },
            { str, len },
            { str, len },
            { str, len },
            { str, len },
        });
    }
    
}



/*==============================================================================
 * MARK: - Extended Escape
 *============================================================================*/

/// Validate unquoted key: `read(set.str) == set.esc_non`.
static void validate_str_esc(char quote, string_set set, yyjson_read_flag flg) {
#if !YYJSON_DISABLE_READER && !YYJSON_DISABLE_NON_STANDARD
    
    string_val *src = &set.str;
    string_val *dst = &set.esc_non;
    
#if YYJSON_DISABLE_UTF8_VALIDATION
    if (src->str && !yy_str_is_utf8(src->str, src->len)) return;
#endif
    
    usize buf_len = src->len + 2;
    char *buf = malloc(buf_len);
    buf[0] = quote;
    memcpy(buf + 1, src->str, src->len);
    buf[buf_len - 1] = quote;
    
    yyjson_doc *doc = yyjson_read(buf, buf_len, flg);
    yyjson_val *val = yyjson_doc_get_root(doc);
    if (dst->str) {
        yy_assert(yyjson_equals_strn(val, dst->str, dst->len) &&
                  val->uni.str[dst->len] == '\0');
    } else {
        yy_assert(!doc);
    }
    free(buf);
    yyjson_doc_free(doc);
#endif
}

static void test_extended_escape(void) {
    
    // ----------------------------------
    // double-quoted string
    validate_str_esc('\"', (string_set) {
        { "ab\\\"xy", 6 },
        { "ab\"xy", 5 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\\"xy", 6 },
        { "ab\"xy", 5 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\\'xy", 6 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\\'xy", 6 },
        { "ab\'xy", 5 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\", 3 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\", 3 },
        { NULL, 0 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    
    // ----------------------------------
    // single-quote string
    validate_str_esc('\'', (string_set) {
        { "ab\\\"xy", 6 },
        { "ab\"xy", 5 }
    }, YYJSON_READ_ALLOW_SINGLE_QUOTED_STR);
    validate_str_esc('\'', (string_set) {
        { "ab\\\"xy", 6 },
        { "ab\"xy", 5 }
    }, YYJSON_READ_ALLOW_SINGLE_QUOTED_STR | YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\'', (string_set) {
        { "ab\\\'xy", 6 },
        { "ab\'xy", 5 }
    }, YYJSON_READ_ALLOW_SINGLE_QUOTED_STR);
    validate_str_esc('\'', (string_set) {
        { "ab\\\'xy", 6 },
        { "ab\'xy", 5 }
    }, YYJSON_READ_ALLOW_SINGLE_QUOTED_STR | YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\'', (string_set) {
        { "ab\\", 3 },
        { NULL, 0 }
    }, YYJSON_READ_ALLOW_SINGLE_QUOTED_STR);
    validate_str_esc('\'', (string_set) {
        { "ab\\", 3 },
        { NULL, 0 }
    }, YYJSON_READ_ALLOW_SINGLE_QUOTED_STR | YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    
    // ----------------------------------
    // single escape
    
    validate_str_esc('\"', (string_set) {
        { "ab\\axy", 6 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\axy", 6 },
        { "ab\axy", 5 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\exy", 6 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\exy", 6 },
        { "ab\x1Bxy", 5 } // this is not standard C escape
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\vxy", 6 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\vxy", 6 },
        { "ab\vxy", 5 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\?xy", 6 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\?xy", 6 },
        { "ab\?xy", 5 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\0xy", 6 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\0xy", 6 },
        { "ab\x00xy", 5 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\012xy", 8 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\012xy", 8 }, // oct not allowed
        { NULL, 0 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    
    // ----------------------------------
    // hex escape
    
    validate_str_esc('\"', (string_set) {
        { "ab\\x00xy", 8 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\x00xy", 8 },
        { "ab\x00xy", 5 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\x7Fxy", 8 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\x7Fxy", 8 }, // max ascii
        { "ab\x7Fxy", 5 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\x80xy", 8 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\x80xy", 8 }, // 2-byte utf8
        { "ab\xC2\x80xy", 6 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\xFFxy", 8 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\xFFxy", 8 }, // 2-byte utf8
        { "abÿxy", 6 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\xPPxy", 8 }, // not hex
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\xPPxy", 8 }, // not hex
        { NULL, 0 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\X7Fxy", 8 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\X7Fxy", 8 }, // `X` not `x`
        { "abX7Fxy", 7 } // just ignore '\'
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    
    // ----------------------------------
    // unknown escape
    
    validate_str_esc('\"', (string_set) {
        { "ab\\U1234xy", 10 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\U1234xy", 10 },
        { "abU1234xy", 9 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\😀xy", 9 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\😀xy", 9 },
        { "ab😀xy", 8 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\1xy", 6 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\1xy", 6 },
        { NULL, 0 } // oct not allow
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    
    // ----------------------------------
    // line continuation
    
    validate_str_esc('\"', (string_set) {
        { "ab\\\nxy", 6 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\\nxy", 6 },
        { "abxy", 4 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\\rxy", 6 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\\rxy", 6 },
        { "abxy", 4 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\\r\nxy", 7 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\\r\nxy", 7 },
        { "abxy", 4 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\\n\rxy", 7 },
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\\n\rxy", 7 },
        { NULL, 0 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\\xE2\x80\xA8xy", 8 }, // <LS>
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\\xE2\x80\xA8xy", 8 }, // <LS>
        { "abxy", 4 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
    
    validate_str_esc('\"', (string_set) {
        { "ab\\\xE2\x80\xA9xy", 8 }, // <PS>
        { NULL, 0 }
    }, 0);
    validate_str_esc('\"', (string_set) {
        { "ab\\\xE2\x80\xA9xy", 8 }, // <PS>
        { "abxy", 4 }
    }, YYJSON_READ_ALLOW_EXT_ESCAPE);
}



/*==============================================================================
 * MARK: - Single-quoted String
 *============================================================================*/

/// Validate single-quoted string: `read(set.str) == set.esc_non`.
static void validate_str_sq(string_set set) {
#if !YYJSON_DISABLE_READER && !YYJSON_DISABLE_NON_STANDARD
    
    string_val *src = &set.str;
    string_val *dst = &set.esc_non;
    
#if YYJSON_DISABLE_UTF8_VALIDATION
    if (src->str && !yy_str_is_utf8(src->str, src->len)) return;
#endif
    
    usize buf_len;
    char *buf, *cur;
    yyjson_doc *doc;
    yyjson_val *key, *val, *arr, *obj;
    yyjson_obj_iter iter;
    
    // single str
    buf_len = src->len + 2;
    cur = buf = malloc(buf_len);
    cur[0] = '\''; cur += 1;
    memcpy(cur, src->str, src->len); cur += src->len;
    cur[0] = '\''; cur += 1;
    
    doc = yyjson_read(buf, buf_len, YYJSON_READ_ALLOW_SINGLE_QUOTED_STR);
    val = yyjson_doc_get_root(doc);
    if (dst->str) {
        yy_assert(yyjson_equals_strn(val, dst->str, dst->len) &&
                  val->uni.str[dst->len] == '\0');
        
#if !YYJSON_DISABLE_WRITER
        // write again
        usize ret_len;
        char *ret = yyjson_write(doc, 0, &ret_len);
        yyjson_doc *ret_doc = yyjson_read(ret, ret_len, 0);
        val = yyjson_doc_get_root(ret_doc);
        yy_assert(yyjson_equals_strn(val, dst->str, dst->len));
        free(ret);
        yyjson_doc_free(ret_doc);
#endif
    } else {
        yy_assert(!doc);
    }
    free(buf);
    yyjson_doc_free(doc);
    
    
    // str in array
    for (int pretty = 0; pretty <= 1; pretty++) {
        buf_len = (src->len + 2) * 2 + 3 + pretty;
        cur = buf = malloc(buf_len);
        memcpy(cur, pretty ? "[ '" : "['", 2 + pretty); cur += 2 + pretty;
        memcpy(cur, src->str, src->len); cur += src->len;
        memcpy(cur, "','", 3); cur += 3;
        memcpy(cur, src->str, src->len); cur += src->len;
        memcpy(cur, "']", 2); cur += 2;
        
        doc = yyjson_read(buf, buf_len, YYJSON_READ_ALLOW_SINGLE_QUOTED_STR);
        arr = yyjson_doc_get_root(doc);
        val = yyjson_arr_get(arr, 0);
        if (dst->str) {
            yy_assert(yyjson_equals_strn(val, dst->str, dst->len) &&
                      val->uni.str[dst->len] == '\0' &&
                      yyjson_equals(val, yyjson_arr_get(arr, 1)));
        } else {
            yy_assert(!doc);
        }
        free(buf);
        yyjson_doc_free(doc);
    }
    
    
    // str in object key
    for (int pretty = 0; pretty <= 1; pretty++) {
        buf_len = (src->len + 2) * 2 + 3 + pretty;
        cur = buf = malloc(buf_len);
        memcpy(cur, pretty ? "{ '" : "{'", 2 + pretty); cur += 2 + pretty;
        memcpy(cur, src->str, src->len); cur += src->len;
        memcpy(cur, "':'", 3); cur += 3;
        memset(cur, ' ', src->len); cur += src->len;
        memcpy(cur, "'}", 2); cur += 2;
        
        doc = yyjson_read(buf, buf_len, YYJSON_READ_ALLOW_SINGLE_QUOTED_STR);
        obj = yyjson_doc_get_root(doc);
        iter = yyjson_obj_iter_with(obj);
        key = yyjson_obj_iter_next(&iter);
        val = yyjson_obj_iter_get_val(key);
        if (dst->str) {
            yy_assert(yyjson_equals_strn(key, dst->str, dst->len) &&
                      key->uni.str[dst->len] == '\0');
        } else {
            yy_assert(!doc);
        }
        free(buf);
        yyjson_doc_free(doc);
    }
    
    // str in object value
    for (int pretty = 0; pretty <= 1; pretty++) {
        buf_len = (src->len + 2) * 2 + 3 + pretty;
        cur = buf = malloc(buf_len);
        memcpy(cur, pretty ? "{ '" : "{'", 2 + pretty); cur += 2 + pretty;
        memset(cur, ' ', src->len); cur += src->len;
        memcpy(cur, "':'", 3); cur += 3;
        memcpy(cur, src->str, src->len); cur += src->len;
        memcpy(cur, "'}", 2); cur += 2;
        
        doc = yyjson_read(buf, buf_len, YYJSON_READ_ALLOW_SINGLE_QUOTED_STR);
        obj = yyjson_doc_get_root(doc);
        iter = yyjson_obj_iter_with(obj);
        key = yyjson_obj_iter_next(&iter);
        val = yyjson_obj_iter_get_val(key);
        if (dst->str) {
            yy_assert(yyjson_equals_strn(val, dst->str, dst->len) &&
                      val->uni.str[dst->len] == '\0');
        } else {
            yy_assert(!doc);
        }
        free(buf);
        yyjson_doc_free(doc);
    }
#endif
}

static void test_single_quoted_string(void) {
    validate_str_sq((string_set) {
        { "", 0 },
        { "", 0 }
    });
    validate_str_sq((string_set) {
        { "abcd", 4 },
        { "abcd", 4 }
    });
    validate_str_sq((string_set) {
        { "ab\"cd", 5 },
        { "ab\"cd", 5 }
    });
    validate_str_sq((string_set) {
        { "ab'cd", 5 },
        { NULL, 0 }
    });
    validate_str_sq((string_set) {
        { "ab\\'cd", 6 },
        { "ab\'cd", 5 }
    });
    validate_str_sq((string_set) {
        { "ab\x00cd", 5 },
        { NULL, 0 }
    });
    validate_str_sq((string_set) {
        { "abcdefghijklmnopqrstuvwxyz😀\\u0000😀", 40 },
        { "abcdefghijklmnopqrstuvwxyz😀\x00😀", 35 }
    });
}



/*==============================================================================
 * MARK: - Unquoted Key
 *============================================================================*/

/// Validate unquoted key: `read(set.str) == set.esc_non`.
static void validate_str_uq(string_set set, yyjson_read_flag flg) {
#if !YYJSON_DISABLE_READER && !YYJSON_DISABLE_NON_STANDARD
    
    string_val *src = &set.str;
    string_val *dst = &set.esc_non;
    
#if YYJSON_DISABLE_UTF8_VALIDATION
    if (src->str && !yy_str_is_utf8(src->str, src->len)) return;
#endif
    
    usize buf_len;
    char *buf, *cur;
    yyjson_doc *doc;
    yyjson_val *key, *val, *arr, *obj;
    yyjson_obj_iter iter;
    
    // str in object key
    for (int pretty = 0; pretty <= 1; pretty++) {
        buf_len = 1 + pretty + src->len + pretty + 3;
        cur = buf = malloc(buf_len);
        memcpy(cur, pretty ? "{ " : "{", 1 + pretty); cur += 1 + pretty;
        memcpy(cur, src->str, src->len); cur += src->len;
        memcpy(cur, pretty ? " " : "", pretty); cur += pretty;
        memcpy(cur, ":0}", 3);
        
        flg |= YYJSON_READ_ALLOW_UNQUOTED_KEY;
        doc = yyjson_read(buf, buf_len, flg);
        obj = yyjson_doc_get_root(doc);
        iter = yyjson_obj_iter_with(obj);
        key = yyjson_obj_iter_next(&iter);
        val = yyjson_obj_iter_get_val(key);
        if (dst->str) {
            yy_assert(yyjson_equals_strn(key, dst->str, dst->len) &&
                      key->uni.str[dst->len] == '\0');
        } else {
            yy_assert(!doc);
        }
        free(buf);
        yyjson_doc_free(doc);
    }
#endif
}

static void test_unquoted_key(void) {
    
    validate_str_uq((string_set) {
        { "abcd", 4 },
        { "abcd", 4 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "ab-cd", 5 }, // `-` is not allowed
        { NULL, 0 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "1", 1 }, // cannot start with digit
        { NULL, 0 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "123abc", 6 }, // cannot start with digit
        { NULL, 0 }
    }, 0);
    
    validate_str_uq((string_set) {
        { ".abc", 4 }, // cannot start with dot
        { NULL, 0 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "abc\n", 4 }, // JSON space
        { "abc", 3 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "ab\0cd", 5 }, // invalid '\0'
        { NULL, 0 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "\\u0000", 6 }, // escaped '\0'
        { "\0", 1 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "abc\f", 4 }, // extended space <FF>
        { NULL, 0 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "$", 1 }, // char `$`
        { "$", 1 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "_", 1 }, // char `_`
        { "_", 1 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "#", 1 }, // char `#`
        { NULL, 0 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "@", 1 }, // char `@`
        { NULL, 0 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "abc\f", 4 }, // extended space <FF> with flag
        { "abc", 3 }
    }, YYJSON_READ_ALLOW_EXT_WHITESPACE);
    
    validate_str_uq((string_set) {
        { "abc\xC2\xA0", 5 }, // extended unicode space <NBSP>
        { "abc\xC2\xA0", 5 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "abc\xC2\xA0", 5 }, // extended unicode space <NBSP> with flag
        { "abc", 3 }
    }, YYJSON_READ_ALLOW_EXT_WHITESPACE);
    
    validate_str_uq((string_set) {
        { "\\u679Cabc\xC2\xA0", 11 }, // extended unicode space <NBSP>
        { "果abc\xC2\xA0", 8 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "\\u679Cabc\xC2\xA0", 11 }, // extended unicode space <NBSP> with flag
        { "果abc", 6 }
    }, YYJSON_READ_ALLOW_EXT_WHITESPACE);
    
    validate_str_uq((string_set) {
        { "ab\\nc", 4 }, // single escape
        { NULL, 0 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "\\u00E9\\u679Cabcd", 16 }, // unicode escape prefix
        { "é果abcd", 9 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "ab\\u00E9\\u679Ccd", 16 }, // unicode escape
        { "abé果cd", 9 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "ab\\uASDFcd", 10 }, // invalid unicode escape
        { NULL, 0 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "\\uD83D\\uDE00abcdÄ果", 16 }, // unicode escape prefix
        { "😀abcdÄ", 8 }
    }, 0);
    
    validate_str_uq((string_set) {
        {"ab\\uD83D\\uDE00cdÄ果", 16}, // unicode escape
        {"ab😀cdÄ", 8}
    }, 0);
    
    validate_str_uq((string_set) {
        {"ab\\uD83D\\uFFFFcdÄ果", 16}, // invalid unicode escape
        {NULL, 0}
    }, 0);
    
    validate_str_uq((string_set) {
        {"\\uDE0Aabc", 9}, // invalid high surrogate
        {NULL, 0}
    }, 0);
    
    validate_str_uq((string_set) {
        {"\\uD83D\\uXXXX", 12}, // invalid low surrogate
        {NULL, 0}
    }, 0);
    
    validate_str_uq((string_set) {
        {"\\uD83Dabc", 9}, // no low surrogate
        {NULL, 0}
    }, 0);
    
    validate_str_uq((string_set) {
        { "abcdefghijklmnopqrstuvwxyz\\u00E9abcdefghijklmnopqrstuvwxyz😀果éabc", 70 }, // long string
        { "abcdefghijklmnopqrstuvwxyzéabcdefghijklmnopqrstuvwxyz😀果éabc", 66 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "😀Check✅©2020®яблокоแอปเปิ้ลリンゴتفاحة蘋果사과", 90 }, // utf8
        { "😀Check✅©2020®яблокоแอปเปิ้ลリンゴتفاحة蘋果사과", 90 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "PPPPPQQQQQ\\u00E9PPPPPQQQQQ\x80", 27 }, //  invalid UTF-8
        { NULL, 0 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "\x80PPPPPQQQQQ\\u00E9PPPPPQQQQQ\x80", 28 }, //  invalid UTF-8
        { NULL, 0 }
    }, 0);
    
    validate_str_uq((string_set) {
        { "\x80PPPPPQQQQQ\\u00E9PPPPPQQQQQ\x80", 28 }, //  invalid UTF-8
        { "\x80PPPPPQQQQQéPPPPPQQQQQ\x80", 24 }
    }, YYJSON_READ_ALLOW_INVALID_UNICODE);
}



/*==============================================================================
 * MARK: - Entry
 *============================================================================*/

yy_test_case(test_string) {
    test_read_write();
    test_extended_escape();
    test_single_quoted_string();
    test_unquoted_key();
}
