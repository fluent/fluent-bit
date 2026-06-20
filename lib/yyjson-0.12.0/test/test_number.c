// This file is used to test the functionality of number reading and writing.
// It contains various test data to detect how numbers are handled in different
// boundary cases. The results are compared with google/double-conversion to
// ensure accuracy.

#include "yyjson.h"
#include "yy_test_utils.h"
#include "goo_double_conv.h"
#include <locale.h>

#if !YYJSON_DISABLE_READER && !YYJSON_DISABLE_WRITER

// Whether IEEE 754 binary floating-point format is used.
#define FP_IEEE_754 GOO_HAS_IEEE_754

// Whether yyjson use libc's strtod/sprintf instead of its built-in functions.
#define FP_USE_LIBC (!FP_IEEE_754 || YYJSON_DISABLE_FAST_FP_CONV)

// The decimal precision required to read/write a floating-point value.
#ifndef FLT_DECIMAL_DIG
#define FLT_DECIMAL_DIG 9
#endif
#ifndef DBL_DECIMAL_DIG
#define DBL_DECIMAL_DIG 17
#endif



/*==============================================================================
 * MARK: - Helper
 *============================================================================*/

/// Convert bits to float.
static yy_inline f32 f32_from_bits(u32 u) {
    f32 f;
    memcpy((void *)&f, (void *)&u, sizeof(u));
    return f;
}

/// Convert bits to double.
static yy_inline f64 f64_from_bits(u64 u) {
    f64 f;
    memcpy((void *)&f, (void *)&u, sizeof(u));
    return f;
}

/// Current locale decimal point.
static char locale_decimal_point = '.';

/// Update locale decimal point.
static void update_locale_decimal_point(void) {
    struct lconv *conv = localeconv();
    char c = conv->decimal_point[0];
    yy_assertf(c && conv->decimal_point[1] == '\0',
               "locale decimal point is invalid: %s\n", conv->decimal_point);
    locale_decimal_point = c;
}

/// Replace decimal point to current locale.
static void decimal_point_to_locale(char *buf) {
    char *ptr = strchr(buf, '.');
    if (ptr) *ptr = locale_decimal_point;
}

/// Reset decimal point to default minimal "C" locale.
static void decimal_point_to_std(char *buf) {
    char *ptr = strchr(buf, locale_decimal_point);
    if (ptr) *ptr = '.';
}



/*==============================================================================
 * MARK: - Conversion (Libc)
 *============================================================================*/

/// Read float from string (libc).
static usize libc_f32_read(const char *str, f32 *val) {
    bool has_locale = (locale_decimal_point != '.');
    if (has_locale) {
        char *dup = yy_str_copy(str);
        decimal_point_to_locale(dup);
        str = dup;
    }
    char *end = NULL;
    *val = strtof(str, &end);
    usize len = end ? (end - str) : 0;
    if (has_locale) free((void *)str);
    return len;
}

/// Read double from string (libc).
static usize libc_f64_read(const char *str, f64 *val) {
    bool has_locale = (locale_decimal_point != '.');
    if (has_locale) {
        char *dup = yy_str_copy(str);
        decimal_point_to_locale(dup);
        str = dup;
    }
    char *end = NULL;
    *val = strtod(str, &end);
    usize len = end ? (end - str) : 0;
    if (has_locale) free((void *)str);
    return len;
}

/// Write float to string shortest (libc).
static usize libc_f32_write(f32 val, char *buf, usize len) {
    if (isinf(val)) return snprintf(buf, len, (val > 0) ? "Infinity" : "-Infinity");
    if (isnan(val)) return snprintf(buf, len, "NaN");
    int out_len = snprintf(buf, len, "%.*g", FLT_DECIMAL_DIG, val);
    if (locale_decimal_point != '.') decimal_point_to_std(buf);
    return (out_len >= (int)len) ? 0 : out_len;
}

/// Write double to string shortest (libc).
static usize libc_f64_write(f64 val, char *buf, usize len) {
    if (isinf(val)) return snprintf(buf, len, (val > 0) ? "Infinity" : "-Infinity");
    if (isnan(val)) return snprintf(buf, len, "NaN");
    int out_len = snprintf(buf, len, "%.*g", DBL_DECIMAL_DIG, val);
    if (locale_decimal_point != '.') decimal_point_to_std(buf);
    return (out_len >= (int)len) ? 0 : out_len;
}

/// Write double to string with fixed-point notation (libc).
static usize libc_f64_write_fixed(f64 val, int prec, char *buf, usize len) {
    if (isinf(val)) return snprintf(buf, len, (val > 0) ? "Infinity" : "-Infinity");
    if (isnan(val)) return snprintf(buf, len, "NaN");
    int out_len = snprintf(buf, len, "%.*f", prec, val);
    if (locale_decimal_point != '.') decimal_point_to_std(buf);
    return (out_len >= (int)len) ? 0 : out_len;
}



/*==============================================================================
 * MARK: - Conversion (Google)
 *============================================================================*/

/// Read float from string (google/double-conversion).
static usize goo_f32_read(const char *str, f32 *val) {
    int str_len = (int)strlen(str);
    *val = goo_strtof(str, str_len, &str_len);
    return (usize)str_len;
}

/// Read double from string (google/double-conversion).
static usize goo_f64_read(const char *str, f64 *val) {
    int str_len = (int)strlen(str);
    *val = goo_strtod(str, str_len, &str_len);
    return (usize)str_len;
}

/// Write float to string shortest (google/double-conversion).
static usize goo_f32_write(f32 val, char *buf, usize len) {
    return (usize)goo_ftoa(val, GOO_FMT_SHORTEST, 0, buf, (int)len);
}

/// Write double to string shortest (google/double-conversion).
static usize goo_f64_write(f64 val, char *buf, usize len) {
    return (usize)goo_dtoa(val, GOO_FMT_SHORTEST, 0, buf, (int)len);
}

/// Write double to string with fixed-point notation (google/double-conversion).
static usize goo_f64_write_fixed(f64 val, int prec, char *buf, usize len) {
    return (usize)goo_dtoa(val, GOO_FMT_FIXED, prec, buf, (int)len);
}



/*==============================================================================
 * MARK: - Conversion (Common)
 *============================================================================*/

/// Read float from string.
static usize f32_read(const char *str, f32 *val) {
#if FP_IEEE_754
    return goo_f32_read(str, val);
#else
    return libc_f32_read(str, val);
#endif
}

/// Read double from string.
static usize f64_read(const char *str, f64 *val) {
#if !FP_USE_LIBC
    return goo_f64_read(str, val);
#else
    return libc_f64_read(str, val);
#endif
}

/// Write float to string shortest.
static usize f32_write(f32 val, char *buf, usize len) {
#if !FP_USE_LIBC
    return goo_f32_write(val, buf, len);
#else
    return libc_f32_write(val, buf, len);
#endif
}

/// Write double to string shortest.
static usize f64_write(f64 val, char *buf, usize len) {
#if !FP_USE_LIBC
    return goo_f64_write(val, buf, len);
#else
    return libc_f64_write(val, buf, len);
#endif
}

/// Write double to string with fixed-point notation.
static usize f64_write_fixed(f64 val, int prec, char *buf, usize len) {
#if !FP_USE_LIBC
    return goo_f64_write_fixed(val, prec, buf, len);
#else
    return libc_f64_write_fixed(val, prec, buf, len);
#endif
}



/*==============================================================================
 * MARK: - Number String Format Checker
 *============================================================================*/

/// number type (accept overflow)
typedef enum {
    NUM_TYPE_FAIL,      // not a number
    NUM_TYPE_SINT,      // signed integer
    NUM_TYPE_UINT,      // unsigned integer
    NUM_TYPE_REAL,      // real number
    NUM_TYPE_LITERAL    // nan or inf literal
} num_type;

/// number information
typedef struct {
    const char *str; // string
    usize len; // string length
    num_type type; // string number type
    bool ext; // extended number format
    bool int_overflow; // overflow when reading as an integer
    bool real_overflow; // overflow when reading as a real number
    i64 i; // read as int64
    u64 u; // read as uint64
    f64 f; // read as double
} num_info;

static yy_inline bool char_is_sign(char c) {
    return c == '-' || c == '+';
}

static yy_inline bool char_is_e(char c) {
    return c == 'e' || c == 'E';
}

static yy_inline bool char_is_x(char c) {
    return c == 'x' || c == 'X';
}

static yy_inline bool char_is_digit(char c) {
    return '0' <= c && c <= '9';
}

static yy_inline bool char_is_hex(char c) {
    return ('0' <= c && c <= '9') ||
           ('a' <= c && c <= 'f') ||
           ('A' <= c && c <= 'F');
}

/// Check for overflow when reading an integer number (uint64/int64).
static yy_inline bool check_int_overflow(const char *str, num_type type) {
    if (type != NUM_TYPE_SINT && type != NUM_TYPE_UINT) return false;
    
    bool neg = (*str == '-');
    str += char_is_sign(*str);
    usize str_len = strlen(str);
    
    if (str[0] == '0' && char_is_x(str[1])) {
        // hex integer
        str_len -= 2;
        str += 2;
        if (str_len < 16) return false;
        if (str_len > 16) return true;
        if (neg) {
            return strcmp(str, "8000000000000000") > 0;
        } else {
            return false;
        }
    } else {
        // standard integer
        if (str_len < 19) return false;
        const char *max = neg ? "9223372036854775808" : "18446744073709551615";
        usize max_len = strlen(max);
        if (str_len > max_len) return true;
        if (str_len == max_len && strcmp(str, max) > 0) return true;
        return false;
    }
}

/// Check for overflow when reading a real number (double).
static yy_inline bool check_real_overflow(const char *str, num_type type) {
    if (type != NUM_TYPE_SINT && type != NUM_TYPE_UINT && type != NUM_TYPE_REAL) return false;
    
    f64 val = 0;
    if (!f64_read(str, &val)) return false;
    return !!isinf(val);
}

/// Check JSON number string and return its type.
/// This checks only the string format, not for numeric overflow.
/// @param str A null-terminated string.
/// @param ext Allow extended number format.
static yy_inline num_type get_num_type(const char *str, bool ext) {
    if (!str || !*str) return NUM_TYPE_FAIL;
    
    if (!ext) {
        // optional sign
        bool neg = (*str == '-');
        str += neg;
        
        // must begin with a digit
        if (!char_is_digit(*str)) {
            if (!yy_str_cmp(str, "nan", true) ||
                !yy_str_cmp(str, "inf", true) ||
                !yy_str_cmp(str, "infinity", true)) return NUM_TYPE_LITERAL;
            return NUM_TYPE_FAIL;
        }
        
        // leading zeros are not allowed
        if (str[0] == '0' && char_is_digit(str[1])) return NUM_TYPE_FAIL;
        
        // one or more digits
        while (char_is_digit(*str)) str++;
        
        // ending with integer type
        if (*str == '\0') return neg ? NUM_TYPE_SINT : NUM_TYPE_UINT;
        
        // optional fraction part
        if (*str == '.') {
            str++;
            // one or more digits
            if (!char_is_digit(*str)) return NUM_TYPE_FAIL;
            while (char_is_digit(*str)) str++;
        }
        
        // optional exponent part
        if (char_is_e(*str)) {
            str++;
            // optional sign
            if (char_is_sign(*str)) str++;
            // one or more digits
            if (!char_is_digit(*str)) return NUM_TYPE_FAIL;
            while (char_is_digit(*str)) str++;
        }
        
        // ending with real type
        return *str == '\0' ? NUM_TYPE_REAL : NUM_TYPE_FAIL;
        
    } else {
        // optional sign
        bool neg = (*str == '-');
        str += char_is_sign(*str);
        
        // hex integer
        if (str[0] == '0' && char_is_x(str[1])) {
            str += 2;
            if (!char_is_hex(*str)) return NUM_TYPE_FAIL;
            while (char_is_hex(*str)) str++;
            if (*str == '\0') return neg ? NUM_TYPE_SINT : NUM_TYPE_UINT;
            return NUM_TYPE_FAIL;
        }
        
        // real number start with '.'
        if (*str == '.') {
            str++;
            if (!char_is_digit(*str)) return NUM_TYPE_FAIL;
            while (char_is_digit(*str)) str++;
            
            // optional exponent part
            if (char_is_e(*str)) {
                str++;
                if (char_is_sign(*str)) str++;
                if (!char_is_digit(*str)) return NUM_TYPE_FAIL;
                while (char_is_digit(*str)) str++;
            }
            
            return *str == '\0' ? NUM_TYPE_REAL : NUM_TYPE_FAIL;
        }
        
        // must begin with a digit
        if (!char_is_digit(*str)) {
            if (!yy_str_cmp(str, "nan", true) ||
                !yy_str_cmp(str, "inf", true) ||
                !yy_str_cmp(str, "infinity", true)) return NUM_TYPE_LITERAL;
            return NUM_TYPE_FAIL;
        }
        
        // leading zeros are not allowed
        if (*str == '0' && char_is_digit(str[1])) return NUM_TYPE_FAIL;
        
        // one or more digits
        while (char_is_digit(*str)) str++;
        
        // ending with integer type
        if (*str == '\0') return neg ? NUM_TYPE_SINT : NUM_TYPE_UINT;
        
        // optional fraction part
        if (*str == '.') {
            str++;
            while (char_is_digit(*str)) str++;
        }
        
        // optional exponent part
        if (char_is_e(*str)) {
            str++;
            if (char_is_sign(*str)) str++;
            if (!char_is_digit(*str)) return NUM_TYPE_FAIL;
            while (char_is_digit(*str)) str++;
        }
        
        // ending with real type
        return *str == '\0' ? NUM_TYPE_REAL : NUM_TYPE_FAIL;
    }
}

/// Get number information from a string.
static yy_inline num_info get_num_info(const char *str) {
    num_info info = { 0 };
    info.str = str;
    info.len = str ? strlen(str) : 0;
    info.type = get_num_type(str, false);
    if (info.type == NUM_TYPE_FAIL) {
        info.type = get_num_type(str, true);
        if (info.type == NUM_TYPE_FAIL) return info;
        info.ext = true;
    }
    
    if (info.type == NUM_TYPE_LITERAL) {
        bool neg = *str == '-';
        str += char_is_sign(*str);
        info.f = (*str == 'n' || *str == 'N') ? NAN : (neg ? -INFINITY : INFINITY);
        return info;
    }
    
    if (info.type == NUM_TYPE_UINT || info.type == NUM_TYPE_SINT) {
        info.int_overflow = check_int_overflow(str, info.type);
        if (!info.int_overflow) {
            if (info.type == NUM_TYPE_UINT) {
                yy_assert(sizeof(unsigned long long) >= sizeof(u64));
                info.u = (u64)strtoull(str, NULL, 0);
                info.f = (f64)info.u;
            } else {
                yy_assert(sizeof(signed long long) >= sizeof(i64));
                info.i = (i64)strtoll(str, NULL, 0);
                info.f = (f64)info.i;
            }
            return info;
        }
    }
    
    // real number and integer overflow number
    f64 val = 0;
    yy_assert(f64_read(str, &val) > 0);
    info.f = val;
    info.real_overflow = !!isinf(val);
    return info;
}

/// Check if the number string is in its most compact (shortest) form.
static yy_inline bool check_num_compact(const char *str, num_type type) {
    if (type == NUM_TYPE_SINT || type == NUM_TYPE_UINT) {
        return *str != '+';
    }
    
    if (type == NUM_TYPE_LITERAL) {
        bool sign = *str == '-';
        str += sign;
        if (*str == 'n' || *str == 'N') return !sign; // sign is unnecessary for NaN
        return true;
    }
    
    if (type == NUM_TYPE_REAL) {
        // get decimal point and exponent part
        const char *dot = NULL, *exp = NULL, *end = NULL;
        const char *cur = str;
        while (*cur) {
            if (*cur == '.') dot = cur;
            else if (char_is_e(*cur)) exp = cur;
            cur++;
        }
        end = cur;
        
        // check fraction part
        if (dot) {
            if (exp) {
                if (*(exp - 1) == '0' ||
                    *(exp - 1) == '.') return false; // 1.0e23, 1.e23 -> 1e23
            } else {
                if (*(end - 1) == '0' &&
                    *(end - 2) != '.' &&
                    !char_is_digit(*(end - 2))) return false; // 1.10 -> 1.1
            }
        }
        
        // check exponent part
        if (exp) {
            if (exp[1] == '+') return false; // 1e+23 -> 1e23
            if (exp[1] == '0') return false; // 1e023 ->  1e23
        }
        return true;
    }
    
    return false;
}



/*==============================================================================
 * MARK: - Number Read/Write
 *============================================================================*/

/// Validate a real number's output.
static void validate_real_output(const char *str,
                                 void *val_ptr, yyjson_write_flag flg) {
#define expect(expr) yy_assertf(expr, "num: %.17g, flg: %u, out: [%s]", num, flg, str)
    
    yyjson_val *val = val_ptr;
    yy_assert(yyjson_is_real(val));
    
    /// global flag
    bool allow_inf_nan = (flg & YYJSON_WRITE_ALLOW_INF_AND_NAN) != 0;
    bool inf_nan_to_null = (flg & YYJSON_WRITE_INF_AND_NAN_AS_NULL) != 0;
    bool to_float = (flg & YYJSON_WRITE_FP_TO_FLOAT) != 0;
    u32 to_fixed = flg >> (32 - YYJSON_WRITE_FP_PREC_BITS);
    
    /// value flag, should override global flag
    bool val_to_float = ((u32)(val->tag >> 32) & YYJSON_WRITE_FP_TO_FLOAT) != 0;
    u32 val_to_fixed = (u32)(val->tag >> 32) >> (32 - YYJSON_WRITE_FP_PREC_BITS);
    if (val_to_fixed) to_fixed = val_to_fixed;
    if (val_to_float) to_float = val_to_float;
    
    /// `to fixed` should override `to float`
    if (to_fixed) to_float = false;
    
    char buf[64];
    f64 num = val->uni.f64;
    if (to_float) num = (f32)num;
    
    if (isfinite(num)) {
        expect(get_num_type(str, false) == NUM_TYPE_REAL);
        expect(check_num_compact(str, NUM_TYPE_REAL));
        
        if (to_fixed && (-1e21 < num && num < 1e21)) {
            // To fixed-point.
            // This will remove trailing zeros and reduce unnecessary precision,
            // so the output string may not be the same as libc/google's.
            f64_write_fixed(num, to_fixed, buf, sizeof(buf));
            f64 out_num;
            expect(f64_read(str, &out_num) > 0);
            expect(f64_read(buf, &num) > 0);
            expect(out_num == num);
            
            char *dot = strchr(str, '.');
            expect(dot != NULL);
            usize digits_after_dot = strlen(str) - (usize)(dot - str) - 1;
            expect(digits_after_dot <= (usize)to_fixed);
            
        } else {
#if FP_USE_LIBC
            // To shortest.
            // The libc's output string may not be the shortest.
            f64 out_num;
            expect(f64_read(str, &out_num) > 0);
            if (to_float) {
                expect((f32)out_num == (f32)num);
            } else {
                expect(out_num == num);
            }
#else
            // To shortest.
            // The output string should be exactly the same as google's.
            if (to_float) {
                f32_write((f32)num, buf, sizeof(buf));
            } else {
                f64_write(num, buf, sizeof(buf));
            }
            expect(!strcmp(str, buf));
#endif
        }
    } else {
        if (inf_nan_to_null) {
            expect(!strcmp(str, "null"));
        }
#if !YYJSON_DISABLE_NON_STANDARD
        else if (allow_inf_nan) {
            if (isnan(num)) {
                expect(!strcmp(str, "NaN"));
            } else if (num > 0) {
                expect(!strcmp(str, "Infinity"));
            } else {
                expect(!strcmp(str, "-Infinity"));
            }
        }
#endif
        else {
            expect(!str);
        }
    }
#undef expect
}

/// Test number write with info and flag.
static void test_num_write(num_info info, yyjson_write_flag flg) {
#define expect(expr) yy_assertf(expr, "num str: [%s], flg: %u", info.str, flg)
    
    bool to_float = (flg & YYJSON_WRITE_FP_TO_FLOAT) != 0;
    u32 to_fixed = flg >> (32 - YYJSON_WRITE_FP_PREC_BITS);
    
    yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
    
    /// write as real number
    f64 num = info.f;
    if (to_float && !to_fixed) num = (f32)num;
    
    yyjson_mut_val *val = yyjson_mut_real(doc, num);
    yyjson_mut_doc_set_root(doc, val);
    char *str = yyjson_mut_write(doc, flg, NULL);
    validate_real_output(str, val, flg);
    free(str);
    
    /// write as uint/sint
    if (info.type == NUM_TYPE_UINT && !info.int_overflow) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%llu", (unsigned long long)info.u);
        val = yyjson_mut_uint(doc, info.u);
        yyjson_mut_doc_set_root(doc, val);
        str = yyjson_mut_write(doc, flg, NULL);
        expect(!strcmp(str, buf));
        free(str);
    } else if (info.type == NUM_TYPE_SINT && !info.int_overflow) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%lld", (signed long long)info.i);
        val = yyjson_mut_sint(doc, info.i);
        yyjson_mut_doc_set_root(doc, val);
        str = yyjson_mut_write(doc, flg, NULL);
        expect(!strcmp(str, buf));
        free(str);
    }
    
    yyjson_mut_doc_free(doc);
    
#undef expect
}

/// Test number read with info and flag.
static void test_num_read(num_info info, yyjson_read_flag flg) {
#define expect(expr) yy_assertf(expr, "num str: [%s], flg: %u", str, flg)
    
    const char *str = info.str;
    usize len = info.len;
    yyjson_doc *doc = yyjson_read(str, len, flg);
    yyjson_val *val = yyjson_doc_get_root(doc);
    
#if YYJSON_DISABLE_NON_STANDARD
    bool non_std = false;
#else
    bool non_std = true;
#endif
    bool flg_big_raw = (flg & YYJSON_READ_BIGNUM_AS_RAW) != 0;
    bool flg_num_raw = (flg & YYJSON_READ_NUMBER_AS_RAW) != 0;
    bool flg_inf_nan = (flg & YYJSON_READ_ALLOW_INF_AND_NAN) != 0;
    bool flg_ext     = (flg & YYJSON_READ_ALLOW_EXT_NUMBER) != 0;
    
    if (info.type == NUM_TYPE_FAIL || (info.ext && (!flg_ext || !non_std))) {
        /// not a valid number
        expect(val == NULL);
        
    } else if (info.type == NUM_TYPE_LITERAL) {
        /// nan/inf literal
        if (flg_inf_nan && non_std) {
            if (flg_num_raw) {
                expect(yyjson_is_raw(val) && !strcmp(yyjson_get_raw(val), str));
            } else if (isnan(info.f)) {
                expect(yyjson_is_real(val) && isnan(yyjson_get_real(val)));
            } else {
                expect(yyjson_is_real(val) && yyjson_get_real(val) == info.f);
            }
        } else {
            expect(val == NULL);
        }
        
    } else if (flg_num_raw) {
        /// uint/sint/real -> raw
        expect(yyjson_is_raw(val) && !strcmp(yyjson_get_raw(val), str));
        
    } else if (info.real_overflow) {
        /// uint/sint/real -> overflow
        if (flg_big_raw) {
            expect(yyjson_is_raw(val) && !strcmp(yyjson_get_raw(val), str));
        } else if (non_std && flg_inf_nan) {
            expect(yyjson_is_real(val) && yyjson_get_real(val) == info.f);
        } else {
            expect(val == NULL);
        }
        
    } else if (info.int_overflow) {
        /// uint/sint overflow -> real
        if (flg_big_raw) {
            expect(yyjson_is_raw(val) && !strcmp(yyjson_get_raw(val), str));
        } else {
            if (strchr(info.str, 'x') || strchr(info.str, 'X')) {
                // Hex, do not read as float
                expect(val == NULL);
            } else {
                expect(yyjson_is_real(val) && yyjson_get_real(val) == info.f);
            }
        }
        
    } else if (info.type == NUM_TYPE_UINT) {
        /// uint
        expect(yyjson_is_uint(val) && yyjson_get_uint(val) == info.u);
        
    } else if (info.type == NUM_TYPE_SINT) {
        /// sint
        expect(yyjson_is_sint(val) && yyjson_get_sint(val) == info.i);
        
    } else if (info.type == NUM_TYPE_REAL) {
        /// real
        expect(yyjson_is_real(val) && yyjson_get_real(val) == info.f);
        
    }
    
    yyjson_val val_out = { 0 };
    const char *ptr = yyjson_read_number(str, &val_out, flg, NULL, NULL);
    if (val) {
        expect(yyjson_equals(val, &val_out));
        expect(ptr == str + len);
    } else {
        expect(ptr != str + len);
    }
    
    yyjson_doc_free(doc);
    
#undef expect
}

/// Test number read and write.
static void test_num_info(num_info info) {
    /// test read
    test_num_read(info, YYJSON_READ_NOFLAG);
    test_num_read(info, YYJSON_READ_BIGNUM_AS_RAW);
    test_num_read(info, YYJSON_READ_NUMBER_AS_RAW);
    test_num_read(info, YYJSON_READ_ALLOW_INF_AND_NAN);
    test_num_read(info, YYJSON_READ_ALLOW_EXT_NUMBER);
    test_num_read(info, YYJSON_READ_ALLOW_INF_AND_NAN | YYJSON_READ_ALLOW_EXT_NUMBER);
    test_num_read(info, YYJSON_READ_BIGNUM_AS_RAW | YYJSON_READ_ALLOW_INF_AND_NAN);
    test_num_read(info, YYJSON_READ_NUMBER_AS_RAW | YYJSON_READ_ALLOW_INF_AND_NAN);
    test_num_read(info, YYJSON_READ_BIGNUM_AS_RAW | YYJSON_READ_ALLOW_EXT_NUMBER);
    test_num_read(info, YYJSON_READ_NUMBER_AS_RAW | YYJSON_READ_ALLOW_EXT_NUMBER);
    test_num_read(info, YYJSON_READ_BIGNUM_AS_RAW | YYJSON_READ_ALLOW_INF_AND_NAN | YYJSON_READ_ALLOW_EXT_NUMBER);
    test_num_read(info, YYJSON_READ_NUMBER_AS_RAW | YYJSON_READ_ALLOW_INF_AND_NAN | YYJSON_READ_ALLOW_EXT_NUMBER);
    
    /// test write
    test_num_write(info, YYJSON_WRITE_NOFLAG);
    test_num_write(info, YYJSON_WRITE_ALLOW_INF_AND_NAN);
    test_num_write(info, YYJSON_WRITE_INF_AND_NAN_AS_NULL);
    
    /// test write fp format
    test_num_write(info, YYJSON_WRITE_FP_TO_FLOAT);
    test_num_write(info, YYJSON_WRITE_FP_TO_FLOAT | YYJSON_WRITE_ALLOW_INF_AND_NAN);
    test_num_write(info, YYJSON_WRITE_FP_TO_FLOAT | YYJSON_WRITE_INF_AND_NAN_AS_NULL);
    for (int i = 1; i <= 15; i++) {
        test_num_write(info, YYJSON_WRITE_FP_TO_FIXED(i));
    }
}

/// Test all numbers from the txt files.
static void test_all_files(void) {
    /// get all files in the /test/data/num directory
    char dir[YY_MAX_PATH];
    yy_path_combine(dir, YYJSON_TEST_DATA_PATH, "data", "num", NULL);
    int count;
    char **names = yy_dir_read(dir, &count);
    yy_assertf(names != NULL && count != 0, "read dir fail:%s\n", dir);
    
    for (int i = 0; i < count; i++) {
        /// get full path of this file, ignore hidden and non-txt file
        char *name = names[i];
        if (*name == '.') continue;
        if (!yy_str_has_suffix(name, ".txt")) continue;
        char path[YY_MAX_PATH];
        yy_path_combine(path, dir, name, NULL);
        
        /// read this file to memory
        yy_dat dat;
        bool file_suc = yy_dat_init_with_file(&dat, path);
        yy_assertf(file_suc == true, "file read fail: %s\n", path);
        
        /// check flags
        bool is_int     = yy_str_has_prefix(name, "int"); // uint/sint
        bool is_hex     = yy_str_has_prefix(name, "hex"); // hex int
        bool is_real    = yy_str_has_prefix(name, "real"); // real
        bool is_literal = yy_str_has_prefix(name, "literal"); // literal
        
        bool is_ext     = yy_str_contains(name, "(ext)"); // extended format
        bool is_big     = yy_str_contains(name, "(big)"); // int overflow -> real
        bool is_inf     = yy_str_contains(name, "(inf)"); // int/real overflow -> inf
        bool is_fail    = yy_str_contains(name, "(fail)"); // always fail
        
        /// iterate over each line of the file
        usize len;
        char *line;
        while ((line = yy_dat_read_line(&dat, &len))) {
            /// ignore empty line and comment
            if (len == 0 || line[0] == '#') continue;
            /// add a null-terminator
            line[len] = '\0';
            
            /// check number format
            num_info info = get_num_info(line);
            if (is_fail) {
                yy_assert(info.type == NUM_TYPE_FAIL);
            } else {
                yy_assert(info.ext == is_ext);
                if (is_int || is_hex) {
                    if (line[0] == '-') {
                        yy_assert(info.type == NUM_TYPE_SINT);
                    } else {
                        yy_assert(info.type == NUM_TYPE_UINT);
                    }
                    if (is_inf) {
                        yy_assert(info.int_overflow == true);
                        yy_assert(info.real_overflow == true);
                    } else if (is_big) {
                        yy_assert(info.int_overflow == true);
                        yy_assert(info.real_overflow == false);
                    }
                } else if (is_real) {
                    yy_assert(info.type == NUM_TYPE_REAL);
                    if (is_inf) {
                        yy_assert(info.real_overflow == is_inf);
                    }
                } else if (is_literal) {
                    yy_assert(info.type == NUM_TYPE_LITERAL);
                }
            }
            
            /// test one number
            test_num_info(info);
        }
        
        yy_dat_release(&dat);
    }
    
    yy_dir_free(names);
}

/// Test some random integer read/write.
static void test_random_int(void) {
    int count = 10000;
    char buf[64] = { 0 };
    char *end;
    
    num_info info = { 0 };
    info.str = buf;
    
    yy_rand_reset(0);
    for (int i = 0; i < count; i++) {
        u64 r = yy_rand_u64();
        info.len = (usize)snprintf(buf, 32, "%llu", (unsigned long long)r);
        info.u = r;
        info.type = NUM_TYPE_UINT;
        test_num_info(info);
    }
    
    yy_rand_reset(0);
    for (int i = 0; i < count; i++) {
        i64 r = (i64)(yy_rand_u64() | ((u64)1 << 63));
        info.len = (usize)snprintf(buf, 32, "%lld", (signed long long)r);
        info.i = r;
        info.type = NUM_TYPE_SINT;
        test_num_info(info);
    }
    
    yy_rand_reset(0);
    for (int i = 0; i < count; i++) {
        u32 r = yy_rand_u32();
        info.len = (usize)snprintf(buf, 32, "%lu", (unsigned long)r);
        info.u = r;
        info.type = NUM_TYPE_UINT;
        test_num_info(info);
    }
    
    yy_rand_reset(0);
    for (int i = 0; i < count; i++) {
        i32 r = (i32)(yy_rand_u32() | ((u32)1 << 31));
        info.len = (usize)snprintf(buf, 32, "%li", (signed long)r);
        info.i = r;
        info.type = NUM_TYPE_SINT;
        test_num_info(info);
    }
}

/// Test real number read/write fast (do not test all flags).
static void test_real_fast(f64 num, yyjson_alc *alc,
                           bool test_to_float,
                           bool test_to_fixed) {
    char buf[64] = { 0 };
    char *str;
    usize len;
    
    yyjson_val val = { 0 };
    yyjson_set_real(&val, num);
    
    /// double to shortest
    str = yyjson_val_write_opts(&val, 0, alc, &len, NULL);
    validate_real_output(str, &val, 0);
    if (str) {
        yyjson_val val_out = { 0 };
        const char *end = yyjson_read_number(str, &val_out, 0, alc, NULL);
        yy_assert(end && *end == '\0');
        yy_assert(val_out.uni.f64 == val.uni.f64);
        alc->free(alc->ctx, str);
    }
    
    /// float to shortest
    if (test_to_float) {
        yyjson_write_flag flg = YYJSON_WRITE_FP_TO_FLOAT;
        str = yyjson_val_write_opts(&val, flg, alc, &len, NULL);
        validate_real_output(str, &val, flg);
        if (str) {
            yyjson_val val2 = { 0 };
            const char *end = yyjson_read_number(str, &val2, 0, alc, NULL);
            yy_assert(end && *end == '\0');
            
            f64 num2;
            f64_read(str, &num2);
            yy_assert(val2.uni.f64 == num2);
            alc->free(alc->ctx, str);
        }
    }
    
    /// double to fixed
    if (test_to_fixed) {
        for (int prec = 1; prec <= 15; prec++) {
            yyjson_write_flag flg = YYJSON_WRITE_FP_TO_FIXED(prec);
            str = yyjson_val_write_opts(&val, flg, alc, &len, NULL);
            validate_real_output(str, &val, flg);
            if (str) {
                yyjson_val val2 = { 0 };
                const char *end = yyjson_read_number(str, &val2, 0, alc, NULL);
                yy_assert(end && *end == '\0');
                
                f64 num2;
                f64_read(str, &num2);
                yy_assert(val2.uni.f64 == num2);
                alc->free(alc->ctx, str);
            }
        }
    }
}

/// Test some random real number read/write.
static void test_random_real(void) {
    int count = 10000;
    char alc_buf[4096];
    yyjson_alc alc;
    yyjson_alc_pool_init(&alc, alc_buf, sizeof(alc_buf));
    
    yy_rand_reset(0);
    for (int i = 0; i < count; i++) {
        u64 r = yy_rand_u64();
        f64 f = f64_from_bits(r);
        test_real_fast(f, &alc, true, true);
    }
    
    yy_rand_reset(0);
    for (int i = 0; i < count; i++) {
        u32 r = yy_rand_u32();
        f32 f = f32_from_bits(r);
        test_real_fast(f, &alc, true, true);
    }
}

/// Test some special real number read/write
static void test_special_real(void) {
    char alc_buf[4096];
    yyjson_alc alc;
    yyjson_alc_pool_init(&alc, alc_buf, sizeof(alc_buf));
    
    // short digits
    for (int sig = 1; sig <= 200; sig++) {
        for (int exp = -326; exp <= 308; exp++) {
            char buf[64];
            snprintf(buf, sizeof(buf), "%de%d", sig, exp);
            f64 num;
            f64_read(buf, &num);
            test_real_fast(num, &alc, true, true);
        }
    }
    
    // edge cases
    for (u64 exp = 0; exp <= 2046; exp++) {
        for (u64 sig = 0; sig <= 100; sig++) {
            u64 raw = (exp << 52) | sig;
            f64 num = f64_from_bits(raw);
            test_real_fast(num, &alc, true, true);
        }
        for (u64 sig = 0xFFFFFFFFFFFFFULL; sig >= (0xFFFFFFFFFFFFFULL - 100); sig--) {
            u64 raw = (exp << 52) | sig;
            f64 num = f64_from_bits(raw);
            test_real_fast(num, &alc, true, true);
        }
    }
}

/// Test all float32 number read/write.
/// It takes about 13 minutes on Apple M1/M2 (release build).
static void test_all_float(void) {
    char alc_buf[4096];
    yyjson_alc alc;
    yyjson_alc_pool_init(&alc, alc_buf, sizeof(alc_buf));
    
    printf("--- begin test all float ---\n");
    f64 begin_time = yy_get_time();
    for (u32 i = 0, max = (u32)1 << 31; i < max; i++) {
        f32 f = f32_from_bits(i);
        test_real_fast((f64)f, &alc, true, false);
        
        // print progress
        if ((i << 8) == 0 && i) {
            f64 progress = (f64)i / max;
            f64 elapsed = yy_get_time() - begin_time;
            f64 expected = elapsed / (i + 1) * max;
            f64 remaining = expected - elapsed;
            printf("progress: %.2f%%, remaining: %.1f minutes\n",
                   progress * 100, remaining / 60);
            fflush(NULL);
        }
    }
    printf("--- end test all float ---\n");
}



/*==============================================================================
 * MARK: - Test Input Types and Flags
 *============================================================================*/

/// Test reader with different parameters.
static void test_read_params(void) {
    yyjson_val ival;
    yyjson_mut_val mval;
    const char *ptr;
    
    ptr = yyjson_read_number(NULL, &ival, 0, NULL, NULL);
    yy_assertf(ptr == NULL, "read line NULL should fail\n");
    ptr = yyjson_read_number("123", NULL, 0, NULL, NULL);
    yy_assertf(ptr == NULL, "read val NULL should fail\n");
    ptr = yyjson_read_number(NULL, NULL, 0, NULL, NULL);
    yy_assertf(ptr == NULL, "read line and val NULL should fail\n");
    
    ptr = yyjson_mut_read_number(NULL, &mval, 0, NULL, NULL);
    yy_assertf(ptr == NULL, "read line NULL should fail\n");
    ptr = yyjson_mut_read_number("123", NULL, 0, NULL, NULL);
    yy_assertf(ptr == NULL, "read val NULL should fail\n");
    ptr = yyjson_mut_read_number(NULL, NULL, 0, NULL, NULL);
    yy_assertf(ptr == NULL, "read line and val NULL should fail\n");
}

/// Test all combinations of number types and flags.
static void test_read_flags(void) {
    
    /// all number types
    const char *num_arr[] = {
        "0", // uint
        "-0", // sint
        "0.0", // real
        "-0.0", // real
        
        "123", // uint
        "-123", // sint
        "123.0", // real
        "-123.0", // real
        
        "9223372036854775808", // uint
        "9223372036854775808.0", // real
        
        "18446744073709551615", // uint
        "18446744073709551615.0", // real
        "18446744073709551616", // uint overflow
        "184467440737095516160", // uint overflow
        
        "-9223372036854775808", // sint
        "-9223372036854775808.0", // real
        "-9223372036854775809", // sint overflow
        "-92233720368547758090", // sint overflow
        
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890", // uint->real overflow
        "-12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890"
        "12345678901234567890123456789012345678901234567890", // sint->real overflow
        
        "123e999", // real overflow
        "-123e999", // real overflow
        
        "NaN", // nan
        "+NaN", // nan
        "-NaN", // nan
        "Inf", // inf
        "+Infinity", // -inf
        "-Infinity", // -inf
        
        "0x123", // hex
        "-0x123", // hex
        "+0X000123" // hex
        
        "+123", // ext number
        ".123", // ext number
        "123.", // ext number
        "+.123e12", // ext number
        "+123.e12", // ext number
        ".000000000000000000000", // ext number
        
        "001", // fail
    };
    
    /// all number flags
    yyjson_read_flag flag_arr[] = {
        YYJSON_READ_NUMBER_AS_RAW,
        YYJSON_READ_BIGNUM_AS_RAW,
        YYJSON_READ_ALLOW_INF_AND_NAN,
        YYJSON_READ_ALLOW_EXT_NUMBER,
    };
    
    /// test number type
    for (usize i = 0; i < yy_nelems(num_arr); i++) {
        const char *num_str = num_arr[i];
        usize num_len = strlen(num_str);
        
        bool ext = false;
        num_type type = get_num_type(num_str, false);
        if (type == NUM_TYPE_FAIL) {
            type = get_num_type(num_str, true);
            if (type != NUM_TYPE_FAIL) ext = true;
        }
        
        /// test flag combination
        u32 flag_count = (u32)yy_nelems(flag_arr);
        u32 comb_count = 1 << flag_count;
        for (u32 c = 0; c < comb_count; c++) {
            yyjson_read_flag flg = 0;
            for (u32 f = 0; f < flag_count; f++) {
                if (c & (1 << f)) flg |= flag_arr[f];
            }
            
            /// doc read
            yyjson_doc *doc = yyjson_read(num_str, num_len, flg);
            yyjson_val *val = yyjson_doc_get_root(doc);
            
            {   /// val read
                yyjson_val val2;
                const char *end = yyjson_read_number(num_str, &val2, flg, NULL, NULL);
                if (val) {
                    yy_assert(yyjson_equals(val, &val2));
                    yy_assert(end && *end == '\0');
                } else {
                    yy_assert(end != num_str);
                }
            }
            {   /// mut val read
                yyjson_mut_val val2;
                const char *end = yyjson_mut_read_number(num_str, &val2, flg, NULL, NULL);
                if (val) {
                    yy_assert(yyjson_equals(val, (yyjson_val *)&val2));
                    yy_assert(end && *end == '\0');
                } else {
                    yy_assert(end != num_str);
                }
            }
            {   /// minity format read
                usize buf_len = num_len + 2;
                char *buf = calloc(1, buf_len + 1);
                buf[0] = '[';
                memcpy(buf + 1, num_str, num_len);
                buf[num_len + 1] = ']';
                yyjson_doc *doc2 = yyjson_read(buf, buf_len, flg);
                yyjson_val *val2 = yyjson_arr_get_first(yyjson_doc_get_root(doc2));
                yy_assert(val == val2 || yyjson_equals(val, val2));
                yyjson_doc_free(doc2);
                free(buf);
            }
            {   /// pretty format read
                usize buf_len = num_len + 6;
                char *buf = calloc(1, buf_len + 1);
                memcpy(buf, "[\n  ", 4);
                memcpy(buf + 4, num_str, num_len);
                memcpy(buf + 4 + num_len, "\n]", 2);
                yyjson_doc *doc2 = yyjson_read(buf, buf_len, flg);
                yyjson_val *val2 = yyjson_arr_get_first(yyjson_doc_get_root(doc2));
                yy_assert(val == val2 || yyjson_equals(val, val2));
                yyjson_doc_free(doc2);
                free(buf);
            }
            
#if YYJSON_DISABLE_NON_STANDARD
            flg &= ~YYJSON_READ_ALLOW_INF_AND_NAN;
            flg &= ~YYJSON_READ_ALLOW_EXT_NUMBER;
#endif
            if (type == NUM_TYPE_FAIL || (ext && !(flg & YYJSON_READ_ALLOW_EXT_NUMBER))) {
                /// invalid number format
                yy_assert(!doc);
            } else if (flg & YYJSON_READ_NUMBER_AS_RAW) {
                /// all number should be raw
                if (type == NUM_TYPE_LITERAL &&
                    !(flg & YYJSON_READ_ALLOW_INF_AND_NAN)) {
                    yy_assert(!doc);
                } else {
                    yy_assert(yyjson_is_raw(val));
                    yy_assert(!strcmp(num_str, yyjson_get_raw(val)));
                }
            } else switch (type) {
                case NUM_TYPE_SINT:
                case NUM_TYPE_UINT: {
                    /// integer number format
                    if (!check_int_overflow(num_str, type)) {
                        /// integer number not overflow
                        yy_assert(yyjson_is_int(val));
                    } else if (!check_real_overflow(num_str, type)) {
                        /// integer number overflow, but real number not overflow
                        if (flg & YYJSON_READ_BIGNUM_AS_RAW) {
                            yy_assert(yyjson_is_raw(val));
                            yy_assert(!strcmp(num_str, yyjson_get_raw(val)));
                        } else {
                            yy_assert(yyjson_is_real(val));
                        }
                    } else {
                        /// real number overflow
                        if (flg & YYJSON_READ_BIGNUM_AS_RAW) {
                            yy_assert(yyjson_is_raw(val));
                            yy_assert(!strcmp(num_str, yyjson_get_raw(val)));
                        } else if (flg & YYJSON_READ_ALLOW_INF_AND_NAN) {
                            yy_assert(yyjson_is_real(val));
                        } else {
                            yy_assert(!doc);
                        }
                    }
                    break;
                }
                case NUM_TYPE_REAL: {
                    /// real number
                    if (!check_real_overflow(num_str, type)) {
                        /// real number not overflow
                        yy_assert(yyjson_is_real(val));
                    } else {
                        /// real number overflow
                        if (flg & YYJSON_READ_BIGNUM_AS_RAW) {
                            yy_assert(yyjson_is_raw(val));
                            yy_assert(!strcmp(num_str, yyjson_get_raw(val)));
                        } else if (flg & YYJSON_READ_ALLOW_INF_AND_NAN) {
                            yy_assert(yyjson_is_real(val));
                        } else {
                            yy_assert(!doc);
                        }
                    }
                    break;
                }
                case NUM_TYPE_LITERAL: {
                    if ((flg & YYJSON_READ_ALLOW_INF_AND_NAN)) {
                        yy_assert(yyjson_is_real(val));
                    } else {
                        yy_assert(!doc);
                    }
                    break;
                }
                default: {
                    break;
                }
            }
            
            yyjson_doc_free(doc);
        }
    }
}

/// Test all combinations of number types and flags.
static void test_write_flags(void) {
    const u32 prec = 3;
    yyjson_write_flag flag_arr[] = {
        YYJSON_WRITE_ALLOW_INF_AND_NAN,
        YYJSON_WRITE_INF_AND_NAN_AS_NULL,
        YYJSON_WRITE_FP_TO_FLOAT,
        YYJSON_WRITE_FP_TO_FIXED(3),
    };
    
    /// test flag combination
    u32 flag_count = (u32)yy_nelems(flag_arr);
    u32 comb_count = 1 << flag_count;
    for (u32 c = 0; c < comb_count; c++) {
        yyjson_write_flag flg = 0;
        for (u32 f = 0; f < flag_count; f++) {
            if (c & (1 << f)) flg |= flag_arr[f];
        }
        bool allow_inf_nan = (flg & YYJSON_WRITE_ALLOW_INF_AND_NAN);
        bool inf_nan_as_null = (flg & YYJSON_WRITE_INF_AND_NAN_AS_NULL);
        bool to_float = (flg & YYJSON_WRITE_FP_TO_FLOAT) != 0;
        bool to_fixed = (flg >> (32 - YYJSON_WRITE_FP_PREC_BITS)) != 0;
        
        f64 num64 = 0.12345678901234567;
        f32 num32 = (f32)num64;
        yyjson_val val = { 0 };
        char *str;
        
        /// int
        yyjson_set_int(&val, 321);
        str = yyjson_val_write(&val, flg, NULL);
        yy_assert(get_num_type(str, false) == NUM_TYPE_UINT);
        free(str);
        
        /// float
        yyjson_set_float(&val, num32);
        str = yyjson_val_write(&val, flg, NULL);
        validate_real_output(str, &val, flg);
        free(str);
        
        /// float to fixed
        yyjson_set_float(&val, num32);
        yyjson_set_fp_to_fixed(&val, prec + 1);
        str = yyjson_val_write(&val, flg, NULL);
        validate_real_output(str, &val, flg);
        free(str);
        
        /// double
        yyjson_set_double(&val, num64);
        str = yyjson_val_write(&val, flg, NULL);
        validate_real_output(str, &val, flg);
        free(str);
        
        /// double to fixed
        yyjson_set_double(&val, num64);
        yyjson_set_fp_to_fixed(&val, prec + 1);
        str = yyjson_val_write(&val, flg, NULL);
        validate_real_output(str, &val, flg);
        free(str);
        
        /// inf
        num64 = INFINITY;
        yyjson_set_double(&val, num64);
        str = yyjson_val_write(&val, flg, NULL);
        validate_real_output(str, &val, flg);
        free(str);
        
        /// inf to fixed
        num64 = INFINITY;
        yyjson_set_double(&val, num64);
        yyjson_set_fp_to_fixed(&val, prec + 1);
        str = yyjson_val_write(&val, flg, NULL);
        validate_real_output(str, &val, flg);
        free(str);
        
        /// float inf
        num64 = 1e100;
        yyjson_set_double(&val, num64);
        str = yyjson_val_write(&val, flg, NULL);
        validate_real_output(str, &val, flg);
        free(str);
        
        /// float inf to fixed
        num64 = 1e100;
        yyjson_set_double(&val, num64);
        yyjson_set_fp_to_fixed(&val, prec + 1);
        str = yyjson_val_write(&val, flg, NULL);
        validate_real_output(str, &val, flg);
        free(str);
    }
    
    {   /// set val format
        yyjson_val val = { 0 };
        
        /// set float/double
        yyjson_set_float(&val, (float)1.25);
        yy_assert(yyjson_is_real(&val));
        yy_assert((float)yyjson_get_real(&val) == (float)1.25);
        yy_assert((val.tag >> 32) == YYJSON_WRITE_FP_TO_FLOAT);
        yyjson_set_double(&val, 1.25);
        yy_assert(yyjson_is_real(&val));
        yy_assert(yyjson_get_real(&val) == 1.25);
        yy_assert((val.tag >> 32) == 0);
        
        /// set to fixed
        yyjson_set_fp_to_fixed(&val, 12);
        yy_assert(yyjson_is_real(&val));
        yy_assert((val.tag >> 32) == YYJSON_WRITE_FP_TO_FIXED(12));
        yyjson_set_fp_to_fixed(&val, 0);
        yy_assert(yyjson_is_real(&val));
        yy_assert((val.tag >> 32) == YYJSON_WRITE_FP_TO_FIXED(0));
        
        /// set to float
        yyjson_set_fp_to_float(&val, true);
        yy_assert(yyjson_is_real(&val));
        yy_assert((val.tag >> 32) == YYJSON_WRITE_FP_TO_FLOAT);
        yyjson_set_fp_to_float(&val, false);
        yy_assert(yyjson_is_real(&val));
        yy_assert((val.tag >> 32) == 0);
    }
    {   /// set mut val format
        yyjson_mut_val val = { 0 };
        
        /// set float/double
        yyjson_mut_set_float(&val, (float)1.25);
        yy_assert(yyjson_mut_is_real(&val));
        yy_assert((float)yyjson_mut_get_real(&val) == (float)1.25);
        yy_assert((val.tag >> 32) == YYJSON_WRITE_FP_TO_FLOAT);
        yyjson_mut_set_double(&val, 1.25);
        yy_assert(yyjson_mut_is_real(&val));
        yy_assert(yyjson_mut_get_real(&val) == 1.25);
        yy_assert((val.tag >> 32) == 0);
        
        /// set to fixed
        yyjson_mut_set_fp_to_fixed(&val, 12);
        yy_assert(yyjson_mut_is_real(&val));
        yy_assert((val.tag >> 32) == YYJSON_WRITE_FP_TO_FIXED(12));
        yyjson_mut_set_fp_to_fixed(&val, 0);
        yy_assert(yyjson_mut_is_real(&val));
        yy_assert((val.tag >> 32) == YYJSON_WRITE_FP_TO_FIXED(0));
        
        /// set to float
        yyjson_mut_set_fp_to_float(&val, true);
        yy_assert(yyjson_mut_is_real(&val));
        yy_assert((val.tag >> 32) == YYJSON_WRITE_FP_TO_FLOAT);
        yyjson_mut_set_fp_to_float(&val, false);
        yy_assert(yyjson_mut_is_real(&val));
        yy_assert((val.tag >> 32) == 0);
    }
    
    /// write number
    {
        char *int_buf = malloc(21);
        char *flt_buf = malloc(40);
        char *str, *end;
        
        yyjson_val val = { 0 };
        yyjson_mut_val mval = { 0 };
        
        /// input check
        yyjson_set_int(&val, 0);
        yyjson_mut_set_int(&mval, 0);
        end = yyjson_write_number(NULL, int_buf);
        yy_assert(!end);
        end = yyjson_mut_write_number(NULL, int_buf);
        yy_assert(!end);
        end = yyjson_write_number(&val, NULL);
        yy_assert(!end);
        end = yyjson_mut_write_number(&mval, NULL);
        yy_assert(!end);
        
        /// type check
        yyjson_set_null(&val);
        yyjson_mut_set_null(&mval);
        end = yyjson_write_number(&val, int_buf);
        yy_assert(!end);
        end = yyjson_mut_write_number(&mval, int_buf);
        yy_assert(!end);
        
        /// uint
        memset(&val, 0, sizeof(val));
        yyjson_set_uint(&val, UINT64_MAX);
        str = yyjson_val_write(&val, 0, NULL);
        end = yyjson_write_number(&val, int_buf);
        yy_assert(!strcmp(str, int_buf));
        yy_assert((usize)(end - int_buf) == strlen(str));
        free(str);
        
        /// sint
        memset(&val, 0, sizeof(val));
        yyjson_set_sint(&val, INT64_MAX);
        str = yyjson_val_write(&val, 0, NULL);
        end = yyjson_write_number(&val, int_buf);
        yy_assert(!strcmp(str, int_buf));
        yy_assert((usize)(end - int_buf) == strlen(str));
        free(str);
        
        /// float
        memset(&val, 0, sizeof(val));
        yyjson_set_float(&val, 1.23456789f);
        str = yyjson_val_write(&val, 0, NULL);
        end = yyjson_write_number(&val, flt_buf);
        yy_assert(!strcmp(str, flt_buf));
        yy_assert((usize)(end - flt_buf) == strlen(str));
        free(str);
        
        /// double
        memset(&val, 0, sizeof(val));
        yyjson_set_double(&val, 1.23456789);
        str = yyjson_val_write(&val, 0, NULL);
        end = yyjson_write_number(&val, flt_buf);
        yy_assert(!strcmp(str, flt_buf));
        yy_assert((usize)(end - flt_buf) == strlen(str));
        free(str);
        
        /// fixed
        memset(&val, 0, sizeof(val));
        yyjson_set_double(&val, 1.23456789);
        yyjson_set_fp_to_fixed(&val, 2);
        str = yyjson_val_write(&val, 0, NULL);
        end = yyjson_write_number(&val, flt_buf);
        yy_assert(!strcmp(str, flt_buf));
        yy_assert((usize)(end - flt_buf) == strlen(str));
        free(str);
        
        /// extra flag bits
        memset(&val, 0, sizeof(val));
        yyjson_set_double(&val, 1.23456789);
        val.tag |= (u64)1 << (64 - 6);
        str = yyjson_val_write(&val, 0, NULL);
        end = yyjson_write_number(&val, flt_buf);
        yy_assert(!strcmp(str, flt_buf));
        yy_assert((usize)(end - flt_buf) == strlen(str));
        free(str);
        
        /// inf
        memset(&val, 0, sizeof(val));
        yyjson_set_double(&val, INFINITY);
        str = yyjson_val_write(&val, YYJSON_WRITE_ALLOW_INF_AND_NAN, NULL);
        end = yyjson_write_number(&val, flt_buf);
        if (str) {
            yy_assert(!strcmp(str, flt_buf));
            yy_assert((usize)(end - flt_buf) == strlen(str));
        } else {
            yy_assert(!end);
        }
        free(str);
        
        free(int_buf);
        free(flt_buf);
    }
}



/*==============================================================================
 * MARK: - Entry
 *============================================================================*/

static void test_number_locale(void) {
    test_read_params();
    test_read_flags();
    test_write_flags();
    test_all_files();
}

static void test_number_extra(void) {
    test_random_int();
    test_random_real();
    test_special_real();
    
#if YYJSON_TEST_ALL_FLOAT || 0
    test_all_float(); /// costs too much time, disabled for regular testing
#endif
}

yy_test_case(test_number) {
    /// change locale (decimal point is ',')
    setlocale(LC_ALL, "fr_FR");
    update_locale_decimal_point();
    test_number_locale();
    
    /// reset locale (decimal point is '.')
    setlocale(LC_ALL, "C");
    update_locale_decimal_point();
    test_number_locale();
    
    /// test some extra numbers
    test_number_extra();
}

#else
yy_test_case(test_number) {}
#endif
