/*==============================================================================
 * Make look-up tables for yyjson.
 * Copyright (C) 2020 Yaoyuan <ibireme@gmail.com>.
 *
 * Released under the MIT License:
 * https://github.com/ibireme/yyjson/blob/master/LICENSE
 *============================================================================*/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

typedef float       f32;
typedef double      f64;
typedef int8_t      i8;
typedef uint8_t     u8;
typedef int16_t     i16;
typedef uint16_t    u16;
typedef int32_t     i32;
typedef uint32_t    u32;
typedef int64_t     i64;
typedef uint64_t    u64;
typedef size_t      usize;

/*----------------------------------------------------------------------------*/

//Generate fp table with C (gmp/mpfr):
//#include <gmp.h>
//#include <mpfr.h>
//void make_pow10_sig_table(void) {
//    static const int DEF_PREC = 5000;
//    static const int BUF_LEN = 2000;
//    char buf[BUF_LEN];
//    
//    mpfr_t sigMax, sigMin, half;
//    mpfr_t pow10, pow2, div, sub;
//    mpfr_inits2(DEF_PREC, sigMax, sigMin, half, NULL);
//    mpfr_inits2(DEF_PREC, pow10, pow2, div, sub, NULL);
//    
//    mpfr_set_ui(sigMax, 0xFFFFFFFFFFFFFFFFULL, MPFR_RNDN);
//    mpfr_set_ui(sigMin, 0x8000000000000000ULL, MPFR_RNDN);
//    mpfr_set_d(half, 0.5, MPFR_RNDN);
//    
//    int e10min = -343, e10max = 324, e10step = 1;
//    
//    printf("#define POW10_SIG_TABLE_MIN_EXP %d\n", e10min);
//    printf("#define POW10_SIG_TABLE_MAX_EXP %d\n", e10max);
//    printf("#define POW10_SIG_TABLE_MIN_EXACT_EXP %d\n", 0);
//    printf("#define POW10_SIG_TABLE_MAX_EXACT_EXP %d\n", 55);
//    printf("static const u64 pow10_sig_table[] = {\n");
//    
//    for (int e10 = e10min; e10 <= e10max; e10 += e10step) {
//        mpfr_set_d(pow10, 10, MPFR_RNDN);
//        mpfr_pow_si(pow10, pow10, e10, MPFR_RNDN); // pow10 = 10^e10
//        
//        // 10^e10 = 2^e2
//        // e2 = floor(log2(pow(10, e10)))
//        // e2 = floor(log2(10) * e10)
//        int e2 = (int)floor(log2(10) * e10) - 64 + 1;
//        mpfr_set_d(pow2, 2, MPFR_RNDN);
//        mpfr_pow_si(pow2, pow2, e2, MPFR_RNDN); // pow2 = 2^e2
//        mpfr_div(div, pow10, pow2, MPFR_RNDN); // div = pow10 / pow2;
//        if (mpfr_cmp(div, sigMin) < 0 || mpfr_cmp(div, sigMax) > 0) {
//            printf("err!\n"); // make sure the highest bit is 1 (normalized)
//        }
//        
//        mpfr_set_d(pow2, 2, MPFR_RNDN);
//        mpfr_pow_si(pow2, pow2, e2, MPFR_RNDN); // pow2 = 2^e2
//        mpfr_div(div, pow10, pow2, MPFR_RNDN); // div = pow10 / pow2;
//        
//        mpfr_snprintf(buf, BUF_LEN, "%.1000Rg", div);
//        u64 val = strtoull(buf, NULL, 0);
//        mpfr_sub_ui(sub, div, val, MPFR_RNDN); // sub = div - (uint64_t)div
//        int cmp = mpfr_cmp(sub, half);
//        if (cmp == 0) printf("err!\n"); // avoid round to even
//        if (cmp > 0 && val == UINT64_MAX) printf("err!\n"); // avoid round up overflow
//        
//        printf("    ");
//        printf("U64(0x%.8X, 0x%.8X),", (u32)(val >> 32), (u32)val);
//        
//        mpfr_set_d(pow2, 2, MPFR_RNDN);
//        mpfr_pow_si(pow2, pow2, 64, MPFR_RNDN); // pow2 = 2^64
//        mpfr_mul(sub, sub, pow2, MPFR_RNDN); // sub *= 2^64
//        
//        mpfr_snprintf(buf, BUF_LEN, "%.1000Rg", sub);
//        u64 val2 = strtoull(buf, NULL, 0);
//        mpfr_sub_ui(sub, sub, val2, MPFR_RNDN); // sub -= (uint64_t)sub
//        int cmp2 = mpfr_cmp(sub, half);
//        if (cmp2 == 0) printf("err!\n"); // avoid round to even
//        if ((cmp > 0) && (val2 < ((u64)1) << 63)) printf("err!\n"); // avoid round up overflow
//        bool is_exact = mpfr_cmp_ui(sub, 0) == 0;
//        
//        printf(" ");
//        printf("U64(0x%.8X, 0x%.8X)", (u32)(val2 >> 32), (u32)val2);
//        printf("%c", e10 < e10max ? ',' : ' ');
//        printf(" /* %s 10^%d */", is_exact ? "==" : "~=", e10);
//        printf("\n");
//    }
//    
//    printf("};\n");
//    printf("\n");
//    
//    mpfr_clears(sigMax, sigMin, half, NULL);
//    mpfr_clears(pow10, pow2, div, sub, NULL);
//}



//Generate fp table with Python:
//import decimal
//from decimal import Decimal
//
//POW10_SIG_TABLE_MIN_EXP = -343
//POW10_SIG_TABLE_MAX_EXP =  324
//POW10_SIG_TABLE_MIN_EXACT_EXP = 0
//POW10_SIG_TABLE_MAX_EXACT_EXP = 55
//
//
//def calc_pow10_u128(p: int) -> int:
//    """
//    Calculate the power of 10 and return the high 128 bits of the result.
//    """
//    
//    # Calculate 10^p with high precision
//    decimal.getcontext().prec = 5000
//    sig = Decimal(10) ** p
//
//    # Normalize the sig to range [0.5,1)
//    while sig < 1:
//        sig *= 2
//    while sig >= 1:
//        sig /= 2
//
//    # Calculate the highest 128 bits of the sig
//    all = sig * (2 ** 128)
//    top = int(all)
//    return top
//
//
//def is_pow10_u128_exact(p: int) -> bool:
//    """
//    Check if calc_pow10_u128(p) is exact value.
//    """
//    
//    # Calculate 10^p with high precision
//    decimal.getcontext().prec = 5000
//    sig = Decimal(10) ** p
//
//    # Normalize the sig to range [0.5,1)
//    while sig < 1:
//        sig *= 2
//    while sig >= 1:
//        sig /= 2
//
//    # Calculate the highest 128 bits of the sig
//    all = sig * (2 ** 128)
//    top = int(all)
//    return top == all
//
//
//def print_pow10_u128_table():
//    """
//    Print the power of 10 table for yy_strtod() and yy_dtoa().
//    """
//    print(f"#define POW10_SIG_TABLE_MIN_EXP {POW10_SIG_TABLE_MIN_EXP}")
//    print(f"#define POW10_SIG_TABLE_MAX_EXP {POW10_SIG_TABLE_MAX_EXP}")
//    print(f"#define POW10_SIG_TABLE_MIN_EXACT_EXP {POW10_SIG_TABLE_MIN_EXACT_EXP}")
//    print(f"#define POW10_SIG_TABLE_MAX_EXACT_EXP {POW10_SIG_TABLE_MAX_EXACT_EXP}")
//    print("static const u64 pow10_sig_table[] = {")
//    for p in range(POW10_SIG_TABLE_MIN_EXP, POW10_SIG_TABLE_MAX_EXP + 1):
//        is_exact = is_pow10_u128_exact(p)
//        assert is_exact == (p in range(POW10_SIG_TABLE_MIN_EXACT_EXP, POW10_SIG_TABLE_MAX_EXACT_EXP + 1))
//
//        c = calc_pow10_u128(p)
//        s = f"{c:X}"
//        line = f"    U64(0x{s[0:8]}, 0x{s[8:16]}), U64(0x{s[16:24]}, 0x{s[24:32]})"
//        if is_exact:
//            line += f", /* == 10^{p} */"
//        elif p == POW10_SIG_TABLE_MAX_EXP:
//            line += f"  /* ~= 10^{p} */"
//        else:
//            line += f", /* ~= 10^{p} */"
//        print(line)
//    print("};")
//
//
//if __name__ == "__main__":
//    print_pow10_u128_table()



/*----------------------------------------------------------------------------*/

static void make_dec_trailing_zero_table(void) {
    int table_len = 100;
    int line_len = 10;
    
    printf("static const u8 dec_trailing_zero_table[] = {\n");
    for (int i = 0; i < table_len; i++) {        
        int tz = 0;
        if (i == 0) tz = 2;
        else {
            if ((i % 10) == 0) tz++;
        }
        
        bool is_head = ((i % line_len) == 0);
        bool is_tail = ((i % line_len) == line_len - 1);
        bool is_last = i + 1 == table_len;
        
        if (is_head) printf("    ");
        
        printf("%1d", tz);
        
        if (i + 1 < table_len) printf(",");
        if (!is_tail && !is_last) printf(" "); else printf("\n");
    }
    printf("};\n");
    printf("\n");
}

/*----------------------------------------------------------------------------*/

/* char_table1 */
#define CHAR_TYPE_ASCII     (1 << 0) /* Except: ["\], [0x00-0x1F, 0x80-0xFF] */
#define CHAR_TYPE_ASCII_SQ  (1 << 1) /* Except: ['\], [0x00-0x1F, 0x80-0xFF] */
#define CHAR_TYPE_SPACE     (1 << 2) /* Whitespace: [ \t\n\r] */
#define CHAR_TYPE_SPACE_EXT (1 << 3) /* Whitespace: [ \t\n\r\v\f], JSON5 */
#define CHAR_TYPE_NUM       (1 << 4) /* Number: [.-+0-9] */
#define CHAR_TYPE_COMMENT   (1 << 5) /* Comment: [/] */

/* char_table2 */
#define CHAR_TYPE_EOL       (1 << 0) /* End of line: [\r\n] */
#define CHAR_TYPE_EOL_EXT   (1 << 1) /* End of line: [\r\n], JSON5 */
#define CHAR_TYPE_ID_START  (1 << 2) /* ID start: [_$A-Za-z\], U+0080+ */
#define CHAR_TYPE_ID_NEXT   (1 << 3) /* ID next: [_$A-Za-z0-9\], U+0080+ */
#define CHAR_TYPE_ID_ASCII  (1 << 4) /* ID next ASCII: [_$A-Za-z0-9] */

/* char_table3 */
#define CHAR_TYPE_SIGN      (1 << 0) /* [-+] */
#define CHAR_TYPE_DIGIT     (1 << 1) /* [0-9] */
#define CHAR_TYPE_NONZERO   (1 << 2) /* [1-9] */
#define CHAR_TYPE_EXP       (1 << 3) /* [eE] */
#define CHAR_TYPE_DOT       (1 << 4) /* [.] */

static void print_char_table(u8 *table, const char *name) {
    int table_len = 256;
    int line_len = 8;
    
    printf("static const u8 %s[256] = {\n", name);
    for (int i = 0; i < table_len; i++) {
        bool is_head = ((i % line_len) == 0);
        bool is_tail = ((i % line_len) == line_len - 1);
        bool is_last = i + 1 == table_len;
        
        if (is_head) printf("    ");
        printf("0x%.2X", table[i]);
        if (i + 1 < table_len) printf(",");
        if (!is_tail && !is_last) printf(" "); else printf("\n");
    }
    printf("};\n");
    printf("\n");
}

static void make_char_table(void) {
    u8 table[256];
    
    // ------------- table1 -------------
    memset(table, 0, sizeof(table));
    
    for (int i = 0; i <= 0xFF; i++) {
        table[i] |= (CHAR_TYPE_ASCII | CHAR_TYPE_ASCII_SQ);
    }
    table['\"'] &= ~(u8)(CHAR_TYPE_ASCII);     // double quote
    table['\''] &= ~(u8)(CHAR_TYPE_ASCII_SQ);  // single quote
    table['\\'] &= ~(u8)(CHAR_TYPE_ASCII | CHAR_TYPE_ASCII_SQ);
    for (int i = 0x00; i <= 0x1F; i++) {
        table[i] &= ~(u8)(CHAR_TYPE_ASCII | CHAR_TYPE_ASCII_SQ);
    }
    for (int i = 0x80; i <= 0xFF; i++) {
        table[i] &= ~(u8)(CHAR_TYPE_ASCII | CHAR_TYPE_ASCII_SQ);
    }
    
    table[' ']  |= (CHAR_TYPE_SPACE | CHAR_TYPE_SPACE_EXT);
    table['\t'] |= (CHAR_TYPE_SPACE | CHAR_TYPE_SPACE_EXT);
    table['\n'] |= (CHAR_TYPE_SPACE | CHAR_TYPE_SPACE_EXT);
    table['\r'] |= (CHAR_TYPE_SPACE | CHAR_TYPE_SPACE_EXT);
    table['\v'] |= CHAR_TYPE_SPACE_EXT;
    table['\f'] |= CHAR_TYPE_SPACE_EXT;
    table[0xC2] |= CHAR_TYPE_SPACE_EXT; // U+00a0  [C2 A0]    non-breaking space
    table[0xE1] |= CHAR_TYPE_SPACE_EXT; // U+1680  [E1 9A 80] ogham space mark
    table[0xE2] |= CHAR_TYPE_SPACE_EXT; // U+2000+ [E2 XX XX] unicode 'Zs' category
    table[0xE3] |= CHAR_TYPE_SPACE_EXT; // U+3000  [E3 80 80] ideographical space
    table[0xEF] |= CHAR_TYPE_SPACE_EXT; // U+FEFF  [EF BB BF] byte order mark
    table['.'] |= CHAR_TYPE_NUM;
    table['-'] |= CHAR_TYPE_NUM;
    table['+'] |= CHAR_TYPE_NUM;
    for (int i = '0'; i <= '9'; i++) {
        table[i] |= CHAR_TYPE_NUM;
    }
    
    table['/'] |= CHAR_TYPE_COMMENT;
    print_char_table(table, "char_table1");
    
    
    // ------------- table2 -------------
    memset(table, 0, sizeof(table));
    table['\r'] |= (CHAR_TYPE_EOL | CHAR_TYPE_EOL_EXT);
    table['\n'] |= (CHAR_TYPE_EOL | CHAR_TYPE_EOL_EXT);
    table[0xE2] |= CHAR_TYPE_EOL_EXT; // <LS> U+2028 [E2 80 A8], <PS> U+2029 [E2 80 A9]
    table['_'] |= (CHAR_TYPE_ID_START | CHAR_TYPE_ID_NEXT | CHAR_TYPE_ID_ASCII);
    table['$'] |= (CHAR_TYPE_ID_START | CHAR_TYPE_ID_NEXT | CHAR_TYPE_ID_ASCII);
    table['\\'] |= (CHAR_TYPE_ID_START | CHAR_TYPE_ID_NEXT);
    for (int i = 'A'; i <= 'Z'; i++) {
        table[i] |= (CHAR_TYPE_ID_START | CHAR_TYPE_ID_NEXT | CHAR_TYPE_ID_ASCII);
    }
    for (int i = 'a'; i <= 'z'; i++) {
        table[i] |= (CHAR_TYPE_ID_START | CHAR_TYPE_ID_NEXT | CHAR_TYPE_ID_ASCII);
    }
    for (int i = '0'; i <= '9'; i++) {
        table[i] |= (CHAR_TYPE_ID_NEXT | CHAR_TYPE_ID_ASCII);
    }
    for (int i = 0x80; i <= 0xFF; i++) {
        table[i] |= (CHAR_TYPE_ID_START | CHAR_TYPE_ID_NEXT);
    }
    print_char_table(table, "char_table2");
    
    
    // ------------- table3 -------------
    memset(table, 0, sizeof(table));
    table['-'] |= CHAR_TYPE_SIGN;
    table['+'] |= CHAR_TYPE_SIGN;
    table['e'] |= CHAR_TYPE_EXP;
    table['E'] |= CHAR_TYPE_EXP;
    table['.'] |= CHAR_TYPE_DOT;
    for (int i = '0'; i <= '9'; i++) {
        table[i] |= CHAR_TYPE_DIGIT;
    }
    for (int i = '1'; i <= '9'; i++) {
        table[i] |= CHAR_TYPE_NONZERO;
    }
    print_char_table(table, "char_table3");
}


/*----------------------------------------------------------------------------*/

static void make_hex_conv_table(void) {
    u8 table[256] = {0};
    
    for (int i = 0; i < 256; i++) {
        if ('0' <= i && i <= '9') {
            table[i] = (u8)(i - '0');
        } else if ('a' <= i && i <= 'f') {
            table[i] = (u8)(0xA + i - 'a');
        } else if ('A' <= i && i <= 'F') {
            table[i] = (u8)(0xA + i - 'A');
        } else {
            table[i] = 0xF0;
        }
    }
    
    int table_len = 256;
    int line_len = 8;
    printf("static const u8 hex_conv_table[256] = {\n");
    for (int i = 0; i < table_len; i++) {
        bool is_head = ((i % line_len) == 0);
        bool is_tail = ((i % line_len) == line_len - 1);
        bool is_last = i + 1 == table_len;
        
        if (is_head) printf("    ");
        printf("0x%.2X", table[i]);
        if (i + 1 < table_len) printf(",");
        if (!is_tail && !is_last) printf(" "); else printf("\n");
    }
    printf("};\n");
    printf("\n");
}

/*----------------------------------------------------------------------------*/

static void make_u64_pow10_table(void) {
    int table_len = 20;
    int line_len = 2;
    
    printf("static const u64 u64_pow10_table[U64_POW10_MAX_EXP + 1] = {\n");
    for (int i = 0; i < table_len; i++) {
        bool is_head = ((i % line_len) == 0);
        bool is_tail = ((i % line_len) == line_len - 1);
        bool is_last = i + 1 == table_len;
        
        u64 num = 1;
        for (int e = 0; e < i; e++) num *= 10;
        
        if (is_head) printf("    ");
        printf("U64(0x%.8X, 0x%.8X)", (u32)(num >> 32), (u32)(num));
        if (i + 1 < table_len) printf(",");
        if (!is_tail && !is_last) printf(" "); else printf("\n");
    }
    printf("};\n");
    printf("\n");
}

/*----------------------------------------------------------------------------*/

/** Character encode type, if (type > CHAR_ENC_ERR_1) bytes = type / 2; */
#define CHAR_ENC_CPY_1  0 /* 1-byte UTF-8, copy. */
#define CHAR_ENC_ERR_1  1 /* 1-byte UTF-8, error. */
#define CHAR_ENC_ESC_A  2 /* 1-byte ASCII, escaped as '\x'. */
#define CHAR_ENC_ESC_1  3 /* 1-byte UTF-8, escaped as '\uXXXX'. */
#define CHAR_ENC_CPY_2  4 /* 2-byte UTF-8, copy. */
#define CHAR_ENC_ESC_2  5 /* 2-byte UTF-8, escaped as '\uXXXX'. */
#define CHAR_ENC_CPY_3  6 /* 3-byte UTF-8, copy. */
#define CHAR_ENC_ESC_3  7 /* 3-byte UTF-8, escaped as '\uXXXX'. */
#define CHAR_ENC_CPY_4  8 /* 4-byte UTF-8, copy. */
#define CHAR_ENC_ESC_4  9 /* 4-byte UTF-8, escaped as '\uXXXX\uXXXX'. */

static void make_enc_table_one(const char *name, u8 *table,
                               int table_len, int line_len) {
    printf("static const char_enc_type %s[%d] = {\n", name, table_len);
    for (int i = 0; i < table_len; i++) {
        bool is_head = ((i % line_len) == 0);
        bool is_tail = ((i % line_len) == line_len - 1);
        bool is_last = i + 1 == table_len;
        
        if (is_head) printf("    ");
        printf("%d", table[i]);
        if (i + 1 < table_len) printf(",");
        if (!is_tail && !is_last) printf(" "); else printf("\n");
    }
    printf("};\n");
    printf("\n");
}

static void make_enc_table(void) {
    u8 table[256];
    int table_len = 256;
    int line_len = 16;
    
    // ASCII: copy or escape
    for (int i = 0; i <= 0x80; i++) {
        if (i == '\b') table[i] = CHAR_ENC_ESC_A; else
        if (i == '\t') table[i] = CHAR_ENC_ESC_A; else
        if (i == '\n') table[i] = CHAR_ENC_ESC_A; else
        if (i == '\f') table[i] = CHAR_ENC_ESC_A; else
        if (i == '\r') table[i] = CHAR_ENC_ESC_A; else
        if (i == '\\') table[i] = CHAR_ENC_ESC_A; else
        if (i ==  '"') table[i] = CHAR_ENC_ESC_A; else
        if (i <= 0x1F) table[i] = CHAR_ENC_ESC_1; else
                       table[i] = CHAR_ENC_CPY_1;
    }
    
    // Unicode: copy, do not escape
    for (int i = 0x80; i <= 0xFF; i++) {
        if ((i & 0xE0) == 0xC0) table[i] = CHAR_ENC_CPY_2; else
        if ((i & 0xF0) == 0xE0) table[i] = CHAR_ENC_CPY_3; else
        if ((i & 0xF8) == 0xF0) table[i] = CHAR_ENC_CPY_4; else
                                table[i] = CHAR_ENC_ERR_1;
    }
    table['/'] = CHAR_ENC_CPY_1;
    make_enc_table_one("enc_table_cpy", table, table_len, line_len);
    table['/'] = CHAR_ENC_ESC_A;
    make_enc_table_one("enc_table_cpy_slash", table, table_len, line_len);
    
    // Unicode: escape
    for (int i = 0x80; i <= 0xFF; i++) {
        if ((i & 0xE0) == 0xC0) table[i] = CHAR_ENC_ESC_2; else
        if ((i & 0xF0) == 0xE0) table[i] = CHAR_ENC_ESC_3; else
        if ((i & 0xF8) == 0xF0) table[i] = CHAR_ENC_ESC_4; else
                                table[i] = CHAR_ENC_ERR_1;
    }
    table['/'] = CHAR_ENC_CPY_1;
    make_enc_table_one("enc_table_esc", table, table_len, line_len);
    table['/'] = CHAR_ENC_ESC_A;
    make_enc_table_one("enc_table_esc_slash", table, table_len, line_len);
}

/*----------------------------------------------------------------------------*/

static void make_esc_hex_char_table(void) {
    int table_len = 512;
    int line_len = 8;
    
    printf("static const u8 esc_hex_char_table[512] = {\n");
    for (int i = 0; i < table_len; i++) {
        bool is_head = ((i % line_len) == 0);
        bool is_tail = ((i % line_len) == line_len - 1);
        bool is_last = i + 1 == table_len;
        
        if (is_head) printf("    ");
        
        char buf[16];
        sprintf(buf, "%.2X", i / 2);
        printf("'%c'", buf[i % 2]);
        
        if (i + 1 < table_len) printf(",");
        if (!is_tail && !is_last) printf(" "); else printf("\n");
    }
    printf("};\n");
    printf("\n");
}

/*----------------------------------------------------------------------------*/

static void make_esc_single_char_table(void) {
    u8 table[512];
    int table_len = 512;
    int line_len = 8;
    
    memset(table, ' ', 512);
    table['\b' * 2 + 0] = '\\';
    table['\b' * 2 + 1] = 'b';
    
    table['\t' * 2 + 0] = '\\';
    table['\t' * 2 + 1] = 't';
    
    table['\n' * 2 + 0] = '\\';
    table['\n' * 2 + 1] = 'n';
    
    table['\f' * 2 + 0] = '\\';
    table['\f' * 2 + 1] = 'f';
    
    table['\r' * 2 + 0] = '\\';
    table['\r' * 2 + 1] = 'r';
    
    table['\\' * 2 + 0] = '\\';
    table['\\' * 2 + 1] = '\\';
    
    table['/' * 2 + 0] = '\\';
    table['/' * 2 + 1] = '/';
    
    table['"' * 2 + 0] = '\\';
    table['"' * 2 + 1] = '"';
    
    printf("static const u8 esc_single_char_table[512] = {\n");
    for (int i = 0; i < table_len; i++) {
        bool is_head = ((i % line_len) == 0);
        bool is_tail = ((i % line_len) == line_len - 1);
        bool is_last = i + 1 == table_len;
        
        if (is_head) printf("    ");
        
        if (table[i] == '\\') printf("'\\\\'");
        else printf("'%c'", table[i]);
        
        if (i + 1 < table_len) printf(",");
        if (!is_tail && !is_last) printf(" "); else printf("\n");
    }
    printf("};\n");
    printf("\n");
}

int main(void) {
    make_dec_trailing_zero_table();
    make_char_table();
    make_hex_conv_table();
    make_u64_pow10_table();
    make_enc_table();
    make_esc_hex_char_table();
    make_esc_single_char_table();
    return 0;
}
