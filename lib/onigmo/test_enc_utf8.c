#include "config.h"
#ifdef ONIG_ESCAPE_UCHAR_COLLISION
#undef ONIG_ESCAPE_UCHAR_COLLISION
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "onigmo.h"

/* #define USE_UTF8_31BITS */

#define SLEN(s)  strlen(s)

static int nsucc  = 0;
static int nfail  = 0;
static int nerror = 0;

static FILE* err_file;

static OnigRegion* region;

static void xx(char* pattern, char* str, int from, int to, int mem, int not)
{
  int r;

  regex_t* reg;
  OnigErrorInfo einfo;
  OnigSyntaxType syn = *ONIG_SYNTAX_DEFAULT;

  r = onig_new(&reg, (UChar* )pattern, (UChar* )(pattern + SLEN(pattern)),
	       ONIG_OPTION_NONE, ONIG_ENCODING_UTF8, &syn, &einfo);
  if (r) {
    char s[ONIG_MAX_ERROR_MESSAGE_LEN];
    onig_error_code_to_str((UChar* )s, r, &einfo);
    fprintf(err_file, "ERROR: %s\n", s);
    nerror++;
    return ;
  }

  r = onig_search(reg, (UChar* )str, (UChar* )(str + SLEN(str)),
		  (UChar* )str, (UChar* )(str + SLEN(str)),
		  region, ONIG_OPTION_NONE);
  if (r < ONIG_MISMATCH) {
    char s[ONIG_MAX_ERROR_MESSAGE_LEN];
    onig_error_code_to_str((UChar* )s, r);
    fprintf(err_file, "ERROR: %s\n", s);
    nerror++;
    return ;
  }

  if (r == ONIG_MISMATCH) {
    if (not) {
      fprintf(stdout, "OK(N): /%s/ '%s'\n", pattern, str);
      nsucc++;
    }
    else {
      fprintf(stdout, "FAIL: /%s/ '%s'\n", pattern, str);
      nfail++;
    }
  }
  else {
    if (not) {
      fprintf(stdout, "FAIL(N): /%s/ '%s'\n", pattern, str);
      nfail++;
    }
    else {
      if (region->beg[mem] == from && region->end[mem] == to) {
        fprintf(stdout, "OK: /%s/ '%s'\n", pattern, str);
        nsucc++;
      }
      else {
        fprintf(stdout, "FAIL: /%s/ '%s' %d-%d : %d-%d\n", pattern, str,
	        (int)from, (int)to, (int)region->beg[mem], (int)region->end[mem]);
        nfail++;
      }
    }
  }
  onig_free(reg);
}

static void x2(char* pattern, char* str, int from, int to)
{
  xx(pattern, str, from, to, 0, 0);
}

#if 0
static void x3(char* pattern, char* str, int from, int to, int mem)
{
  xx(pattern, str, from, to, mem, 0);
}

static void n(char* pattern, char* str)
{
  xx(pattern, str, 0, 0, 0, 1);
}
#endif

const OnigEncodingType * target_encoding = ONIG_ENCODING_UTF8;

static void test_mbc_enc_len(const char * str, int expect) {
  const OnigEncodingType * enc = target_encoding;
  size_t len = strlen(str);
  int actual = ONIGENC_PRECISE_MBC_ENC_LEN(enc, (const UChar *)str, (const UChar *)str + len);
  if (actual == expect) {
    fprintf(stdout, "OK: mbc_enc_len(%s)=%d\n", str, expect);
    nsucc++;
  } else {
    fprintf(stdout, "FAIL: mbc_enc_len(%s)=%d\n", str, expect);
    nfail++;
  }
}

static void test_code_to_mbclen(OnigCodePoint code, int expect) {
  const OnigEncodingType * enc = target_encoding;
  int actual = ONIGENC_CODE_TO_MBCLEN(enc, code);
  if (actual == expect) {
    fprintf(stdout, "OK: code_to_mbclen(U+%04X)=%d\n", code, expect);
    nsucc++;
  } else {
    fprintf(stdout, "FAIL: code_to_mbclen(U+%04X)=%d\n", code, expect);
    nfail++;
  }
}

static void test_mbc_to_code(const char * str, int expect) {
  const OnigEncodingType * enc = target_encoding;
  size_t len = strlen(str);
  int actual = ONIGENC_MBC_TO_CODE(enc, (const UChar *)str, (const UChar *)str + len);
  if (actual == expect) {
    fprintf(stdout, "OK: mbc_to_code(%s)=U+%04X\n", str, expect);
    nsucc++;
  } else {
    fprintf(stdout, "FAIL: mbc_to_code(%s)=U+%04X\n", str, expect);
    nfail++;
  }
}

static void test_code_to_mbc(OnigCodePoint code, const char * expect, int exp_error) {
  const OnigEncodingType * enc = target_encoding;
  UChar * buf = (UChar *)malloc(ONIGENC_MBC_MAXLEN(enc) + 1);
  int len = ONIGENC_CODE_TO_MBC(enc, code, buf);
  if (len < 0) {
    int err = len;
    if (err == exp_error) {
      fprintf(stdout, "OK: code_to_mbc(U+%04X)=(error %d)\n", code, len);
      nsucc++;
    } else {
      fprintf(stdout, "FAIL: code_to_mbc(U+%04X)=(error %d)\n", code, len);
      nfail++;
    }
    goto exit;
  }

  buf[len] = '\0';
  if (strcmp((const char *)buf, expect) == 0) {
    fprintf(stdout, "OK: code_to_mbc(U+%04X)=%s\n", code, expect);
    nsucc++;
  } else {
    fprintf(stdout, "FAIL: code_to_mbc(U+%04X)=%s\n", code, expect);
    nfail++;
  }

exit:
  free(buf);
}

extern int main(int argc, char* argv[])
{
  err_file = stdout;

  region = onig_region_new();

  test_mbc_enc_len("\xC2\x80", 2);            // S0, S1, A
  test_code_to_mbclen(0x0080, 2);
  test_code_to_mbc(0x0080, "\xC2\x80", 0);
  x2("\\x{0080}", "\xC2\x80", 0, 2);
  x2("\xC2\x80", "\xC2\x80", 0, 2);           // min 2 bytes

  test_mbc_enc_len("\xC2\xC0", -1);           // S0, S1, F

  test_mbc_enc_len("\xDF\xBF", 2);            // S0, S1, A
  test_code_to_mbclen(0x07FF, 2);
  test_code_to_mbc(0x07FF, "\xDF\xBF", 0);
  x2("\\x{07FF}", "\xDF\xBF", 0, 2);
  x2("\xDF\xBF", "\xDF\xBF", 0, 2);           // max 2 bytes

  test_mbc_enc_len("\xE0\xA0\x80", 3);        // S0, S2, S1, A
  test_code_to_mbclen(0x0800, 3);
  test_code_to_mbc(0x0800, "\xE0\xA0\x80", 0);
  x2("\xE0\xA0\x80", "\xE0\xA0\x80", 0, 3);
  x2("\\x{0800}", "\xE0\xA0\x80", 0, 3);      // min 3 bytes

  test_mbc_enc_len("\xE0\xC0\x80", -1);       // S0, S2, F

  test_mbc_enc_len("\xEF\xBF\xBF", 3);        // S0, S3, S1, A
  test_code_to_mbclen(0xFFFF, 3);
  test_code_to_mbc(0xFFFF, "\xEF\xBF\xBF", 0);
  x2("\xEF\xBF\xBF", "\xEF\xBF\xBF", 0, 3);
  x2("\\x{FFFF}", "\xEF\xBF\xBF", 0, 3);      // max 3 bytes

  test_mbc_enc_len("\xEF\xC0\xBF", -1);       // S0, S3, F

  test_mbc_enc_len("\xED\x80\x80", 3);        // S0, S4, S1, A
  test_code_to_mbclen(0xD000, 3);
  test_code_to_mbc(0xD000, "\xED\x80\x80", 0);
  x2("\xED\x80\x80", "\xED\x80\x80", 0, 3);
  x2("\\x{D000}", "\xED\x80\x80", 0, 3);

  test_mbc_enc_len("\xED\xA0\xA0", -1);       // S0, S4, F

  test_mbc_enc_len("\xF0\x90\x80\x80", 4);    // S0, S5, S3, S1, A
  test_code_to_mbclen(0x00010000, 4);
  test_code_to_mbc(0x00010000, "\xF0\x90\x80\x80", 0);
  x2("\xF0\x90\x80\x80", "\xF0\x90\x80\x80", 0, 4);
  x2("\\x{00010000}", "\xF0\x90\x80\x80", 0, 4); // min 4 bytes

  test_mbc_enc_len("\xF0\x80\x80\x80", -1);   // S0, S5, F

  test_mbc_enc_len("\xF4\x8F\xBF\xBF", 4);    // S0, S7, S3, S1, A
  test_code_to_mbclen(0x0010FFFF, 4);
  test_code_to_mbc(0x0010FFFF, "\xF4\x8F\xBF\xBF", 0);
  x2("\xF4\x8F\xBF\xBF", "\xF4\x8F\xBF\xBF", 0, 4);
  x2("\\x{0010FFFF}", "\xF4\x8F\xBF\xBF", 0, 4); // max Unicode

#ifndef USE_UTF8_31BITS
  test_mbc_enc_len("\xF7\xBF\xBF\xBF", -1);           // S0, F
#else
  test_mbc_enc_len("\xF7\xBF\xBF\xBF", 4);            // S0, S6, S3, S1, A
  test_code_to_mbclen(0x001FFFFF, 4);
  test_code_to_mbc(0x001FFFFF, "\xF7\xBF\xBF\xBF", 0);
  x2("\xF7\xBF\xBF\xBF", "\xF7\xBF\xBF\xBF", 0, 4);
  x2("\\x{001FFFFF}", "\xF7\xBF\xBF\xBF", 0, 4);      // max 4 bytes (21bits)

  test_mbc_enc_len("\xF7\xC0\xBF\xBF", -1);           // S0, S6, F

  test_mbc_enc_len("\xF8\x88\x80\x80\x80", 5);        // S0, S8, S6, S3, S1, A
  test_code_to_mbclen(0x00200000, 5);
  test_code_to_mbc(0x00200000, "\xF8\x88\x80\x80\x80", 0);
  x2("\xF8\x88\x80\x80\x80", "\xF8\x88\x80\x80\x80", 0, 5);
  x2("\\x{00200000}", "\xF8\x88\x80\x80\x80", 0, 5);  // min 5 bytes

  test_mbc_enc_len("\xF8\x80\x80\x80\x80", -1);       // S0, S8, F

  test_mbc_enc_len("\xFB\xBF\xBF\xBF\xBF", 5);        // S0, S9, S6, S3, S1, A
  test_code_to_mbclen(0x03FFFFFF, 5);
  test_code_to_mbc(0x03FFFFFF, "\xFB\xBF\xBF\xBF\xBF", 0);
  x2("\xFB\xBF\xBF\xBF\xBF", "\xFB\xBF\xBF\xBF\xBF", 0, 5);
  x2("\\x{03FFFFFF}", "\xFB\xBF\xBF\xBF\xBF", 0, 5);  // max 5 bytes

  test_mbc_enc_len("\xFB\xC0\xBF\xBF\xBF", -1);       // S0, S9, F

  test_mbc_enc_len("\xFC\x84\x80\x80\x80\x80", 6);    // S0, S10, S9, S6, S3, S1, A
  test_code_to_mbclen(0x04000000, 6);
  test_code_to_mbc(0x04000000, "\xFC\x84\x80\x80\x80\x80", 0);
  x2("\xFC\x84\x80\x80\x80\x80", "\xFC\x84\x80\x80\x80\x80", 0, 6);
  x2("\\x{04000000}", "\xFC\x84\x80\x80\x80\x80", 0, 6); // min 6 bytes

  test_mbc_enc_len("\xFC\x80\x80\x80\x80\x80", -1);   // S0, S10, F

  test_mbc_enc_len("\xFD\xBF\xBF\xBF\xBF\xBF", 6);    // S0, S11, S9, S6, S3, S1, A
  test_code_to_mbclen(0x7FFFFFFF, 6);
  test_code_to_mbc(0x7FFFFFFF, "\xFD\xBF\xBF\xBF\xBF\xBF", 0);
  x2("\xFD\xBF\xBF\xBF\xBF\xBF", "\xFD\xBF\xBF\xBF\xBF\xBF", 0, 6);
  x2("\\x{7FFFFFFF}", "\xFD\xBF\xBF\xBF\xBF\xBF", 0, 6); // max 6 bytes

  test_mbc_enc_len("\xFD\xC0\xBF\xBF\xBF\xBF", -1);   // S0, S11, F

  test_code_to_mbclen(0x80000000, ONIGERR_TOO_BIG_WIDE_CHAR_VALUE);
  test_code_to_mbc(0x80000000, "", ONIGERR_TOO_BIG_WIDE_CHAR_VALUE);
  test_code_to_mbclen(0xFFFFFFFD, ONIGERR_TOO_BIG_WIDE_CHAR_VALUE);
  test_code_to_mbc(0xFFFFFFFD, "", ONIGERR_TOO_BIG_WIDE_CHAR_VALUE);
  test_code_to_mbclen(0xFFFFFFFE, 1);
  test_code_to_mbc(0xFFFFFFFE, "\xFE", 0);
  test_code_to_mbclen(0xFFFFFFFF, 1);
  test_code_to_mbc(0xFFFFFFFF, "\xFF", 0);
#endif

  test_mbc_to_code("\xFE", 0xFFFFFFFE);
  test_mbc_to_code("\xFF", 0xFFFFFFFF);

  fprintf(stdout,
       "\nRESULT   SUCC: %d,  FAIL: %d,  ERROR: %d      (by Onigmo %s)\n",
       nsucc, nfail, nerror, onig_version());

  onig_region_free(region, 1);
  onig_end();

  return ((nfail == 0 && nerror == 0) ? 0 : -1);
}
