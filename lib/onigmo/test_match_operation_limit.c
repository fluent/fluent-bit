#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "onigmo.h"

#ifndef DEFAULT_MATCH_OPERATION_LIMIT
# define DEFAULT_MATCH_OPERATION_LIMIT 0
#endif

static int
check(const char* pattern, const char* text, unsigned long limit,
      int backward, int match, OnigPosition expected)
{
  regex_t* reg;
  OnigRegion* region;
  OnigErrorInfo error;
  const UChar* str = (const UChar*)text;
  const UChar* end = str + strlen(text);
  OnigPosition result;
  int failed;

  if (onig_new(&reg, (const UChar*)pattern,
               (const UChar*)pattern + strlen(pattern), ONIG_OPTION_DEFAULT,
               ONIG_ENCODING_UTF8, ONIG_SYNTAX_RUBY, &error) != ONIG_NORMAL) {
    return 1;
  }
  region = onig_region_new();
  onig_set_match_operation_limit(limit);
  if (match) {
    result = onig_match(reg, str, end, str, region, ONIG_OPTION_NONE);
  }
  else {
    result = onig_search(reg, str, end, backward ? end : str,
                         backward ? str : end, region, ONIG_OPTION_NONE);
  }
  failed = result != expected;
  if (failed) {
    fprintf(stderr, "%s: limit=%lu backward=%d match=%d expected=%ld got=%ld\n",
            pattern, limit, backward, match, (long)expected, (long)result);
  }
  onig_region_free(region, 1);
  onig_free(reg);
  return failed;
}

/* A cache must not change the final capture of a nullable repeated group. */
static int
check_nullable_capture(void)
{
  const char* pattern = "((a|b|)*)*b|a+!";
  const char* text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab";
  regex_t* reg;
  OnigRegion* region;
  OnigErrorInfo error;
  const UChar* str = (const UChar*)text;
  const UChar* end = str + strlen(text);
  OnigPosition result;
  int failed;

  if (onig_new(&reg, (const UChar*)pattern,
               (const UChar*)pattern + strlen(pattern), ONIG_OPTION_DEFAULT,
               ONIG_ENCODING_UTF8, ONIG_SYNTAX_RUBY, &error) != ONIG_NORMAL) {
    return 1;
  }
  onig_set_match_operation_limit(100000);
  region = onig_region_new();
  result = onig_search(reg, str, end, str, end, region, ONIG_OPTION_NONE);
  failed = result != 0 || region->num_regs != 3;
  if (!failed) {
    failed = region->beg[1] != 35 || region->end[1] != 35 ||
             region->beg[2] != 35 || region->end[2] != 35;
  }
  if (failed) fprintf(stderr, "nullable repeat changed its captures\n");
  onig_region_free(region, 1);
  onig_free(reg);
  return failed;
}

/* Cache initialization must not write into a potentially shared regex. */
static int
check_shared_repeat_range(void)
{
  const char* pattern = "^(a|aa){0,20}b$";
  const char* text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabc";
  regex_t* reg;
  OnigErrorInfo error;
  const UChar* str = (const UChar*)text;
  const UChar* end = str + strlen(text);
  OnigPosition result;
  int i;
  int failed = 0;

  if (onig_new(&reg, (const UChar*)pattern,
               (const UChar*)pattern + strlen(pattern), ONIG_OPTION_DEFAULT,
               ONIG_ENCODING_UTF8, ONIG_SYNTAX_RUBY, &error) != ONIG_NORMAL) {
    return 1;
  }
  if (reg->num_repeat == 0) failed = 1;
  for (i = 0; i < reg->num_repeat; i++) {
    reg->repeat_range[i].base_num = -123;
    reg->repeat_range[i].inner_num = -456;
  }
  onig_set_match_operation_limit(10000000);
  result = onig_search(reg, str, end, str, end, NULL, ONIG_OPTION_NONE);
  failed |= result != ONIG_MISMATCH;
  for (i = 0; i < reg->num_repeat; i++) {
    failed |= reg->repeat_range[i].base_num != -123 ||
              reg->repeat_range[i].inner_num != -456;
  }
  if (failed) fprintf(stderr, "cache modified the compiled repeat ranges\n");
  onig_free(reg);
  return failed;
}

/* Exercise the cache at repeat bounds, for both directions and greediness. */
static int
check_repeat_boundaries(void)
{
  const int lower_bounds[] = {0, 1, 3, 10};
  char pattern[64];
  char text[23];
  int i;
  int lazy;
  int count;
  int failed = 0;
  OnigPosition expected;

  for (i = 0; i < 4; i++) {
    for (lazy = 0; lazy < 2; lazy++) {
      snprintf(pattern, sizeof(pattern), "^(a|aa){%d,10}%sb$",
               lower_bounds[i], lazy ? "?" : "");
      for (count = 0; count <= 21; count++) {
        memset(text, 'a', count);
        text[count] = 'b';
        text[count + 1] = '\0';
        expected = count >= lower_bounds[i] && count <= 20 ? 0 : ONIG_MISMATCH;
        failed |= check(pattern, text, 10000000, 0, 0, expected);
        failed |= check(pattern, text, 10000000, 1, 0, expected);
        failed |= check(pattern, text, 10000000, 0, 1,
                        expected == 0 ? count + 1 : expected);
      }
    }
  }
  /* Earlier repeats move the reserved zero-lower entry beyond its own body
   * span. Include an empty final repeat to exercise the last cache row. */
  failed |= check("^(x|xx){1,30}(a|aa){0,10}b$",
                  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxaaaaaaaaaaaaaaab",
                  10000000, 0, 0, 0);
  failed |= check("^(x|xx){1,30}(a|aa){0,10}?b$",
                  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxaaaaaaaaaaaaaaab",
                  10000000, 0, 0, 0);
  failed |= check("^(x|xx){1,30}(a|aa){0,10}$",
                  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                  10000000, 0, 0, 0);
  failed |= check("^(a|aa){3,}b$", "aaaaaaaaaaaaaaab", 10000000, 0, 0, 0);
  failed |= check("^(a|aa){3,}?b$", "aaaaaaaaaaaaaaab", 10000000, 0, 0, 0);
  return failed;
}

static int
check_repeat_capture(void)
{
  const char* pattern = "^(a|aa){3,10}b$";
  const char* text = "aaaaaaaaaaaaaaab";
  regex_t* reg;
  OnigRegion* region;
  OnigErrorInfo error;
  const UChar* str = (const UChar*)text;
  const UChar* end = str + strlen(text);
  OnigPosition result;
  int failed;

  if (onig_new(&reg, (const UChar*)pattern,
               (const UChar*)pattern + strlen(pattern), ONIG_OPTION_DEFAULT,
               ONIG_ENCODING_UTF8, ONIG_SYNTAX_RUBY, &error) != ONIG_NORMAL) {
    return 1;
  }
  onig_set_match_operation_limit(10000000);
  region = onig_region_new();
  result = onig_search(reg, str, end, str, end, region, ONIG_OPTION_NONE);
  failed = result != 0 || region->num_regs != 2;
  if (!failed) {
    failed = region->beg[0] != 0 || region->end[0] != 16 ||
             region->beg[1] != 13 || region->end[1] != 15;
  }
  if (failed) {
    fprintf(stderr, "bounded repeat lost its match or final capture\n");
  }
  onig_region_free(region, 1);
  onig_free(reg);
  return failed;
}

int
main(void)
{
  char text[1002];
  UChar message[ONIG_MAX_ERROR_MESSAGE_LEN];
  int failed = 0;

  onig_init();
  failed |= onig_get_match_operation_limit() != DEFAULT_MATCH_OPERATION_LIMIT;
  memset(text, 'a', sizeof(text) - 2);
  text[sizeof(text) - 2] = '!';
  text[sizeof(text) - 1] = '\0';
  failed |= check("^(a+)+$", text, 100, 0, 0, ONIGERR_MATCH_OPERATION_LIMIT_OVER);
  failed |= check("^(a*)*$", text, 100, 0, 1, ONIGERR_MATCH_OPERATION_LIMIT_OVER);
#ifndef ONIG_DISABLE_CACHE_MATCH_OPT
  /* These formerly exponential searches now finish without spending the budget. */
  failed |= check("^(a+)+$", text, 10000000, 0, 0, ONIG_MISMATCH);
  failed |= check("^(a*)*$", text, 100000, 0, 1,
                  ONIGERR_MATCH_OPERATION_LIMIT_OVER);
  failed |= check("^(a+)+$", text, 10000000, 1, 0, ONIG_MISMATCH);
  failed |= check("^(a+)+$|^(a+)!$", text, 10000000, 0, 0, 0);
#endif
  /* Backreferences cannot use the cache, so the budget remains essential. */
  failed |= check("^(a+)+\\1$", text, 100000, 0, 0,
                  ONIGERR_MATCH_OPERATION_LIMIT_OVER);
  /* A large finite repeat would require an excessive cache allocation. */
  failed |= check("^(a|aa){0,100000}$", text, 100000, 0, 0,
                  ONIGERR_MATCH_OPERATION_LIMIT_OVER);
  /* Each candidate needs few instructions; the total search must be bounded. */
  failed |= check("[ab]$", text, 100, 0, 0, ONIGERR_MATCH_OPERATION_LIMIT_OVER);
  failed |= check("[ab]$", text, 100, 1, 0, ONIGERR_MATCH_OPERATION_LIMIT_OVER);
  failed |= check("[ab]$", text, 0, 0, 0, ONIG_MISMATCH);
  failed |= check("(a+)", "aaaa", 100, 0, 0, 0);
  failed |= check("(a+)", "aaaa", 100, 0, 1, 4);
  failed |= check("a", "b", 100, 0, 0, ONIG_MISMATCH);
  /* A new call gets a fresh budget after exhaustion. */
  failed |= check("a", "a", 100, 0, 0, 0);
  onig_error_code_to_str(message, ONIGERR_MATCH_OPERATION_LIMIT_OVER);
  failed |= strcmp((const char*)message, "match operation limit over") != 0;
  failed |= check_repeat_boundaries();
  failed |= check_repeat_capture();
  failed |= check_nullable_capture();
#ifndef ONIG_DISABLE_CACHE_MATCH_OPT
  failed |= check_shared_repeat_range();
#endif
  onig_set_match_operation_limit(0);
  onig_end();
  return failed;
}
