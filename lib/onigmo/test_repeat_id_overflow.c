#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "onigmo.h"

static int
check_pattern(const char* piece, size_t count, int expected)
{
  size_t piece_len = strlen(piece);
  size_t len = piece_len * count;
  UChar* pattern = (UChar* )malloc(len + 1);
  regex_t* reg = NULL;
  OnigErrorInfo error_info;
  int result;
  size_t i;

  if (pattern == NULL) return 1;
  for (i = 0; i < count; i++)
    memcpy(pattern + i * piece_len, piece, piece_len);
  pattern[len] = '\0';

  result = onig_new(&reg, pattern, pattern + len, ONIG_OPTION_DEFAULT,
                    ONIG_ENCODING_UTF8, ONIG_SYNTAX_RUBY, &error_info);
  if (result != expected)
    fprintf(stderr, "count=%zu: expected %d, got %d\n", count, expected, result);

  if (reg != NULL) onig_free(reg);
  free(pattern);
  return result != expected;
}

int
main(void)
{
  int failed;

  if (onig_init() != ONIG_NORMAL) return 1;
  failed = check_pattern("(?:fo){0,100}", 32767, ONIG_NORMAL);
  failed |= check_pattern("(?:fo){0,100}", 32768,
                          ONIGERR_TOO_MANY_RANGE_REPEAT);
  failed |= check_pattern("(?:fo){0,100}", 32769,
                          ONIGERR_TOO_MANY_RANGE_REPEAT);
  failed |= check_pattern("(?:a|)*", 40000,
                          ONIGERR_TOO_MANY_NULL_CHECK);
  onig_end();
  return failed;
}
