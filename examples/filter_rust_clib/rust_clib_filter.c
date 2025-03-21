#include <stdio.h>
#include <string.h>
#include <time.h>
#include "filter_rust_clib.h"

char* rust_clib_filter(char* tag, int len, uint32_t sec, uint32_t nsec, char* record, int record_len)
{
  return (char *)rust_filter(tag, strlen(tag), sec, nsec, record, strlen(record));
}
