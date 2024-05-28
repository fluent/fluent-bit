/*
 * Copyright (C) The c-ares project
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * SPDX-License-Identifier: MIT
 */
/*
 * General driver to allow command-line fuzzer (i.e. afl) to
 * exercise the libFuzzer entrypoint.
 */

#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#  include <io.h>
#else
#  include <unistd.h>
#endif

#include "ares.h"

#define kMaxAflInputSize (1 << 20)
static unsigned char afl_buffer[kMaxAflInputSize];

#ifdef __AFL_LOOP
/* If we are built with afl-clang-fast, use persistent mode */
#  define KEEP_FUZZING(count) __AFL_LOOP(1000)
#else
/* If we are built with afl-clang, execute each input once */
#  define KEEP_FUZZING(count) ((count) < 1)
#endif

/* In ares-test-fuzz.c and ares-test-fuzz-name.c: */
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);

static void ProcessFile(int fd)
{
  ares_ssize_t count = read(fd, afl_buffer, kMaxAflInputSize);
  /*
   * Make a copy of the data so that it's not part of a larger
   * buffer (where buffer overflows would go unnoticed).
   */
  if (count > 0) {
    unsigned char *copied_data = (unsigned char *)malloc((size_t)count);
    memcpy(copied_data, afl_buffer, (size_t)count);
    LLVMFuzzerTestOneInput(copied_data, (size_t)count);
    free(copied_data);
  }
}

int main(int argc, char *argv[])
{
  if (argc == 1) {
    int count = 0;
    while (KEEP_FUZZING(count)) {
      ProcessFile(fileno(stdin));
      count++;
    }
  } else {
    int ii;
    for (ii = 1; ii < argc; ++ii) {
      int fd = open(argv[ii], O_RDONLY);
      if (fd < 0) {
        fprintf(stderr, "Failed to open '%s'\n", argv[ii]);
        continue;
      }
      ProcessFile(fd);
      close(fd);
    }
  }
  return 0;
}
