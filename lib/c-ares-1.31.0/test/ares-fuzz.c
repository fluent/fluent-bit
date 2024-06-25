/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
