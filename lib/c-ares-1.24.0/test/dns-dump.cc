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
#include <sys/types.h>
#include <fcntl.h>
#ifdef _MSC_VER
#  include <io.h>
#else
#  include <unistd.h>
#endif

#include <iostream>
#include <vector>

#include "dns-proto.h"

namespace ares {

static void ShowFile(const char* filename) {
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    std::cerr << "Failed to open '" << filename << "'" << std::endl;
    return;
  }
  std::vector<unsigned char> contents;
  while (true) {
    unsigned char buffer[1024];
    ares_ssize_t len = read(fd, buffer, sizeof(buffer));
    if (len <= 0) break;
    contents.insert(contents.end(), buffer, buffer + len);
  }
  std::cout << PacketToString(contents) << std::endl;
}

}  // namespace ares

int main(int argc, char* argv[]) {
  for (int ii = 1; ii < argc; ++ii) {
    ares::ShowFile(argv[ii]);
  }
  return 0;
}

