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

