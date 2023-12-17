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
#include <signal.h>
#include <stdlib.h>

#include "ares-test.h"

int main(int argc, char* argv[]) {
  std::vector<char*> gtest_argv = {argv[0]};
  for (int ii = 1; ii < argc; ii++) {
    if (strcmp(argv[ii], "-v") == 0) {
      ares::test::verbose = true;
    } else if ((strcmp(argv[ii], "-p") == 0) && (ii + 1 < argc)) {
      ii++;
      ares::test::mock_port = (unsigned short)atoi(argv[ii]);
    } else if (strcmp(argv[ii], "-4") == 0) {
      ares::test::families = ares::test::ipv4_family;
      ares::test::families_modes = ares::test::ipv4_family_both_modes;
    } else if (strcmp(argv[ii], "-6") == 0) {
      ares::test::families = ares::test::ipv6_family;
      ares::test::families_modes = ares::test::ipv6_family_both_modes;
    } else {
      gtest_argv.push_back(argv[ii]);
    }
  }
  int gtest_argc = (int)gtest_argv.size();
  gtest_argv.push_back(nullptr);
  ::testing::InitGoogleTest(&gtest_argc, gtest_argv.data());

#ifdef WIN32
  WORD wVersionRequested = MAKEWORD(2, 2);
  WSADATA wsaData;
  WSAStartup(wVersionRequested, &wsaData);
#else
  signal(SIGPIPE, SIG_IGN);
#endif

  int rc = RUN_ALL_TESTS();

#ifdef WIN32
  WSACleanup();
#endif

  return rc;
}
