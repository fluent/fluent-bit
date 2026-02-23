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
#include <signal.h>
#include <stdlib.h>

#include "ares-test.h"

#ifdef __APPLE__
#  include <mach/mach.h>
#  include <mach/mach_time.h>
#  include <pthread.h>

static void thread_set_realtime(pthread_t pthread)
{
  mach_timebase_info_data_t            timebase_info;
  const uint64_t                       NANOS_PER_MSEC = 1000000ULL;
  double                               clock2abs;
  int                                  rv;
  thread_time_constraint_policy_data_t policy;

  mach_timebase_info(&timebase_info);
  clock2abs = ((double)timebase_info.denom / (double)timebase_info.numer)
              * NANOS_PER_MSEC;

  policy.period      = 0;
  policy.computation = (uint32_t)(5 * clock2abs); // 5 ms of work
  policy.constraint  = (uint32_t)(10 * clock2abs);
  policy.preemptible = FALSE;

  rv = thread_policy_set(pthread_mach_thread_np(pthread),
                         THREAD_TIME_CONSTRAINT_POLICY,
                         (thread_policy_t)&policy,
                         THREAD_TIME_CONSTRAINT_POLICY_COUNT);
  if (rv != KERN_SUCCESS) {
    mach_error("thread_policy_set:", rv);
    exit(1);
  }
}
#endif

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
      ares::test::evsys_families = ares::test::all_evsys_ipv4_family;
      ares::test::evsys_families_modes = ares::test::all_evsys_ipv4_family_both_modes;
    } else if (strcmp(argv[ii], "-6") == 0) {
      ares::test::families = ares::test::ipv6_family;
      ares::test::families_modes = ares::test::ipv6_family_both_modes;
      ares::test::evsys_families = ares::test::all_evsys_ipv6_family;
      ares::test::evsys_families_modes = ares::test::all_evsys_ipv6_family_both_modes;
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

#ifdef __APPLE__
  /* We need to increase the priority in order for some timing-sensitive tests
   * to succeed reliably.  On CI systems, the host can be overloaded and things
   * like sleep timers can wait many multiples of the time specified otherwise.
   * This is sort of a necessary hack for test reliability. Not something that
   * would generally be used */
  thread_set_realtime(pthread_self());
#endif

  int rc = RUN_ALL_TESTS();

#ifdef WIN32
  WSACleanup();
#endif

  return rc;
}
