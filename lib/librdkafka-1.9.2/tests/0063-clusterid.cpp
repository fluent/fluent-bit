/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2016, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <iostream>
#include <cstring>
#include <cstdlib>
#include "testcpp.h"

/**
 * Test Handle::clusterid() and Handle::controllerid()
 */

static void do_test_clusterid(void) {
  Test::Say("[ do_test_clusterid ]\n");

  /*
   * Create client with appropriate protocol support for
   * retrieving clusterid
   */
  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 10);
  Test::conf_set(conf, "api.version.request", "true");
  std::string errstr;
  RdKafka::Producer *p_good = RdKafka::Producer::create(conf, errstr);
  if (!p_good)
    Test::Fail("Failed to create client: " + errstr);
  delete conf;

  /*
   * Create client with lacking protocol support.
   */
  Test::conf_init(&conf, NULL, 10);
  Test::conf_set(conf, "api.version.request", "false");
  Test::conf_set(conf, "broker.version.fallback", "0.9.0");
  RdKafka::Producer *p_bad = RdKafka::Producer::create(conf, errstr);
  if (!p_bad)
    Test::Fail("Failed to create client: " + errstr);
  delete conf;


  std::string clusterid;

  /*
   * good producer, give the first call a timeout to allow time
   * for background metadata requests to finish.
   */
  std::string clusterid_good_1 = p_good->clusterid(tmout_multip(2000));
  if (clusterid_good_1.empty())
    Test::Fail("good producer(w timeout): ClusterId is empty");
  Test::Say("good producer(w timeout): ClusterId " + clusterid_good_1 + "\n");

  /* Then retrieve a cached copy. */
  std::string clusterid_good_2 = p_good->clusterid(0);
  if (clusterid_good_2.empty())
    Test::Fail("good producer(0): ClusterId is empty");
  Test::Say("good producer(0): ClusterId " + clusterid_good_2 + "\n");

  if (clusterid_good_1 != clusterid_good_2)
    Test::Fail("Good ClusterId mismatch: " + clusterid_good_1 +
               " != " + clusterid_good_2);

  /*
   * Try bad producer, should return empty string.
   */
  std::string clusterid_bad_1 = p_bad->clusterid(tmout_multip(2000));
  if (!clusterid_bad_1.empty())
    Test::Fail("bad producer(w timeout): ClusterId should be empty, not " +
               clusterid_bad_1);
  std::string clusterid_bad_2 = p_bad->clusterid(0);
  if (!clusterid_bad_2.empty())
    Test::Fail("bad producer(0): ClusterId should be empty, not " +
               clusterid_bad_2);

  delete p_good;
  delete p_bad;
}


/**
 * @brief controllerid() testing.
 *        This instantiates its own client to avoid having the value cached
 *        from do_test_clusterid(), but they are basically the same tests.
 */
static void do_test_controllerid(void) {
  Test::Say("[ do_test_controllerid ]\n");

  /*
   * Create client with appropriate protocol support for
   * retrieving controllerid
   */
  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 10);
  Test::conf_set(conf, "api.version.request", "true");
  std::string errstr;
  RdKafka::Producer *p_good = RdKafka::Producer::create(conf, errstr);
  if (!p_good)
    Test::Fail("Failed to create client: " + errstr);
  delete conf;

  /*
   * Create client with lacking protocol support.
   */
  Test::conf_init(&conf, NULL, 10);
  Test::conf_set(conf, "api.version.request", "false");
  Test::conf_set(conf, "broker.version.fallback", "0.9.0");
  RdKafka::Producer *p_bad = RdKafka::Producer::create(conf, errstr);
  if (!p_bad)
    Test::Fail("Failed to create client: " + errstr);
  delete conf;

  /*
   * good producer, give the first call a timeout to allow time
   * for background metadata requests to finish.
   */
  int32_t controllerid_good_1 = p_good->controllerid(tmout_multip(2000));
  if (controllerid_good_1 == -1)
    Test::Fail("good producer(w timeout): Controllerid is -1");
  Test::Say(tostr() << "good producer(w timeout): Controllerid "
                    << controllerid_good_1 << "\n");

  /* Then retrieve a cached copy. */
  int32_t controllerid_good_2 = p_good->controllerid(0);
  if (controllerid_good_2 == -1)
    Test::Fail("good producer(0): Controllerid is -1");
  Test::Say(tostr() << "good producer(0): Controllerid " << controllerid_good_2
                    << "\n");

  if (controllerid_good_1 != controllerid_good_2)
    Test::Fail(tostr() << "Good Controllerid mismatch: " << controllerid_good_1
                       << " != " << controllerid_good_2);

  /*
   * Try bad producer, should return -1
   */
  int32_t controllerid_bad_1 = p_bad->controllerid(tmout_multip(2000));
  if (controllerid_bad_1 != -1)
    Test::Fail(
        tostr() << "bad producer(w timeout): Controllerid should be -1, not "
                << controllerid_bad_1);
  int32_t controllerid_bad_2 = p_bad->controllerid(0);
  if (controllerid_bad_2 != -1)
    Test::Fail(tostr() << "bad producer(0): Controllerid should be -1, not "
                       << controllerid_bad_2);

  delete p_good;
  delete p_bad;
}

extern "C" {
int main_0063_clusterid(int argc, char **argv) {
  do_test_clusterid();
  do_test_controllerid();
  return 0;
}
}
