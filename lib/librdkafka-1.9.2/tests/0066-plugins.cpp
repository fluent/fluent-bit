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

#ifdef _WIN32
#include <direct.h>
#endif


extern "C" {
#include "interceptor_test/interceptor_test.h"

struct ictest ictest;
};


/**
 * Verify plugin.library.paths and interceptors
 * using interceptor_test/...
 *
 */


static void do_test_plugin() {
  std::string errstr;
  std::string topic           = Test::mk_topic_name("0066_plugins", 1);
  static const char *config[] = {
      "session.timeout.ms",
      "6000", /* Before plugin */
      "plugin.library.paths",
      "interceptor_test/interceptor_test",
      "socket.timeout.ms",
      "12", /* After plugin */
      "interceptor_test.config1",
      "one",
      "interceptor_test.config2",
      "two",
      "topic.metadata.refresh.interval.ms",
      "1234",
      NULL,
  };

  char cwd[512], *pcwd;
#ifdef _WIN32
  pcwd = _getcwd(cwd, sizeof(cwd) - 1);
#else
  pcwd = getcwd(cwd, sizeof(cwd) - 1);
#endif
  if (pcwd)
    Test::Say(tostr() << "running test from cwd " << cwd << "\n");

  /* Interceptor back-channel config */
  ictest_init(&ictest);
  ictest_cnt_init(&ictest.conf_init, 1, 1000);
  ictest_cnt_init(&ictest.on_new, 1, 1);

  /* Config for intercepted client */
  RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);

  for (int i = 0; config[i]; i += 2) {
    Test::Say(tostr() << "set(" << config[i] << ", " << config[i + 1] << ")\n");
    if (conf->set(config[i], config[i + 1], errstr))
      Test::Fail(tostr() << "set(" << config[i] << ") failed: " << errstr);
  }

  /* Create producer */
  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create producer: " + errstr);

  if (ictest.on_new.cnt < ictest.on_new.min ||
      ictest.on_new.cnt > ictest.on_new.max)
    Test::Fail(tostr() << "on_new.cnt " << ictest.on_new.cnt
                       << " not within range " << ictest.on_new.min << ".."
                       << ictest.on_new.max);

  /* Verification */
  if (!ictest.config1 || strcmp(ictest.config1, "one"))
    Test::Fail(tostr() << "config1 was " << ictest.config1);
  if (!ictest.config2 || strcmp(ictest.config2, "two"))
    Test::Fail(tostr() << "config2 was " << ictest.config2);
  if (!ictest.session_timeout_ms || strcmp(ictest.session_timeout_ms, "6000"))
    Test::Fail(tostr() << "session.timeout.ms was "
                       << ictest.session_timeout_ms);
  if (!ictest.socket_timeout_ms || strcmp(ictest.socket_timeout_ms, "12"))
    Test::Fail(tostr() << "socket.timeout.ms was " << ictest.socket_timeout_ms);

  delete conf;

  delete p;

  ictest_free(&ictest);
}

extern "C" {
int main_0066_plugins(int argc, char **argv) {
  do_test_plugin();
  return 0;
}
}
