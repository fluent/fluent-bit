/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2015, Magnus Edenhill
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


#include "testcpp.h"

#include <fstream>
#include <cstring>


namespace Test {

/**
 * @brief Read config file and populate config objects.
 * @returns 0 on success or -1 on error
 */
static int read_config_file(std::string path,
                            RdKafka::Conf *conf,
                            RdKafka::Conf *topic_conf,
                            int *timeoutp) {
  std::ifstream input(path.c_str(), std::ifstream::in);

  if (!input)
    return 0;

  std::string line;
  while (std::getline(input, line)) {
    /* Trim string */
    line.erase(0, line.find_first_not_of("\t "));
    line.erase(line.find_last_not_of("\t ") + 1);

    if (line.length() == 0 || line.substr(0, 1) == "#")
      continue;

    size_t f = line.find("=");
    if (f == std::string::npos) {
      Test::Fail(tostr() << "Conf file: malformed line: " << line);
      return -1;
    }

    std::string n = line.substr(0, f);
    std::string v = line.substr(f + 1);
    std::string errstr;

    if (test_set_special_conf(n.c_str(), v.c_str(), timeoutp))
      continue;

    RdKafka::Conf::ConfResult r = RdKafka::Conf::CONF_UNKNOWN;

    if (n.substr(0, 6) == "topic.")
      r = topic_conf->set(n.substr(6), v, errstr);
    if (r == RdKafka::Conf::CONF_UNKNOWN)
      r = conf->set(n, v, errstr);

    if (r != RdKafka::Conf::CONF_OK) {
      Test::Fail(errstr);
      return -1;
    }
  }

  return 0;
}

void conf_init(RdKafka::Conf **conf, RdKafka::Conf **topic_conf, int timeout) {
  const char *tmp;

  if (conf)
    *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
  if (topic_conf)
    *topic_conf = RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC);

  read_config_file(test_conf_get_path(), conf ? *conf : NULL,
                   topic_conf ? *topic_conf : NULL, &timeout);

  std::string errstr;
  if ((*conf)->set("client.id", test_curr_name(), errstr) !=
      RdKafka::Conf::CONF_OK)
    Test::Fail("set client.id failed: " + errstr);

  if (*conf && (tmp = test_getenv("TEST_DEBUG", NULL))) {
    if ((*conf)->set("debug", tmp, errstr) != RdKafka::Conf::CONF_OK)
      Test::Fail("TEST_DEBUG failed: " + errstr);
  }


  if (timeout)
    test_timeout_set(timeout);
}


void DeliveryReportCb::dr_cb(RdKafka::Message &msg) {
  if (msg.err() != RdKafka::ERR_NO_ERROR)
    Test::Fail(tostr() << "Delivery failed to " << msg.topic_name() << " ["
                       << msg.partition() << "]: " << msg.errstr());
  else
    Test::Say(3, tostr() << "Delivered to " << msg.topic_name() << " ["
                         << msg.partition() << "] @ " << msg.offset()
                         << " (timestamp " << msg.timestamp().timestamp
                         << ")\n");
}
};  // namespace Test
