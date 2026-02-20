/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2016-2022, Magnus Edenhill
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


#include "rdkafka.h" /* Include before rdkafkacpp.h (from testcpp.h) */
#include "testcpp.h"
#include <cstring>

/**
 * @name Verify that the c_ptr()'s returned from C++ can be used
 *       to interact directly with the C API.
 */


extern "C" {
int main_0078_c_from_cpp(int argc, char **argv) {
  RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);

  std::string errstr;

  if (conf->set("client.id", "myclient", errstr))
    Test::Fail("conf->set() failed: " + errstr);

  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create Producer: " + errstr);

  delete conf;

  /*
   * Acquire rd_kafka_t and compare its name to the configured client.id
   */
  rd_kafka_t *rk = p->c_ptr();
  if (!rk)
    Test::Fail("Failed to acquire c_ptr");

  std::string name   = p->name();
  std::string c_name = rd_kafka_name(rk);

  Test::Say("Compare C name " + c_name + " to C++ name " + name + "\n");
  if (c_name != name)
    Test::Fail("Expected C client name " + c_name + " to match C++ " + name);

  /*
   * Create topic object, acquire rd_kafka_topic_t and compare
   * its topic name.
   */

  RdKafka::Topic *topic = RdKafka::Topic::create(p, "mytopic", NULL, errstr);
  if (!topic)
    Test::Fail("Failed to create Topic: " + errstr);

  rd_kafka_topic_t *rkt = topic->c_ptr();
  if (!rkt)
    Test::Fail("Failed to acquire topic c_ptr");

  std::string topicname   = topic->name();
  std::string c_topicname = rd_kafka_topic_name(rkt);

  Test::Say("Compare C topic " + c_topicname + " to C++ topic " + topicname +
            "\n");
  if (c_topicname != topicname)
    Test::Fail("Expected C topic " + c_topicname + " to match C++ topic " +
               topicname);

  delete topic;
  delete p;

  return 0;
}
}
