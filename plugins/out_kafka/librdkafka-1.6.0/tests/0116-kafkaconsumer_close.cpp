/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2020, Magnus Edenhill
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
#include <map>
#include <cstring>
#include <cstdlib>
#include "testcpp.h"
extern "C" {
#include "test.h"
}

/**
 * Test KafkaConsumer close and destructor behaviour.
 */


static void do_test_consumer_close (bool do_subscribe,
                                    bool do_unsubscribe,
                                    bool do_close) {
  Test::Say(tostr() << _C_MAG << "[ Test C++ KafkaConsumer close " <<
            "subscribe=" << do_subscribe <<
            ", unsubscribe=" << do_unsubscribe <<
            ", close=" << do_close << " ]\n");

  rd_kafka_mock_cluster_t *mcluster;
  const char *bootstraps;
  mcluster = test_mock_cluster_new(3, &bootstraps);

  std::string errstr;

  /*
   * Produce messages to topics
   */
  const int msgs_per_partition = 10;
  RdKafka::Conf *pconf;
  Test::conf_init(&pconf, NULL, 10);
  Test::conf_set(pconf, "bootstrap.servers", bootstraps);
  RdKafka::Producer *p = RdKafka::Producer::create(pconf, errstr);
  if (!p)
    Test::Fail(tostr() << __FUNCTION__ << ": Failed to create producer: " <<
               errstr);
  delete pconf;
  Test::produce_msgs(p, "some_topic", 0, msgs_per_partition, 10, true/*flush*/);
  delete p;

  /* Create consumer */
  RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
  Test::conf_set(conf, "bootstrap.servers", bootstraps);
  Test::conf_set(conf, "group.id", "mygroup");
  Test::conf_set(conf, "auto.offset.reset", "beginning");

  RdKafka::KafkaConsumer *c = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!c)
    Test::Fail("Failed to create KafkaConsumer: " + errstr);
  delete conf;

  if (do_subscribe) {
    std::vector<std::string> topics;
    topics.push_back("some_topic");
    RdKafka::ErrorCode err;
    if ((err = c->subscribe(topics)))
      Test::Fail("subscribe failed: " + RdKafka::err2str(err));
  }

  int received = 0;
  while (received < msgs_per_partition) {
    RdKafka::Message *msg = c->consume(500);
    if (msg) {
      ++received;
      delete msg;
    }
  }

  RdKafka::ErrorCode err;
  if (do_unsubscribe)
    if ((err = c->unsubscribe()))
      Test::Fail("unsubscribe failed: " + RdKafka::err2str(err));

  if (do_close) {
    if ((err = c->close()))
      Test::Fail("close failed: " + RdKafka::err2str(err));

    /* A second call should fail */
    if ((err = c->close()) != RdKafka::ERR__DESTROY)
      Test::Fail("Expected second close to fail with DESTROY, not " +
                 RdKafka::err2str(err));
  }

  /* Call an async method that will do nothing but verify that we're not
   * crashing due to use-after-free. */
  if ((err = c->commitAsync()))
    Test::Fail("Expected commitAsync close to succeed, got " +
               RdKafka::err2str(err));

  delete c;

  test_mock_cluster_destroy(mcluster);
}

extern "C" {
  int main_0116_kafkaconsumer_close (int argc, char **argv) {
    /* Parameters:
     *  subscribe, unsubscribe, close */
    do_test_consumer_close(true, true, true);
    do_test_consumer_close(true, true, false);
    do_test_consumer_close(true, false, true);
    do_test_consumer_close(true, false, false);
    do_test_consumer_close(false, true, true);
    do_test_consumer_close(false, true, false);
    do_test_consumer_close(false, false, true);
    do_test_consumer_close(false, false, false);

    return 0;
  }
}
