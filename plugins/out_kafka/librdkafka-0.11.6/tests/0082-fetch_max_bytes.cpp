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
 * @brief Test fetch.max.bytes
 *
 *  - Produce 1*10 Megs to 3 partitions (~<1 Meg per message)
 *  - Set max.partition.fetch.bytes to 5 Meg
 *  - Set fetch.max.bytes to 2 Meg
 *  - Verify all messages are consumed without error.
 */


static void do_test_fetch_max_bytes (void) {
  const int partcnt = 3;
  int msgcnt = 10 * partcnt;
  const int msgsize = 900*1024;  /* Less than 1 Meg to account
                                  * for batch overhead */
  std::string errstr;
  RdKafka::ErrorCode err;

  std::string topic = Test::mk_topic_name("0081-fetch_max_bytes", 1);

  /* Produce messages to partitions */
  for (int32_t p = 0 ; p < (int32_t)partcnt ; p++)
    test_produce_msgs_easy_size(topic.c_str(), 0, p, msgcnt, msgsize);

  /* Create consumer */
  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 10);
  Test::conf_set(conf, "group.id", topic);
  Test::conf_set(conf, "auto.offset.reset", "earliest");
  /* We try to fetch 20 Megs per partition, but only allow 1 Meg as total
   * response size, this ends up serving the first batch from the
   * first partition.
   * receive.message.max.bytes is set low to trigger the original bug,
   * but this value is now adjusted upwards automatically by rd_kafka_new()
   * to hold both fetch.max.bytes and the protocol / batching overhead.
   * Prior to the introduction of fetch.max.bytes the fetcher code
   * would use receive.message.max.bytes to limit the total Fetch response,
   * but due to batching overhead it would result in situations where
   * the consumer asked for 1000000 bytes and got 1000096 bytes batch, which
   * was higher than the 1000000 limit.
   * See https://github.com/edenhill/librdkafka/issues/1616
   */
  Test::conf_set(conf, "max.partition.fetch.bytes", "20000000"); /* ~20MB */
  Test::conf_set(conf, "fetch.max.bytes", "1000000"); /* ~1MB */
  Test::conf_set(conf, "receive.message.max.bytes", "1000000"); /* ~1MB+ */

  RdKafka::KafkaConsumer *c = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!c)
    Test::Fail("Failed to create KafkaConsumer: " + errstr);
  delete conf;

  /* Subscribe */
  std::vector<std::string> topics;
  topics.push_back(topic);
  if ((err = c->subscribe(topics)))
    Test::Fail("subscribe failed: " + RdKafka::err2str(err));

  /* Start consuming */
  Test::Say("Consuming topic " + topic + "\n");
  int cnt = 0;
  while (cnt < msgcnt) {
    RdKafka::Message *msg = c->consume(tmout_multip(1000));
    switch (msg->err())
      {
      case RdKafka::ERR__TIMED_OUT:
      case RdKafka::ERR__PARTITION_EOF:
        break;

      case RdKafka::ERR_NO_ERROR:
        cnt++;
        break;

      default:
        Test::Fail("Consume error: " + msg->errstr());
        break;
      }

    delete msg;
  }
  Test::Say("Done\n");

  c->close();
  delete c;
}

extern "C" {
  int main_0082_fetch_max_bytes (int argc, char **argv) {
    do_test_fetch_max_bytes();
    return 0;
  }
}
