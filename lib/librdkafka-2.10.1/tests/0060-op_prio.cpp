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

#include <iostream>
#include "testcpp.h"

/**
 * Verify prioritization of non-message ops.
 * MO:
 *
 *  - Seed topic with 1000 messages
 *  - Start consumer with auto offset commit disabled,
 *    but with commit and stats callbacks registered,
 *  - Consume one message
 *  - Commit that message manually
 *  - Consume one message per second
 *  - The commit callback should be fired within reasonable time, long before
 *  - The stats callback should behave the same.
 *    all messages are consumed.
 */



class MyCbs : public RdKafka::OffsetCommitCb, public RdKafka::EventCb {
 public:
  int seen_commit;
  int seen_stats;

  void offset_commit_cb(RdKafka::ErrorCode err,
                        std::vector<RdKafka::TopicPartition *> &offsets) {
    if (err)
      Test::Fail("Offset commit failed: " + RdKafka::err2str(err));

    seen_commit++;
    Test::Say("Got commit callback!\n");
  }

  void event_cb(RdKafka::Event &event) {
    switch (event.type()) {
    case RdKafka::Event::EVENT_STATS:
      Test::Say("Got stats callback!\n");
      seen_stats++;
      break;
    default:
      break;
    }
  }
};



static void do_test_commit_cb(void) {
  const int msgcnt = test_quick ? 100 : 1000;
  std::string errstr;
  RdKafka::ErrorCode err;
  std::string topic = Test::mk_topic_name("0060-op_prio", 1);

  test_produce_msgs_easy(topic.c_str(), 0, 0, msgcnt);

  /*
   * Create consumer
   */

  /* Create consumer */
  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 10);
  Test::conf_set(conf, "group.id", topic);
  Test::conf_set(conf, "socket.timeout.ms", "10000");
  Test::conf_set(conf, "enable.auto.commit", "false");
  Test::conf_set(conf, "enable.partition.eof", "false");
  Test::conf_set(conf, "auto.offset.reset", "earliest");
  Test::conf_set(conf, "statistics.interval.ms", "1000");

  MyCbs cbs;
  cbs.seen_commit = 0;
  cbs.seen_stats  = 0;
  if (conf->set("offset_commit_cb", (RdKafka::OffsetCommitCb *)&cbs, errstr) !=
      RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to set commit callback: " + errstr);
  if (conf->set("event_cb", (RdKafka::EventCb *)&cbs, errstr) !=
      RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to set event callback: " + errstr);

  RdKafka::KafkaConsumer *c = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!c)
    Test::Fail("Failed to create KafkaConsumer: " + errstr);
  delete conf;

  /* Subscribe */
  std::vector<std::string> topics;
  topics.push_back(topic);
  if ((err = c->subscribe(topics)))
    Test::Fail("subscribe failed: " + RdKafka::err2str(err));

  /* Wait for messages and commit callback. */
  Test::Say("Consuming topic " + topic + "\n");
  int cnt = 0;
  while (!cbs.seen_commit || !cbs.seen_stats) {
    RdKafka::Message *msg = c->consume(tmout_multip(1000));
    if (!msg->err()) {
      cnt++;
      Test::Say(tostr() << "Received message #" << cnt << "\n");
      if (cnt > 10)
        Test::Fail(tostr() << "Should've seen the "
                              "offset commit ("
                           << cbs.seen_commit
                           << ") and "
                              "stats callbacks ("
                           << cbs.seen_stats << ") by now");

      /* Commit the first message to trigger the offset commit_cb */
      if (cnt == 1) {
        err = c->commitAsync(msg);
        if (err)
          Test::Fail("commitAsync() failed: " + RdKafka::err2str(err));
        rd_sleep(1); /* Sleep to simulate slow processing, making sure
                      * that the offset commit callback op gets
                      * inserted on the consume queue in front of
                      * the messages. */
      }

    } else if (msg->err() == RdKafka::ERR__TIMED_OUT)
      ; /* Stil rebalancing? */
    else
      Test::Fail("consume() failed: " + msg->errstr());
    delete msg;
  }

  c->close();
  delete c;
}

extern "C" {
int main_0060_op_prio(int argc, char **argv) {
  do_test_commit_cb();
  return 0;
}
}
