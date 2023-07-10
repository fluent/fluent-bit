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
#include "testcpp.h"

/**
 * binary search by timestamp: excercices KafkaConsumer's seek() API.
 */


static std::string topic;
static const int partition      = 0;
static int64_t golden_timestamp = -1;
static int64_t golden_offset    = -1;

/**
 * @brief Seek to offset and consume that message.
 *
 * Asserts on failure.
 */
static RdKafka::Message *get_msg(RdKafka::KafkaConsumer *c,
                                 int64_t offset,
                                 bool use_seek) {
  RdKafka::TopicPartition *next =
      RdKafka::TopicPartition::create(topic, partition, offset);
  RdKafka::ErrorCode err;

  /* Since seek() can only be used to change the currently consumed
   * offset we need to start consuming the first time we run this
   * loop by calling assign() */

  test_timing_t t_seek;
  TIMING_START(&t_seek, "seek");
  if (!use_seek) {
    std::vector<RdKafka::TopicPartition *> parts;
    parts.push_back(next);
    err = c->assign(parts);
    if (err)
      Test::Fail("assign() failed: " + RdKafka::err2str(err));
  } else {
    err = c->seek(*next, tmout_multip(5000));
    if (err)
      Test::Fail("seek() failed: " + RdKafka::err2str(err));
  }
  TIMING_STOP(&t_seek);
  delete next;

  test_timing_t t_consume;
  TIMING_START(&t_consume, "consume");

  RdKafka::Message *msg = c->consume(tmout_multip(5000));
  if (!msg)
    Test::Fail("consume() returned NULL");
  TIMING_STOP(&t_consume);

  if (msg->err())
    Test::Fail("consume() returned error: " + msg->errstr());

  if (msg->offset() != offset)
    Test::Fail(tostr() << "seek()ed to offset " << offset
                       << " but consume() returned offset " << msg->offset());

  return msg;
}

class MyDeliveryReportCb : public RdKafka::DeliveryReportCb {
 public:
  void dr_cb(RdKafka::Message &msg) {
    if (msg.err())
      Test::Fail("Delivery failed: " + msg.errstr());

    if (!msg.msg_opaque())
      return;

    RdKafka::MessageTimestamp ts = msg.timestamp();
    if (ts.type != RdKafka::MessageTimestamp::MSG_TIMESTAMP_CREATE_TIME)
      Test::Fail(tostr() << "Dr msg timestamp type wrong: " << ts.type);

    golden_timestamp = ts.timestamp;
    golden_offset    = msg.offset();
  }
};

static void do_test_bsearch(void) {
  RdKafka::Conf *conf, *tconf;
  int msgcnt = 1000;
  int64_t timestamp;
  std::string errstr;
  RdKafka::ErrorCode err;
  MyDeliveryReportCb my_dr;

  topic = Test::mk_topic_name("0059-bsearch", 1);
  Test::conf_init(&conf, &tconf, 0);
  Test::conf_set(tconf, "acks", "all");
  Test::conf_set(conf, "api.version.request", "true");
  conf->set("dr_cb", &my_dr, errstr);
  conf->set("default_topic_conf", tconf, errstr);

  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create Producer: " + errstr);
  delete conf;
  delete tconf;

  timestamp = 1000;
  for (int i = 0; i < msgcnt; i++) {
    err = p->produce(topic, partition, RdKafka::Producer::RK_MSG_COPY,
                     (void *)topic.c_str(), topic.size(), NULL, 0, timestamp,
                     i == 357 ? (void *)1 /*golden*/ : NULL);
    if (err != RdKafka::ERR_NO_ERROR)
      Test::Fail("Produce failed: " + RdKafka::err2str(err));
    timestamp += 100 + (timestamp % 9);
  }

  if (p->flush(tmout_multip(5000)) != 0)
    Test::Fail("Not all messages flushed");

  Test::Say(tostr() << "Produced " << msgcnt << " messages, "
                    << "golden message with timestamp " << golden_timestamp
                    << " at offset " << golden_offset << "\n");

  delete p;

  /*
   * Now find the golden message using bsearch
   */

  /* Create consumer */
  Test::conf_init(&conf, NULL, 10);
  Test::conf_set(conf, "group.id", topic);
  Test::conf_set(conf, "api.version.request", "true");
  Test::conf_set(conf, "fetch.wait.max.ms", "1");
  Test::conf_set(conf, "fetch.error.backoff.ms", "1");
  Test::conf_set(conf, "queued.min.messages", "1");
  Test::conf_set(conf, "enable.auto.commit", "false");

  RdKafka::KafkaConsumer *c = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!c)
    Test::Fail("Failed to create KafkaConsumer: " + errstr);
  delete conf;

  Test::Say("Find initial middle offset\n");
  int64_t low, high;
  test_timing_t t_qr;
  TIMING_START(&t_qr, "query_watermark_offsets");
  err = c->query_watermark_offsets(topic, partition, &low, &high,
                                   tmout_multip(5000));
  TIMING_STOP(&t_qr);
  if (err)
    Test::Fail("query_watermark_offsets failed: " + RdKafka::err2str(err));

  /* Divide and conquer */
  test_timing_t t_bsearch;
  TIMING_START(&t_bsearch, "actual bsearch");
  int itcnt = 0;
  do {
    int64_t mid;

    mid = low + ((high - low) / 2);

    Test::Say(1, tostr() << "Get message at mid point of " << low << ".."
                         << high << " -> " << mid << "\n");

    RdKafka::Message *msg = get_msg(c, mid,
                                    /* use assign() on first iteration,
                                     * then seek() */
                                    itcnt > 0);

    RdKafka::MessageTimestamp ts = msg->timestamp();
    if (ts.type != RdKafka::MessageTimestamp::MSG_TIMESTAMP_CREATE_TIME)
      Test::Fail(tostr() << "Expected CreateTime timestamp, not " << ts.type
                         << " at offset " << msg->offset());

    Test::Say(1, tostr() << "Message at offset " << msg->offset()
                         << " with timestamp " << ts.timestamp << "\n");

    if (ts.timestamp == golden_timestamp) {
      Test::Say(1, tostr() << "Found golden timestamp " << ts.timestamp
                           << " at offset " << msg->offset() << " in "
                           << itcnt + 1 << " iterations\n");
      delete msg;
      break;
    }

    if (low == high) {
      Test::Fail(tostr() << "Search exhausted at offset " << msg->offset()
                         << " with timestamp " << ts.timestamp
                         << " without finding golden timestamp "
                         << golden_timestamp << " at offset " << golden_offset);

    } else if (ts.timestamp < golden_timestamp)
      low = msg->offset() + 1;
    else if (ts.timestamp > golden_timestamp)
      high = msg->offset() - 1;

    delete msg;
    itcnt++;
  } while (true);
  TIMING_STOP(&t_bsearch);

  c->close();

  delete c;
}

extern "C" {
int main_0059_bsearch(int argc, char **argv) {
  do_test_bsearch();
  return 0;
}
}
