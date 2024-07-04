/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2020-2022, Magnus Edenhill
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

/**
 * Verify that the producer waits topic.metadata.propagation.max.ms
 * before flagging a topic as non-existent, allowing asynchronous
 * CreateTopics() to be used in non-auto-create scenarios.
 *
 * This tests the producer. The consumer behaviour is implicitly tested
 * in 0109.
 */


namespace {
class DrCb : public RdKafka::DeliveryReportCb {
 public:
  DrCb(RdKafka::ErrorCode exp_err) : ok(false), _exp_err(exp_err) {
  }

  void dr_cb(RdKafka::Message &msg) {
    Test::Say("Delivery report: " + RdKafka::err2str(msg.err()) + "\n");
    if (msg.err() != _exp_err)
      Test::Fail("Delivery report: Expected " + RdKafka::err2str(_exp_err) +
                 " but got " + RdKafka::err2str(msg.err()));
    else if (ok)
      Test::Fail("Too many delivery reports");
    else
      ok = true;
  }

  bool ok;

 private:
  RdKafka::ErrorCode _exp_err;
};
};  // namespace

static void do_test_producer(bool timeout_too_short) {
  Test::Say(tostr() << _C_MAG << "[ Test with timeout_too_short="
                    << (timeout_too_short ? "true" : "false") << " ]\n");

  std::string topic = Test::mk_topic_name("0110-delay_create_topics", 1);

  /* Create Producer */
  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 20);

  std::string errstr;

  if (timeout_too_short) {
    if (conf->set("topic.metadata.propagation.max.ms", "3", errstr))
      Test::Fail(errstr);
  }

  DrCb dr_cb(timeout_too_short ? RdKafka::ERR_UNKNOWN_TOPIC_OR_PART
                               : RdKafka::ERR_NO_ERROR);
  conf->set("dr_cb", &dr_cb, errstr);

  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create Producer: " + errstr);
  delete conf;

  /* Produce a message to the yet non-existent topic. */
  RdKafka::ErrorCode err = p->produce(
      topic, RdKafka::Topic::PARTITION_UA, RdKafka::Producer::RK_MSG_COPY,
      (void *)"hello", 5, "hi", 2, 0, NULL, NULL);
  if (err)
    Test::Fail(tostr() << "produce failed: " << RdKafka::err2str(err));

  int delay        = 5;
  int64_t end_wait = test_clock() + (delay * 1000000);

  while (test_clock() < end_wait)
    p->poll(1000);

  Test::create_topic(NULL, topic.c_str(), 1, 3);

  p->flush(10 * 1000);

  if (!dr_cb.ok)
    Test::Fail("Did not get delivery report for message");

  delete p;

  Test::Say(tostr() << _C_GRN << "[ Test with timeout_too_short="
                    << (timeout_too_short ? "true" : "false") << ": PASS ]\n");
}

extern "C" {
int main_0111_delay_create_topics(int argc, char **argv) {
  do_test_producer(false);
  do_test_producer(true);
  return 0;
}
}
