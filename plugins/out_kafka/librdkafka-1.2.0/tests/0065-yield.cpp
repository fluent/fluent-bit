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
 * Verify that yield() works.
 *
 * In two iterations, do:
 *  - Register a DR callback that counts the number of messages and
 *    calls yield() in iteration 1, and not in iteration 2.
 *  - Produce 100 messages quickly (to ensure same-batch)
 *  - Verify that only one DR callback is triggered per poll() call
 *    in iteration 1, and all messages in iteration 2.
 */

class DrCb0065 : public RdKafka::DeliveryReportCb {
 public:
  int cnt; // dr messages seen
  bool do_yield; // whether to yield for each message or not
  RdKafka::Producer *p;

  DrCb0065(bool yield):  cnt(0), do_yield(yield), p(NULL) {}

  void dr_cb (RdKafka::Message &message) {
    if (message.err())
      Test::Fail("DR: message failed: " + RdKafka::err2str(message.err()));

    Test::Say(3, tostr() << "DR #" << cnt << "\n");
    cnt++;

    if (do_yield)
      p->yield();
  }
};


static void do_test_producer (bool do_yield) {
  int msgcnt = test_quick ? 20 : 100;
  std::string errstr;
  RdKafka::ErrorCode err;
  std::string topic = Test::mk_topic_name("0065_yield", 1);

  /*
   * Create Producer
   */

  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 10);
  DrCb0065 dr(do_yield);
  conf->set("dr_cb", &dr, errstr);
  /* Make sure messages are produced in batches of 100 */
  conf->set("batch.num.messages", "100", errstr);
  conf->set("linger.ms", "10000", errstr);

  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create producer: " + errstr);
  delete conf;

  dr.p = p;

  Test::Say(tostr() << (do_yield ? "Yield: " : "Dont Yield: ") <<
            "Producing " << msgcnt << " messages to " << topic << "\n");

  for (int i = 0 ; i < msgcnt ; i++) {
    err = p->produce(topic, 0, RdKafka::Producer::RK_MSG_COPY,
                     (void *)"hi", 2, NULL, 0, 0, NULL);
    if (err)
      Test::Fail("produce() failed: " + RdKafka::err2str(err));
  }


  int exp_msgs_per_poll = do_yield ? 1 : msgcnt;

  while (dr.cnt < msgcnt) {
    int pre_cnt = dr.cnt;
    p->poll(1000);

    int this_dr_cnt = dr.cnt - pre_cnt;
    if (this_dr_cnt == 0) {
      /* Other callbacks may cause poll() to return early
       * before DRs are available, ignore these. */
      Test::Say(3, "Zero DRs called, ignoring\n");
      continue;
    }

    if (this_dr_cnt != exp_msgs_per_poll)
      Test::Fail(tostr() << "Expected " << exp_msgs_per_poll <<
                 " DRs per poll() call, got " << this_dr_cnt);
    else
      Test::Say(3, tostr() << dr.cnt << "/" << msgcnt << "\n");
  }

  if (dr.cnt != msgcnt)
    Test::Fail(tostr() << "Expected " << msgcnt << " DRs, got " << dr.cnt);

  Test::Say(tostr() << (do_yield ? "Yield: " : "Dont Yield: ") <<
            "Success: " << dr.cnt << " DRs received in batches of " <<
            exp_msgs_per_poll << "\n");

  delete p;
}

extern "C" {
  int main_0065_yield (int argc, char **argv) {
    do_test_producer(1/*yield*/);
    do_test_producer(0/*dont yield*/);
    return 0;
  }
}
