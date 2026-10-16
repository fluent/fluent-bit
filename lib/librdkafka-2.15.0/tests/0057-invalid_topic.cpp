/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2022, Magnus Edenhill
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
 * Proper handling of invalid topic names, not by local client enforcement
 * but by proper propagation of broker errors.
 *
 * E.g.: produce messages to invalid topic should fail quickly, not by timeout.
 */



#define check_err(ERR, EXP)                                                    \
  do {                                                                         \
    if ((ERR) != (EXP))                                                        \
      Test::Fail(tostr() << __FUNCTION__ << ":" << __LINE__ << ": "            \
                         << "Expected " << RdKafka::err2str(EXP) << ", got "   \
                         << RdKafka::err2str(ERR));                            \
  } while (0)

class DrCb0057 : public RdKafka::DeliveryReportCb {
 public:
  void dr_cb(RdKafka::Message &msg) {
    std::string val((const char *)msg.payload());

    Test::Say(tostr() << "DeliveryReport for " << val << " message on "
                      << msg.topic_name() << " [" << msg.partition()
                      << "]: " << msg.errstr() << "\n");

    if (val == "good")
      check_err(msg.err(), RdKafka::ERR_NO_ERROR);
    else if (val == "bad") {
      if (test_broker_version >= TEST_BRKVER(0, 8, 2, 2))
        check_err(msg.err(), RdKafka::ERR_TOPIC_EXCEPTION);
      else
        check_err(msg.err(), RdKafka::ERR_UNKNOWN);
    }
  }
};

static void test_invalid_topic(void) {
  std::string topic_bad  = Test::mk_topic_name("0057-invalid_topic$#!", 1);
  std::string topic_good = Test::mk_topic_name("0057-invalid_topic_good", 1);
  RdKafka::Conf *conf;
  std::string errstr;

  Test::conf_init(&conf, NULL, 0);

  DrCb0057 MyDr;
  conf->set("dr_cb", &MyDr, errstr);

  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create Producer: " + errstr);

  RdKafka::ErrorCode err;

  for (int i = -1; i < 3; i++) {
    err = p->produce(topic_bad, i, RdKafka::Producer::RK_MSG_COPY,
                     (void *)"bad", 4, NULL, 0, 0, NULL);
    if (err) /* Error is probably delayed until delivery report */
      check_err(err, RdKafka::ERR_TOPIC_EXCEPTION);

    err = p->produce(topic_good, i, RdKafka::Producer::RK_MSG_COPY,
                     (void *)"good", 5, NULL, 0, 0, NULL);
    check_err(err, RdKafka::ERR_NO_ERROR);
  }

  p->flush(tmout_multip(10000));

  if (p->outq_len() > 0)
    Test::Fail(tostr() << "Expected producer to be flushed, " << p->outq_len()
                       << " messages remain");

  delete p;
  delete conf;
}

extern "C" {
int main_0057_invalid_topic(int argc, char **argv) {
  test_invalid_topic();
  return 0;
}
}
