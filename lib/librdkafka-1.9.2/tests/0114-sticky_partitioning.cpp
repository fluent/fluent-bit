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

/**
 * Test sticky.partitioning.linger.ms producer property.
 *
 */

#include <iostream>
#include <fstream>
#include <iterator>
#include <string>
#include "testcpp.h"
#include "test.h"

/**
 * @brief Specify sticky.partitioning.linger.ms and check consumed
 * messages to verify it takes effect.
 */
static void do_test_sticky_partitioning(int sticky_delay) {
  std::string topic = Test::mk_topic_name(__FILE__, 1);
  Test::create_topic(NULL, topic.c_str(), 3, 1);

  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 0);

  Test::conf_set(conf, "sticky.partitioning.linger.ms",
                 tostr() << sticky_delay);

  std::string errstr;
  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create Producer: " + errstr);

  RdKafka::Consumer *c = RdKafka::Consumer::create(conf, errstr);
  if (!c)
    Test::Fail("Failed to create Consumer: " + errstr);
  delete conf;

  RdKafka::Topic *t = RdKafka::Topic::create(c, topic, NULL, errstr);
  if (!t)
    Test::Fail("Failed to create Topic: " + errstr);

  c->start(t, 0, RdKafka::Topic::OFFSET_BEGINNING);
  c->start(t, 1, RdKafka::Topic::OFFSET_BEGINNING);
  c->start(t, 2, RdKafka::Topic::OFFSET_BEGINNING);

  const int msgrate = 100;
  const int msgsize = 10;

  /* Produce messages */
  char val[msgsize];
  memset(val, 'a', msgsize);

  /* produce for for seconds at 100 msgs/sec */
  for (int s = 0; s < 4; s++) {
    int64_t end_wait = test_clock() + (1 * 1000000);

    for (int i = 0; i < msgrate; i++) {
      RdKafka::ErrorCode err = p->produce(topic, RdKafka::Topic::PARTITION_UA,
                                          RdKafka::Producer::RK_MSG_COPY, val,
                                          msgsize, NULL, 0, -1, NULL);
      if (err)
        Test::Fail("Produce failed: " + RdKafka::err2str(err));
    }

    while (test_clock() < end_wait)
      p->poll(100);
  }

  Test::Say(tostr() << "Produced " << 4 * msgrate << " messages\n");
  p->flush(5 * 1000);

  /* Consume messages */
  int partition_msgcnt[3]   = {0, 0, 0};
  int num_partitions_active = 0;
  int i                     = 0;

  int64_t end_wait = test_clock() + (5 * 1000000);
  while (test_clock() < end_wait) {
    RdKafka::Message *msg = c->consume(t, i, 5);

    switch (msg->err()) {
    case RdKafka::ERR__TIMED_OUT:
      i++;
      if (i > 2)
        i = 0;
      break;

    case RdKafka::ERR_NO_ERROR:
      partition_msgcnt[msg->partition()]++;
      break;

    default:
      Test::Fail("Consume error: " + msg->errstr());
      break;
    }

    delete msg;
  }

  c->stop(t, 0);
  c->stop(t, 1);
  c->stop(t, 2);

  for (int i = 0; i < 3; i++) {
    /* Partitions must receive 100+ messages to be deemed 'active'. This
     * is because while topics are being updated, it is possible for some
     * number of messages to be partitioned to joining partitions before
     * they become available. This can cause some initial turnover in
     * selecting a sticky partition. This behavior is acceptable, and is
     * not important for the purpose of this segment of the test. */

    if (partition_msgcnt[i] > (msgrate - 1))
      num_partitions_active++;
  }

  Test::Say("Partition Message Count: \n");
  for (int i = 0; i < 3; i++) {
    Test::Say(tostr() << " " << i << ": " << partition_msgcnt[i] << "\n");
  }

  /* When sticky.partitioning.linger.ms is long (greater than expected
   * length of run), one partition should be sticky and receive messages. */
  if (sticky_delay == 5000 && num_partitions_active > 1)
    Test::Fail(tostr() << "Expected only 1 partition to receive msgs"
                       << " but " << num_partitions_active
                       << " partitions received msgs.");

  /* When sticky.partitioning.linger.ms is short (sufficiently smaller than
   * length of run), it is extremely likely that all partitions are sticky
   * at least once and receive messages. */
  if (sticky_delay == 1000 && num_partitions_active <= 1)
    Test::Fail(tostr() << "Expected more than one partition to receive msgs"
                       << " but only " << num_partitions_active
                       << " partition received msgs.");

  delete t;
  delete p;
  delete c;
}

extern "C" {
int main_0114_sticky_partitioning(int argc, char **argv) {
  /* long delay (5 secs) */
  do_test_sticky_partitioning(5000);
  /* short delay (0.001 secs) */
  do_test_sticky_partitioning(1);
  return 0;
}
}
