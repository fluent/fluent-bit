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


namespace {
class DrCb : public RdKafka::DeliveryReportCb {
 public:
  DrCb (RdKafka::ErrorCode exp_err): cnt(0), exp_err(exp_err) {}

  void dr_cb (RdKafka::Message &msg) {
    Test::Say("Delivery report: " + RdKafka::err2str(msg.err()) + "\n");
    if (msg.err() != exp_err)
      Test::Fail("Delivery report: Expected " + RdKafka::err2str(exp_err) +
                 " but got " + RdKafka::err2str(msg.err()));
    cnt++;
  }

  int cnt;
  RdKafka::ErrorCode exp_err;
};
};

/**
 * @brief Test producer auth failures.
 *
 * @param topic_known If true we make sure the producer knows about the topic
 *                    before restricting access to it and producing,
 *                    this should result in the ProduceRequest failing,
 *                    if false we restrict access prior to this which should
 *                    result in MetadataRequest failing.
 */


static void do_test_producer (bool topic_known) {
  Test::Say(tostr() << _C_MAG << "[ Test producer auth with topic " <<
            (topic_known ? "" : "not ") << "known ]\n");

  /* Create producer */
  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 20);

  std::string errstr;
  DrCb dr(RdKafka::ERR_NO_ERROR);
  conf->set("dr_cb", &dr, errstr);

  std::string bootstraps;
  if (conf->get("bootstrap.servers", bootstraps) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to retrieve bootstrap.servers");

  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create Producer: " + errstr);
  delete conf;

  /* Create topic */
  std::string topic_unauth = Test::mk_topic_name("0115-unauthorized", 1);
  Test::create_topic(NULL, topic_unauth.c_str(), 3, 1);

  int exp_dr_cnt = 0;

  RdKafka::ErrorCode err;

  if (topic_known) {
    /* Produce a single message to make sure metadata is known. */
    Test::Say("Producing seeding message 0\n");
    err = p->produce(topic_unauth,
                     RdKafka::Topic::PARTITION_UA,
                     RdKafka::Producer::RK_MSG_COPY,
                     (void *)"0", 1,
                     NULL, 0,
                     0, NULL);
    TEST_ASSERT(!err,
                "produce() failed: %s", RdKafka::err2str(err).c_str());

    p->flush(-1);
    exp_dr_cnt++;
  }

  /* Add denying ACL for unauth topic */
  test_kafka_cmd("kafka-acls.sh --bootstrap-server %s "
                 "--add --deny-principal 'User:*' "
                 "--operation All --deny-host '*' "
                 "--topic '%s'",
                 bootstraps.c_str(), topic_unauth.c_str());

  /* Produce message to any partition. */
  Test::Say("Producing message 1 to any partition\n");
  err = p->produce(topic_unauth,
                   RdKafka::Topic::PARTITION_UA,
                   RdKafka::Producer::RK_MSG_COPY,
                   (void *)"1", 1,
                   NULL, 0,
                   0, NULL);
  TEST_ASSERT(!err,
              "produce() failed: %s", RdKafka::err2str(err).c_str());
  exp_dr_cnt++;

  /* Produce message to specific partition. */
  Test::Say("Producing message 2 to partition 0\n");
  err = p->produce(topic_unauth,
                   0,
                   RdKafka::Producer::RK_MSG_COPY,
                   (void *)"3", 1,
                   NULL, 0,
                   0, NULL);
  TEST_ASSERT(!err,
              "produce() failed: %s", RdKafka::err2str(err).c_str());
  exp_dr_cnt++;

  /* Wait for DRs */
  dr.exp_err = RdKafka::ERR_TOPIC_AUTHORIZATION_FAILED;
  p->flush(-1);


  /* Produce message to any and specific partition, should fail immediately. */
  Test::Say("Producing message 3 to any partition\n");
  err = p->produce(topic_unauth,
                   RdKafka::Topic::PARTITION_UA,
                   RdKafka::Producer::RK_MSG_COPY,
                   (void *)"3", 1,
                   NULL, 0,
                   0, NULL);
  TEST_ASSERT(err == dr.exp_err,
              "Expected produce() to fail with ERR_TOPIC_AUTHORIZATION_FAILED, "
              "not %s", RdKafka::err2str(err).c_str());

  /* Specific partition */
  Test::Say("Producing message 4 to partition 0\n");
  err = p->produce(topic_unauth,
                   0,
                   RdKafka::Producer::RK_MSG_COPY,
                   (void *)"4", 1,
                   NULL, 0,
                   0, NULL);
  TEST_ASSERT(err == dr.exp_err,
              "Expected produce() to fail with ERR_TOPIC_AUTHORIZATION_FAILED, "
              "not %s", RdKafka::err2str(err).c_str());

  /* Final flush just to make sure */
  p->flush(-1);

  TEST_ASSERT(exp_dr_cnt == dr.cnt,
              "Expected %d deliveries, not %d", exp_dr_cnt, dr.cnt);

  Test::Say(tostr() << _C_GRN << "[ Test producer auth with topic " <<
            (topic_known ? "" : "not ") << "known: PASS ]\n");

  delete p;
}

extern "C" {
  int main_0115_producer_auth (int argc, char **argv) {
    /* We can't bother passing Java security config to kafka-acls.sh */
    if (test_needs_auth()) {
      Test::Skip("Cluster authentication required\n");
      return 0;
    }

    do_test_producer(true);
    do_test_producer(false);

    return 0;
  }
}
