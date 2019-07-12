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


#include "testcpp.h"
#include <cstring>

/**
 * Verification of difference between empty and null Key and Value
 */


static int check_equal (const char *exp,
                         const char *actual, size_t len,
                         std::string what) {
  size_t exp_len = exp ? strlen(exp) : 0;
  int failures = 0;

  if (!actual && len != 0) {
    Test::FailLater(tostr() << what << ": expected length 0 for Null, not " << len);
    failures++;
  }

  if (exp) {
    if (!actual) {
      Test::FailLater(tostr() << what << ": expected \"" << exp << "\", not Null");
      failures++;

    } else if (len != exp_len || strncmp(exp, actual, exp_len)) {
      Test::FailLater(tostr() << what << ": expected \"" << exp << "\", not \"" << actual << "\" (" << len << " bytes)");
      failures++;
    }

  } else {
    if (actual) {
      Test::FailLater(tostr() << what << ": expected Null, not \"" << actual << "\" (" << len << " bytes)");
      failures++;
    }
  }

  if (!failures)
    Test::Say(3, tostr() << what << ": matched expectation\n");

  return failures;
}


static void do_test_null_empty (bool api_version_request) {
  std::string topic = Test::mk_topic_name("0070_null_empty", 1);
  const int partition = 0;

  Test::Say(tostr() << "Testing with api.version.request=" << api_version_request << " on topic " << topic << " partition " << partition << "\n");

  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 0);
  Test::conf_set(conf, "api.version.request",
                 api_version_request ? "true" : "false");
  Test::conf_set(conf, "acks", "all");


  std::string errstr;
  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create Producer: " + errstr);
  delete conf;

  const int msgcnt = 8;
  static const char *msgs[msgcnt*2] = {
    NULL, NULL,
    "key2", NULL,
    "key3", "val3",
    NULL, "val4",
    "", NULL,
    NULL, "",
    "", ""
  };

  RdKafka::ErrorCode err;

  for (int i = 0 ; i < msgcnt * 2 ; i += 2) {
    Test::Say(3, tostr() << "Produce message #" << (i/2) <<
              ": key=\"" << (msgs[i] ? msgs[i] : "Null") <<
              "\", value=\"" << (msgs[i+1] ? msgs[i+1] : "Null") << "\"\n");
    err = p->produce(topic, partition, RdKafka::Producer::RK_MSG_COPY,
                     /* Value */
                     (void *)msgs[i+1], msgs[i+1] ? strlen(msgs[i+1]) : 0,
                     /* Key */
                     (void *)msgs[i], msgs[i] ? strlen(msgs[i]) : 0,
                     0, NULL);
    if (err != RdKafka::ERR_NO_ERROR)
      Test::Fail("Produce failed: " + RdKafka::err2str(err));
  }

  if (p->flush(tmout_multip(3*5000)) != 0)
    Test::Fail("Not all messages flushed");

  Test::Say(tostr() << "Produced " << msgcnt << " messages to " << topic << "\n");

  delete p;

  /*
   * Now consume messages from the beginning, making sure they match
   * what was produced.
   */

  /* Create consumer */
  Test::conf_init(&conf, NULL, 10);
  Test::conf_set(conf, "group.id", topic);
  Test::conf_set(conf, "api.version.request",
                 api_version_request ? "true" : "false");
  Test::conf_set(conf, "enable.auto.commit", "false");

  RdKafka::KafkaConsumer *c = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!c)
    Test::Fail("Failed to create KafkaConsumer: " + errstr);
  delete conf;

  /* Assign the partition */
  std::vector<RdKafka::TopicPartition*> parts;
  parts.push_back(RdKafka::TopicPartition::create(topic, partition,
                                                 RdKafka::Topic::OFFSET_BEGINNING));
  err = c->assign(parts);
  if (err != RdKafka::ERR_NO_ERROR)
    Test::Fail("assign() failed: " + RdKafka::err2str(err));
  RdKafka::TopicPartition::destroy(parts);

  /* Start consuming */
  int failures = 0;
  for (int i = 0 ; i < msgcnt * 2 ; i += 2) {
    RdKafka::Message *msg = c->consume(tmout_multip(5000));
    if (msg->err())
      Test::Fail(tostr() << "consume() failed at message " << (i/2) << ": " <<
                 msg->errstr());

    /* verify key */
    failures += check_equal(msgs[i], msg->key() ? msg->key()->c_str() : NULL, msg->key_len(),
                            tostr() << "message #" << (i/2) << " (offset " << msg->offset() << ") key");
    /* verify key_pointer() API as too */
    failures += check_equal(msgs[i], (const char *)msg->key_pointer(), msg->key_len(),
                tostr() << "message #" << (i/2) << " (offset " << msg->offset() << ") key");

    /* verify value */
    failures += check_equal(msgs[i+1], (const char *)msg->payload(), msg->len(),
                tostr() << "message #" << (i/2) << " (offset " << msg->offset() << ") value");
    delete msg;
  }

  Test::Say(tostr() << "Done consuming, closing. " << failures << " test failures\n");
  if (failures)
    Test::Fail(tostr() << "See " << failures << "  previous test failure(s)");

  c->close();
  delete c;
}


extern "C" {
  int main_0070_null_empty (int argc, char **argv) {
    do_test_null_empty(true);
    do_test_null_empty(false);
    return 0;
  }
}
