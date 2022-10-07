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


/**
 * @brief Let FetchRequests fail with authorization failure.
 *
 */


static void do_test_fetch_unauth() {
  Test::Say(tostr() << _C_MAG << "[ Test unauthorized Fetch ]\n");

  std::string topic = Test::mk_topic_name("0119-fetch_unauth", 1);

  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 20);

  Test::conf_set(conf, "group.id", topic);

  std::string bootstraps;
  if (conf->get("bootstrap.servers", bootstraps) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to retrieve bootstrap.servers");

  std::string errstr;
  RdKafka::KafkaConsumer *c = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!c)
    Test::Fail("Failed to create KafkaConsumer: " + errstr);
  delete conf;

  /* Create topic */
  const int partition_cnt = 3;
  Test::create_topic(NULL, topic.c_str(), partition_cnt, 1);

  /* Produce messages */
  test_produce_msgs_easy(topic.c_str(), 0, RdKafka::Topic::PARTITION_UA, 1000);

  /* Add ACLs:
   *   Allow Describe (Metadata)
   *   Deny Read (Fetch)
   */

  test_kafka_cmd(
      "kafka-acls.sh --bootstrap-server %s "
      "--add --allow-principal 'User:*' "
      "--operation Describe --allow-host '*' "
      "--topic '%s'",
      bootstraps.c_str(), topic.c_str());

  test_kafka_cmd(
      "kafka-acls.sh --bootstrap-server %s "
      "--add --deny-principal 'User:*' "
      "--operation Read --deny-host '*' "
      "--topic '%s'",
      bootstraps.c_str(), topic.c_str());

  Test::subscribe(c, topic);

  int auth_err_cnt = 0;

  /* Consume for 15s (30*0.5), counting the number of auth errors,
   * should only see one error per consumed partition, and no messages. */
  for (int i = 0; i < 30; i++) {
    RdKafka::Message *msg;

    msg = c->consume(500);
    TEST_ASSERT(msg, "Expected msg");

    switch (msg->err()) {
    case RdKafka::ERR__TIMED_OUT:
      break;

    case RdKafka::ERR_NO_ERROR:
      Test::Fail("Did not expect a valid message");
      break;

    case RdKafka::ERR_TOPIC_AUTHORIZATION_FAILED:
      Test::Say(tostr() << "Consumer error on " << msg->topic_name() << " ["
                        << msg->partition() << "]: " << msg->errstr() << "\n");

      if (auth_err_cnt++ > partition_cnt)
        Test::Fail(
            "Too many auth errors received, "
            "expected same as number of partitions");
      break;

    default:
      Test::Fail(tostr() << "Unexpected consumer error on " << msg->topic_name()
                         << " [" << msg->partition() << "]: " << msg->errstr());
      break;
    }

    delete msg;
  }

  TEST_ASSERT(auth_err_cnt == partition_cnt,
              "Expected exactly %d auth errors, saw %d", partition_cnt,
              auth_err_cnt);

  delete c;

  Test::Say(tostr() << _C_GRN << "[ Test unauthorized Fetch PASS ]\n");
}

extern "C" {
int main_0119_consumer_auth(int argc, char **argv) {
  /* We can't bother passing Java security config to kafka-acls.sh */
  if (test_needs_auth()) {
    Test::Skip("Cluster authentication required\n");
    return 0;
  }

  do_test_fetch_unauth();

  return 0;
}
}
