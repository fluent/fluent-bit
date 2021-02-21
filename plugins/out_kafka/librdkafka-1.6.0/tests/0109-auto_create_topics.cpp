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
 * Test consumer allow.auto.create.topics by subscribing to a mix
 * of available, unauthorized and non-existent topics.
 *
 * The same test is run with and without allow.auto.create.topics
 * and with and without wildcard subscribes.
 *
 */


static void do_test_consumer (bool allow_auto_create_topics,
                              bool with_wildcards) {
  Test::Say(tostr() << _C_MAG << "[ Test allow.auto.create.topics=" <<
            (allow_auto_create_topics ? "true":"false") <<
            " with_wildcards=" << (with_wildcards ? "true":"false") << " ]\n");

  bool has_acl_cli =
    test_broker_version >= TEST_BRKVER(2,1,0,0) &&
    !test_needs_auth(); /* We can't bother passing Java security config to
                         * kafka-acls.sh */

  bool supports_allow = test_broker_version >= TEST_BRKVER(0,11,0,0);

  std::string topic_exists = Test::mk_topic_name("0109-exists", 1);
  std::string topic_notexists = Test::mk_topic_name("0109-notexists", 1);
  std::string topic_unauth = Test::mk_topic_name("0109-unauthorized", 1);

  /* Create consumer */
  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 20);
  Test::conf_set(conf, "group.id", topic_exists);
  Test::conf_set(conf, "enable.partition.eof", "true");
  /* Quickly refresh metadata on topic auto-creation since the first
   * metadata after auto-create hides the topic due to 0 partition count. */
  Test::conf_set(conf, "topic.metadata.refresh.interval.ms", "1000");
  if (allow_auto_create_topics)
    Test::conf_set(conf, "allow.auto.create.topics", "true");

  std::string bootstraps;
  if (conf->get("bootstrap.servers", bootstraps) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to retrieve bootstrap.servers");

  std::string errstr;
  RdKafka::KafkaConsumer *c = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!c)
    Test::Fail("Failed to create KafkaConsumer: " + errstr);
  delete conf;

  /* Create topics */
  Test::create_topic(c, topic_exists.c_str(), 1, 1);

  if (has_acl_cli) {
    Test::create_topic(c, topic_unauth.c_str(), 1, 1);

    /* Add denying ACL for unauth topic */
    test_kafka_cmd("kafka-acls.sh --bootstrap-server %s "
                   "--add --deny-principal 'User:*' "
                   "--operation All --deny-host '*' "
                   "--topic '%s'",
                   bootstraps.c_str(), topic_unauth.c_str());
  }


  /* Wait for topic to be fully created */
  test_wait_topic_exists(NULL, topic_exists.c_str(), 10*1000);


  /*
   * Subscribe
   */
  std::vector<std::string> topics;
  std::map<std::string,RdKafka::ErrorCode> exp_errors;

  topics.push_back(topic_notexists);
  if (has_acl_cli)
    topics.push_back(topic_unauth);

  if (with_wildcards) {
    topics.push_back("^" + topic_exists);
    topics.push_back("^" + topic_notexists);
    /* If the subscription contains at least one wildcard/regex
     * then no auto topic creation will take place (since the consumer
     * requests all topics in metadata, and not specific ones, thus
     * not triggering topic auto creation).
     * We need to handle the expected error cases accordingly. */
    exp_errors["^" + topic_notexists] = RdKafka::ERR_UNKNOWN_TOPIC_OR_PART;
    exp_errors[topic_notexists] = RdKafka::ERR_UNKNOWN_TOPIC_OR_PART;

    if (has_acl_cli) {
      /* Unauthorized topics are not included in list-all-topics Metadata,
       * which we use for wildcards, so in this case the error code for
       * unauthorixed topics show up as unknown topic. */
      exp_errors[topic_unauth] = RdKafka::ERR_UNKNOWN_TOPIC_OR_PART;
    }
  } else {
    topics.push_back(topic_exists);

    if (has_acl_cli)
      exp_errors[topic_unauth] = RdKafka::ERR_TOPIC_AUTHORIZATION_FAILED;
  }

  if (supports_allow && !allow_auto_create_topics)
    exp_errors[topic_notexists] = RdKafka::ERR_UNKNOWN_TOPIC_OR_PART;

  RdKafka::ErrorCode err;
  if ((err = c->subscribe(topics)))
    Test::Fail("subscribe failed: " + RdKafka::err2str(err));

  /* Start consuming until EOF is reached, which indicates that we have an
   * assignment and any errors should have been reported. */
  bool run = true;
  while (run) {
    RdKafka::Message *msg = c->consume(tmout_multip(1000));
    switch (msg->err())
      {
      case RdKafka::ERR__TIMED_OUT:
      case RdKafka::ERR_NO_ERROR:
        break;

      case RdKafka::ERR__PARTITION_EOF:
        run = false;
        break;

      default:
        Test::Say("Consume error on " + msg->topic_name() +
                  ": " + msg->errstr() + "\n");

        std::map<std::string,RdKafka::ErrorCode>::iterator it =
          exp_errors.find(msg->topic_name());

        /* Temporary unknown-topic errors are okay for auto-created topics. */
        bool unknown_is_ok =
          allow_auto_create_topics &&
          !with_wildcards &&
          msg->err() == RdKafka::ERR_UNKNOWN_TOPIC_OR_PART &&
          msg->topic_name() == topic_notexists;

        if (it == exp_errors.end()) {
          if (unknown_is_ok)
            Test::Say("Ignoring temporary auto-create error for topic " +
                      msg->topic_name() + ": " +
                      RdKafka::err2str(msg->err()) + "\n");
          else
            Test::Fail("Did not expect error for " + msg->topic_name() +
                       ": got: " + RdKafka::err2str(msg->err()));
        } else if (msg->err() != it->second) {
          if (unknown_is_ok)
            Test::Say("Ignoring temporary auto-create error for topic " +
                      msg->topic_name() + ": " +
                      RdKafka::err2str(msg->err()) + "\n");
          else
            Test::Fail("Expected '" + RdKafka::err2str(it->second) + "' for " +
                       msg->topic_name() + ", got " +
                       RdKafka::err2str(msg->err()));
        } else {
          exp_errors.erase(msg->topic_name());
        }

        break;
      }

    delete msg;
  }


  /* Fail if not all expected errors were seen. */
  if (!exp_errors.empty())
    Test::Fail(tostr() << "Expecting " << exp_errors.size() << " more errors");

  c->close();

  delete c;
}

extern "C" {
  int main_0109_auto_create_topics (int argc, char **argv) {
    /* Parameters:
     *  allow auto create, with wildcards */
    do_test_consumer(true, true);
    do_test_consumer(true, false);
    do_test_consumer(false, true);
    do_test_consumer(false, false);

    return 0;
  }
}
