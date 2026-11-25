/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2022, Magnus Edenhill
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
 * Verify that SASL credentials can be updated.
 */
#include "testcpp.h"

/* Include C API and test helpers for share consumer tests */
extern "C" {
#include "test.h"
#include "rdkafka.h"
}



class authErrorEventCb : public RdKafka::EventCb {
 public:
  authErrorEventCb() : error_seen(false) {
  }

  void event_cb(RdKafka::Event &event) {
    switch (event.type()) {
    case RdKafka::Event::EVENT_ERROR:
      Test::Say(tostr() << "Error: " << RdKafka::err2str(event.err()) << ": "
                        << event.str() << "\n");
      if (event.err() == RdKafka::ERR__AUTHENTICATION)
        error_seen = true;
      break;

    case RdKafka::Event::EVENT_LOG:
      Test::Say(tostr() << "Log: " << event.str() << "\n");
      break;

    default:
      break;
    }
  }

  bool error_seen;
};


/**
 * @brief Test setting SASL credentials.
 *
 * 1. Switch out the proper username/password for invalid ones.
 * 2. Verify that we get an auth failure.
 * 3. Set the proper username/passwords.
 * 4. Verify that we can now connect.
 */
static void do_test(bool set_after_auth_failure) {
  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 30);

  SUB_TEST_QUICK("set_after_auth_failure=%s",
                 set_after_auth_failure ? "yes" : "no");

  /* Get the correct sasl.username and sasl.password */
  std::string username, password;
  if (conf->get("sasl.username", username) ||
      conf->get("sasl.password", password)) {
    delete conf;
    SUB_TEST_SKIP("sasl.username and/or sasl.password not configured\n");
    return;
  }

  /* Replace with incorrect ones */
  Test::conf_set(conf, "sasl.username", "ThisIsNotRight");
  Test::conf_set(conf, "sasl.password", "Neither Is This");

  /* Set up an event callback to track authentication errors */
  authErrorEventCb pEvent = authErrorEventCb();
  std::string errstr;
  if (conf->set("event_cb", &pEvent, errstr) != RdKafka::Conf::CONF_OK)
    Test::Fail(errstr);

  /* Create client */
  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create Producer: " + errstr);
  delete conf;

  if (set_after_auth_failure) {
    Test::Say("Awaiting auth failure\n");

    while (!pEvent.error_seen)
      p->poll(1000);

    Test::Say("Authentication error seen\n");
  }

  Test::Say("Setting proper credentials\n");
  RdKafka::Error *error = p->sasl_set_credentials(username, password);
  if (error)
    Test::Fail("Failed to set credentials: " + error->str());

  Test::Say("Expecting successful cluster authentication\n");
  const std::string clusterid = p->clusterid(5 * 1000);

  if (clusterid.empty())
    Test::Fail("Expected clusterid() to succeed");

  delete p;

  SUB_TEST_PASS();
}

static rd_bool_t share_error_seen = rd_false;

static void share_auth_error_cb(rd_kafka_t *rk,
                                int err,
                                const char *reason,
                                void *opaque) {
  if (err == RD_KAFKA_RESP_ERR__AUTHENTICATION) {
    Test::Say(tostr() << "Share consumer auth error: "
                      << rd_kafka_err2str((rd_kafka_resp_err_t)err) << ": "
                      << reason << "\n");
    share_error_seen = rd_true;
  }
}

/**
 * @brief Test setting SASL credentials on a share consumer.
 *
 * 1. Produce a message to a topic.
 * 2. Create share consumer with wrong credentials (or correct if
 *    set_after_auth_failure is false).
 * 3. Optionally wait for auth failure.
 * 4. Set correct credentials via rd_kafka_share_sasl_set_credentials().
 * 5. Verify share consumer can consume the message.
 */
static void do_test_share_consumer(bool set_after_auth_failure) {
  rd_kafka_conf_t *conf;
  rd_kafka_t *p1;
  rd_kafka_share_t *sc;
  rd_kafka_topic_partition_list_t *subs;
  rd_kafka_messages_t *batch = NULL;
  rd_kafka_error_t *err;
  char errstr[512];
  char *username, *password;
  const char *topic;
  const char *group = "share-sasl-creds-test";
  size_t rcvd;
  int attempts;

  SUB_TEST("Share consumer: set_after_auth_failure=%s",
           set_after_auth_failure ? "yes" : "no");

  /* Get correct credentials from test config */
  test_conf_init(&conf, NULL, 30);
  username = rd_strdup(test_conf_get(conf, "sasl.username"));
  password = rd_strdup(test_conf_get(conf, "sasl.password"));

  /* Create a producer with correct creds, produce a message first */
  rd_kafka_conf_set_dr_msg_cb(conf, test_dr_msg_cb);
  p1 = test_create_handle(RD_KAFKA_PRODUCER, conf);

  topic = test_mk_topic_name("0135_share_sasl_creds", 1);
  test_create_topic_wait_exists(p1, topic, 1, 3, 5000);

  /* Set group config for earliest offset */
  test_share_set_auto_offset_reset(group, "earliest");

  /* Produce a message */
  test_produce_msgs_simple(p1, topic, 0, 1);

  /* Create share consumer */
  test_conf_init(&conf, NULL, 30);
  if (set_after_auth_failure) {
    /* Start with wrong credentials */
    test_conf_set(conf, "sasl.username", "ThisIsNotRight");
    test_conf_set(conf, "sasl.password", "Neither Is This");
  }
  rd_kafka_conf_set(conf, "group.id", group, errstr, sizeof(errstr));

  share_error_seen = rd_false;
  rd_kafka_conf_set_error_cb(conf, share_auth_error_cb);

  sc = rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
  TEST_ASSERT(sc != NULL, "Failed to create share consumer: %s", errstr);

  /* Subscribe */
  subs = rd_kafka_topic_partition_list_new(1);
  rd_kafka_topic_partition_list_add(subs, topic, RD_KAFKA_PARTITION_UA);
  rd_kafka_share_subscribe(sc, subs);
  rd_kafka_topic_partition_list_destroy(subs);

  if (set_after_auth_failure) {
    Test::Say("Awaiting share consumer auth failure\n");
    while (!share_error_seen) {
      err = rd_kafka_share_poll(sc, 1000, &batch);
      if (err)
        rd_kafka_error_destroy(err);
      rd_kafka_messages_destroy(batch);
      batch = NULL;
    }
    Test::Say("Share consumer authentication error seen\n");
  }

  /* Set correct credentials */
  Test::Say("Setting proper credentials on share consumer\n");
  err = rd_kafka_share_sasl_set_credentials(sc, username, password);
  TEST_ASSERT(!err, "share_sasl_set_credentials failed: %s",
              err ? rd_kafka_error_string(err) : "");

  /* Consume the message to verify connectivity */
  attempts = 100;
  rcvd     = 0;
  while (rcvd == 0 && attempts-- > 0) {
    err = rd_kafka_share_poll(sc, 3000, &batch);
    if (err)
      rd_kafka_error_destroy(err);
    rcvd = rd_kafka_messages_count(batch);
    if (rcvd == 0) {
      rd_kafka_messages_destroy(batch);
      batch = NULL;
    }
  }
  TEST_ASSERT(rcvd > 0,
              "Share consumer failed to consume message after "
              "credential update");
  rd_kafka_messages_destroy(batch);
  batch = NULL;

  Test::Say("Share consumer successfully consumed after credential update\n");

  rd_kafka_share_consumer_close(sc);
  rd_kafka_share_destroy(sc);
  rd_kafka_destroy(p1);
  free(username);
  free(password);

  SUB_TEST_PASS();
}

extern "C" {
int main_0135_sasl_credentials(int argc, char **argv) {
  const char *mech = test_conf_get(NULL, "sasl.mechanism");

  if (strcmp(mech, "PLAIN") && strncmp(mech, "SCRAM", 5)) {
    Test::Skip("Test requires SASL PLAIN or SASL SCRAM\n");
    return 0;
  }

  do_test(false);
  do_test(true);
  do_test_share_consumer(false);
  do_test_share_consumer(true);

  return 0;
}
}
