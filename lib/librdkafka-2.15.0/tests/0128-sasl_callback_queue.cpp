/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2021-2022, Magnus Edenhill
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
 * Verify that background SASL callback queues work by calling
 * a non-polling API after client creation.
 */
#include "testcpp.h"
#include "rdatomic.h"

/* Include C API for share consumer tests */
extern "C" {
#include "rdkafka.h"
}

namespace {
/* Provide our own token refresh callback */
class MyCb : public RdKafka::OAuthBearerTokenRefreshCb {
 public:
  MyCb() {
    rd_atomic32_init(&called_, 0);
  }

  bool called() {
    return rd_atomic32_get(&called_) > 0;
  }

  void oauthbearer_token_refresh_cb(RdKafka::Handle *handle,
                                    const std::string &oauthbearer_config) {
    handle->oauthbearer_set_token_failure(
        "Not implemented by this test, "
        "but that's okay");
    rd_atomic32_add(&called_, 1);
    Test::Say("Callback called!\n");
  }

  rd_atomic32_t called_;
};
};  // namespace


static void do_test(bool use_background_queue) {
  SUB_TEST("Use background queue = %s", use_background_queue ? "yes" : "no");

  bool expect_called = use_background_queue;

  RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);

  Test::conf_set(conf, "security.protocol", "SASL_PLAINTEXT");
  Test::conf_set(conf, "sasl.mechanism", "OAUTHBEARER");

  std::string errstr;

  MyCb mycb;
  if (conf->set("oauthbearer_token_refresh_cb", &mycb, errstr))
    Test::Fail("Failed to set refresh callback: " + errstr);

  if (use_background_queue)
    if (conf->enable_sasl_queue(true, errstr))
      Test::Fail("Failed to enable SASL queue: " + errstr);

  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create Producer: " + errstr);
  delete conf;

  if (use_background_queue) {
    RdKafka::Error *error = p->sasl_background_callbacks_enable();
    if (error)
      Test::Fail("sasl_background_callbacks_enable() failed: " + error->str());
  }

  /* This call should fail since the refresh callback fails,
   * and there are no brokers configured anyway. */
  const std::string clusterid = p->clusterid(5 * 1000);

  TEST_ASSERT(clusterid.empty(),
              "Expected clusterid() to fail since the token was not set");

  if (expect_called)
    TEST_ASSERT(mycb.called(),
                "Expected refresh callback to have been called by now");
  else
    TEST_ASSERT(!mycb.called(),
                "Did not expect refresh callback to have been called");

  delete p;

  SUB_TEST_PASS();
}

static rd_atomic32_t share_cb_called;

static void share_refresh_cb(rd_kafka_t *rk,
                             const char *oauthbearer_config,
                             void *opaque) {
  rd_kafka_oauthbearer_set_token_failure(rk,
                                         "Not implemented by this test, "
                                         "but that's okay");
  rd_atomic32_add(&share_cb_called, 1);
  Test::Say("Share consumer refresh callback called!\n");
}

/**
 * @brief Verify that background SASL callback queues work with
 *        a share consumer using the C API.
 *
 * When use_background_queue is true, the SASL queue is enabled and
 * forwarded to the background thread. The callback should fire even
 * from a non-polling API (clusterid).
 *
 * When use_background_queue is false, the callback should still fire
 * when polling via share_consume_batch (which serves the main queue).
 */
static void do_test_share_consumer(bool use_background_queue) {
  SUB_TEST("Share consumer: Use background queue = %s",
           use_background_queue ? "yes" : "no");

  rd_kafka_conf_t *conf = rd_kafka_conf_new();
  char errstr[512];

  rd_kafka_conf_set(conf, "security.protocol", "SASL_PLAINTEXT", errstr,
                    sizeof(errstr));
  rd_kafka_conf_set(conf, "sasl.mechanism", "OAUTHBEARER", errstr,
                    sizeof(errstr));
  rd_kafka_conf_set(conf, "group.id", "share-sasl-callback-test", errstr,
                    sizeof(errstr));

  if (use_background_queue)
    rd_kafka_conf_enable_sasl_queue(conf, 1);

  rd_atomic32_init(&share_cb_called, 0);
  rd_kafka_conf_set_oauthbearer_token_refresh_cb(conf, share_refresh_cb);

  rd_kafka_share_t *rkshare =
      rd_kafka_share_consumer_new(conf, errstr, sizeof(errstr));
  TEST_ASSERT(rkshare != NULL, "Failed to create share consumer: %s", errstr);

  if (use_background_queue) {
    rd_kafka_error_t *error =
        rd_kafka_share_sasl_background_callbacks_enable(rkshare);
    if (error)
      Test::Fail("share_sasl_background_callbacks_enable() failed: " +
                 std::string(rd_kafka_error_string(error)));

    /* Call a non-polling share consumer API — the callback should
     * still fire via the background thread. */
    rd_kafka_topic_partition_list_t *sub = NULL;
    rd_kafka_share_subscription(rkshare, &sub);
    if (sub)
      rd_kafka_topic_partition_list_destroy(sub);

  } else {
    /* Poll via share_poll — this serves the main queue
     * which should trigger the OAUTHBEARER refresh callback. */
    rd_kafka_messages_t *batch = NULL;
    rd_kafka_error_t *err      = rd_kafka_share_poll(rkshare, 1000, &batch);
    if (err)
      rd_kafka_error_destroy(err);
    rd_kafka_messages_destroy(batch);
    batch = NULL;
  }

  Test::Say(tostr() << "share_cb_called = " << rd_atomic32_get(&share_cb_called)
                    << "\n");
  TEST_ASSERT(rd_atomic32_get(&share_cb_called) > 0,
              "Expected refresh callback to have been called "
              "for share consumer");

  rd_kafka_share_consumer_close(rkshare);
  rd_kafka_share_destroy(rkshare);

  SUB_TEST_PASS();
}


extern "C" {
int main_0128_sasl_callback_queue(int argc, char **argv) {
  if (!test_check_builtin("sasl_oauthbearer")) {
    Test::Skip("Test requires OAUTHBEARER support\n");
    return 0;
  }

  do_test(true);
  do_test(false);
  do_test_share_consumer(true);
  do_test_share_consumer(false);

  return 0;
}
}
