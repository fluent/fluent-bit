/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2021, Magnus Edenhill
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

extern "C" {
int main_0128_sasl_callback_queue(int argc, char **argv) {
  if (!test_check_builtin("sasl_oauthbearer")) {
    Test::Skip("Test requires OAUTHBEARER support\n");
    return 0;
  }

  do_test(true);
  do_test(false);

  return 0;
}
}
