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

extern "C" {
int main_0135_sasl_credentials(int argc, char **argv) {
  const char *mech = test_conf_get(NULL, "sasl.mechanism");

  if (strcmp(mech, "PLAIN") && strncmp(mech, "SCRAM", 5)) {
    Test::Skip("Test requires SASL PLAIN or SASL SCRAM\n");
    return 0;
  }

  do_test(false);
  do_test(true);

  return 0;
}
}
