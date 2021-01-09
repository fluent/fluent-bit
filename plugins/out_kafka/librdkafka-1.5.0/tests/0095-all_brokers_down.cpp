/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019, Magnus Edenhill
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


class errorEventCb : public RdKafka::EventCb {
public:
  errorEventCb(): error_seen(false) { }

  void event_cb (RdKafka::Event &event) {
    switch (event.type())
      {
    case RdKafka::Event::EVENT_ERROR:
      Test::Say(tostr() << "Error: " << RdKafka::err2str(event.err()) <<
        ": " << event.str() << "\n");
      if (event.err() == RdKafka::ERR__ALL_BROKERS_DOWN)
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


extern "C" {
  int main_0095_all_brokers_down (int argc, char **argv) {
    RdKafka::Conf *conf;
    std::string errstr;

    Test::conf_init(&conf, NULL, 20);
    /* Two broker addresses that will quickly reject the connection */
    Test::conf_set(conf, "bootstrap.servers", "127.0.0.1:1,127.0.0.1:2");

    /*
     * First test producer
     */
    errorEventCb pEvent = errorEventCb();

    if (conf->set("event_cb", &pEvent, errstr) != RdKafka::Conf::CONF_OK)
      Test::Fail(errstr);

    Test::Say("Test Producer\n");

    RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
    if (!p)
      Test::Fail("Failed to create Producer: " + errstr);

    /* Wait for all brokers down */
    while (!pEvent.error_seen)
      p->poll(1000);

    delete p;


    /*
     * Test high-level consumer that has a logical broker (group coord),
     * which has caused AllBrokersDown generation problems (#2259)
     */
    errorEventCb cEvent = errorEventCb();

    Test::conf_set(conf, "group.id", "test");

    if (conf->set("event_cb", &cEvent, errstr) != RdKafka::Conf::CONF_OK)
      Test::Fail(errstr);

    Test::Say("Test KafkaConsumer\n");

    RdKafka::KafkaConsumer *c = RdKafka::KafkaConsumer::create(conf, errstr);
    if (!c)
      Test::Fail("Failed to create KafkaConsumer: " + errstr);

    delete conf;

    /* Wait for all brokers down */
    while (!cEvent.error_seen) {
      RdKafka::Message *m = c->consume(1000);
      if (m)
        delete m;
    }

    c->close();

    delete c;

    return 0;
  }
}
