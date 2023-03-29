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
extern "C" {
#include "test.h"
#include "tinycthread.h"
#include "rdatomic.h"
}

/**
 * Test KafkaConsumer close and destructor behaviour.
 */


struct args {
  RdKafka::Queue *queue;
  RdKafka::KafkaConsumer *c;
};

static int run_polling_thread(void *p) {
  struct args *args = (struct args *)p;

  while (!args->c->closed()) {
    RdKafka::Message *msg;

    /* We use a long timeout to also verify that the
     * consume() call is yielded/woken by librdkafka
     * when consumer_close_queue() finishes. */
    msg = args->queue->consume(60 * 1000 /*60s*/);
    if (msg)
      delete msg;
  }

  return 0;
}


static void start_polling_thread(thrd_t *thrd, struct args *args) {
  if (thrd_create(thrd, run_polling_thread, (void *)args) != thrd_success)
    Test::Fail("Failed to create thread");
}

static void stop_polling_thread(thrd_t thrd, struct args *args) {
  int ret;
  if (thrd_join(thrd, &ret) != thrd_success)
    Test::Fail("Thread join failed");
}


static void do_test_consumer_close(bool do_subscribe,
                                   bool do_unsubscribe,
                                   bool do_close,
                                   bool with_queue) {
  std::string testname = tostr()
                         << "Test C++ KafkaConsumer close "
                         << "subscribe=" << do_subscribe
                         << ", unsubscribe=" << do_unsubscribe
                         << ", close=" << do_close << ", queue=" << with_queue;
  SUB_TEST("%s", testname.c_str());

  rd_kafka_mock_cluster_t *mcluster;
  const char *bootstraps;

  mcluster = test_mock_cluster_new(3, &bootstraps);

  std::string errstr;

  /*
   * Produce messages to topics
   */
  const int msgs_per_partition = 10;
  RdKafka::Conf *pconf;
  Test::conf_init(&pconf, NULL, 10);
  Test::conf_set(pconf, "bootstrap.servers", bootstraps);
  RdKafka::Producer *p = RdKafka::Producer::create(pconf, errstr);
  if (!p)
    Test::Fail(tostr() << __FUNCTION__
                       << ": Failed to create producer: " << errstr);
  delete pconf;
  Test::produce_msgs(p, "some_topic", 0, msgs_per_partition, 10,
                     true /*flush*/);
  delete p;

  /* Create consumer */
  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 0);
  Test::conf_set(conf, "bootstrap.servers", bootstraps);
  Test::conf_set(conf, "group.id", "mygroup");
  Test::conf_set(conf, "auto.offset.reset", "beginning");

  RdKafka::KafkaConsumer *c = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!c)
    Test::Fail("Failed to create KafkaConsumer: " + errstr);
  delete conf;

  if (do_subscribe) {
    std::vector<std::string> topics;
    topics.push_back("some_topic");
    RdKafka::ErrorCode err;
    if ((err = c->subscribe(topics)))
      Test::Fail("subscribe failed: " + RdKafka::err2str(err));
  }

  int received = 0;
  while (received < msgs_per_partition) {
    RdKafka::Message *msg = c->consume(500);
    if (msg) {
      ++received;
      delete msg;
    }
  }

  RdKafka::ErrorCode err;
  if (do_unsubscribe)
    if ((err = c->unsubscribe()))
      Test::Fail("unsubscribe failed: " + RdKafka::err2str(err));

  if (do_close) {
    if (with_queue) {
      RdKafka::Queue *queue = RdKafka::Queue::create(c);
      struct args args      = {queue, c};
      thrd_t thrd;

      /* Serve queue in background thread until close() is done */
      start_polling_thread(&thrd, &args);

      RdKafka::Error *error;

      Test::Say("Closing with queue\n");
      if ((error = c->close(queue)))
        Test::Fail("close(queue) failed: " + error->str());

      stop_polling_thread(thrd, &args);

      Test::Say("Attempting second close\n");
      /* A second call should fail */
      if (!(error = c->close(queue)))
        Test::Fail("Expected second close(queue) to fail");
      if (error->code() != RdKafka::ERR__DESTROY)
        Test::Fail("Expected second close(queue) to fail with DESTROY, not " +
                   error->str());
      delete error;

      delete queue;

    } else {
      if ((err = c->close()))
        Test::Fail("close failed: " + RdKafka::err2str(err));

      /* A second call should fail */
      if ((err = c->close()) != RdKafka::ERR__DESTROY)
        Test::Fail("Expected second close to fail with DESTROY, not " +
                   RdKafka::err2str(err));
    }
  }

  /* Call an async method that will do nothing but verify that we're not
   * crashing due to use-after-free. */
  if ((err = c->commitAsync()))
    Test::Fail("Expected commitAsync close to succeed, got " +
               RdKafka::err2str(err));

  delete c;

  test_mock_cluster_destroy(mcluster);

  SUB_TEST_PASS();
}

extern "C" {
int main_0116_kafkaconsumer_close(int argc, char **argv) {
  /* Parameters:
   *  subscribe, unsubscribe, close, with_queue */
  for (int i = 0; i < 1 << 4; i++) {
    bool subscribe   = i & (1 << 0);
    bool unsubscribe = i & (1 << 1);
    bool do_close    = i & (1 << 2);
    bool with_queue  = i & (1 << 3);
    do_test_consumer_close(subscribe, unsubscribe, do_close, with_queue);
  }

  return 0;
}
}
