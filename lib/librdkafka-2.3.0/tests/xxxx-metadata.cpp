/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2022, Magnus Edenhill
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
 * - Generate unique topic name (there is a C function for that in test.h wihch
 * you should use)
 * - Query metadata for that topic
 * - Wait one second
 * - Query again, it should now have isrs and everything
 * Note: The test require auto.create.topics.enable = true in kafka server
 * properties.
 */


#define _GNU_SOURCE
#include <sys/time.h>
#include <time.h>
#include <string>
#include <sstream>
#include <iostream>


extern "C" {
#include "test.h"
}

/* Typical include path would be <librdkafka/rdkafka.h>, but this program
 * is built from within the librdkafka source tree and thus differs. */
#include "rdkafkacpp.h" /* for Kafka driver */

/**
 * Generate unique topic name (there is a C function for that in test.h wihch
 * you should use) Query metadata for that topic Wait one second Query again, it
 * should now have isrs and everything
 */
static void test_metadata_cpp(void) {
  RdKafka::Conf *conf = RdKafka::Conf::create(
      RdKafka::Conf::CONF_GLOBAL); /* @TODO: Do we need to merge with C
                                      test_conf_init()? */
  RdKafka::Conf *tconf = RdKafka::Conf::create(
      RdKafka::Conf::CONF_TOPIC); /* @TODO: Same of prev */

  RdKafka::Metadata *metadata;
  RdKafka::ErrorCode err;
  int msgcnt        = test_on_ci ? 1000 : 10000;
  int partition_cnt = 2;
  int i;
  uint64_t testid;
  int msg_base = 0;
  std::string errstr;
  const char *topic_str = test_mk_topic_name("0013", 1);
  /*        if(!topic){
                  TEST_FAIL()
          }*/

  // const RdKafka::Conf::ConfResult confResult =
  // conf->set("debug","all",errstr); if(confResult != RdKafka::Conf::CONF_OK){
  //        std::stringstream errstring;
  //        errstring << "Can't set config" << errstr;
  //        TEST_FAIL(errstring.str().c_str());
  //}

  TEST_SAY("Topic %s.\n", topic_str);

  const RdKafka::Conf::ConfResult confBrokerResult =
      conf->set("metadata.broker.list", "localhost:9092", errstr);
  if (confBrokerResult != RdKafka::Conf::CONF_OK) {
    std::stringstream errstring;
    errstring << "Can't set broker" << errstr;
    TEST_FAIL(errstring.str().c_str());
  }

  /* Create a producer to fetch metadata */
  RdKafka::Producer *producer = RdKafka::Producer::create(conf, errstr);
  if (!producer) {
    std::stringstream errstring;
    errstring << "Can't create producer" << errstr;
    TEST_FAIL(errstring.str().c_str());
  }

  /*
   * Create topic handle.
   */
  RdKafka::Topic *topic = NULL;
  topic = RdKafka::Topic::create(producer, topic_str, tconf, errstr);
  if (!topic) {
    std::stringstream errstring;
    errstring << "Can't create topic" << errstr;
    exit(1);
  }

  /* First request of metadata: It have to fail */
  err = producer->metadata(topic != NULL, topic, &metadata, 5000);
  if (err != RdKafka::ERR_NO_ERROR) {
    std::stringstream errstring;
    errstring << "Can't request first metadata: " << errstr;
    TEST_FAIL(errstring.str().c_str());
  }

  /* It's a new topic, it should have no partitions */
  if (metadata->topics()->at(0)->partitions()->size() != 0) {
    TEST_FAIL("ISRS != 0");
  }

  sleep(1);

  /* Second request of metadata: It have to success */
  err = producer->metadata(topic != NULL, topic, &metadata, 5000);

  /* It should have now partitions */
  if (metadata->topics()->at(0)->partitions()->size() == 0) {
    TEST_FAIL("ISRS == 0");
  }


  delete topic;
  delete producer;
  delete tconf;
  delete conf;

  /* Wait for everything to be cleaned up since broker destroys are
   * handled in its own thread. */
  test_wait_exit(10);

  /* If we havent failed at this point then
   * there were no threads leaked */
  return;
}

int main(int argc, char **argv) {
  test_conf_init(NULL, NULL, 20);
  test_metadata_cpp();
  return 0;
}
