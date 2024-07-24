/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2023, Confluent Inc.
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

using namespace std;

/**
 * @brief Committed metadata should be stored and received back when
 *        checking committed offsets.
 */
static void test_commit_metadata() {
  SUB_TEST_QUICK();

  std::string bootstraps;
  std::string errstr;
  RdKafka::ErrorCode err;

  RdKafka::Conf *conf;
  std::string topic = Test::mk_topic_name(__FUNCTION__, 1);
  Test::conf_init(&conf, NULL, 3000);
  Test::conf_set(conf, "group.id", topic);

  RdKafka::KafkaConsumer *consumer =
      RdKafka::KafkaConsumer::create(conf, errstr);
  if (!consumer)
    Test::Fail("Failed to create KafkaConsumer: " + errstr);
  delete conf;

  Test::Say("Create topic.\n");
  Test::create_topic(consumer, topic.c_str(), 1, 1);

  Test::Say("Commit offsets.\n");
  std::vector<RdKafka::TopicPartition *> offsets;
  RdKafka::TopicPartition *offset =
      RdKafka::TopicPartition::create(topic, 0, 10);

  std::string metadata = "some_metadata";
  std::vector<unsigned char> metadata_vect(metadata.begin(), metadata.end());

  offset->set_metadata(metadata_vect);
  offsets.push_back(offset);

  err = consumer->commitSync(offsets);
  TEST_ASSERT(!err, "commit failed: %s", RdKafka::err2str(err).c_str());
  RdKafka::TopicPartition::destroy(offsets);

  Test::Say("Read committed offsets.\n");
  offset = RdKafka::TopicPartition::create(topic, 0, 10);
  offsets.push_back(offset);
  err = consumer->committed(offsets, 5000);
  TEST_ASSERT(!err, "committed offsets failed: %s",
              RdKafka::err2str(err).c_str());
  TEST_ASSERT(offsets.size() == 1, "expected offsets size 1, got %" PRIusz,
              offsets.size());

  Test::Say("Check committed metadata.\n");
  std::vector<unsigned char> metadata_vect_committed =
      offsets[0]->get_metadata();
  std::string metadata_committed(metadata_vect_committed.begin(),
                                 metadata_vect_committed.end());

  if (metadata != metadata_committed) {
    Test::Fail(tostr() << "Expecting metadata to be \"" << metadata
                       << "\", got \"" << metadata_committed << "\"");
  }

  RdKafka::TopicPartition::destroy(offsets);

  consumer->close();

  delete consumer;

  SUB_TEST_PASS();
}

extern "C" {
int main_0140_commit_metadata(int argc, char **argv) {
  test_commit_metadata();
  return 0;
}
}
