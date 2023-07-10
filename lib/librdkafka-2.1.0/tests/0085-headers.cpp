/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2015, Magnus Edenhill
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


static RdKafka::Producer *producer;
static RdKafka::KafkaConsumer *consumer;
static std::string topic;

static void assert_all_headers_match(RdKafka::Headers *actual,
                                     const RdKafka::Headers *expected) {
  if (!actual) {
    Test::Fail("Expected RdKafka::Message to contain headers");
  }
  if (actual->size() != expected->size()) {
    Test::Fail(tostr() << "Expected headers length to equal "
                       << expected->size() << " instead equals "
                       << actual->size() << "\n");
  }

  std::vector<RdKafka::Headers::Header> actual_headers   = actual->get_all();
  std::vector<RdKafka::Headers::Header> expected_headers = expected->get_all();
  Test::Say(3, tostr() << "Header size " << actual_headers.size() << "\n");
  for (size_t i = 0; i < actual_headers.size(); i++) {
    RdKafka::Headers::Header actual_header         = actual_headers[i];
    const RdKafka::Headers::Header expected_header = expected_headers[i];
    std::string actual_key                         = actual_header.key();
    std::string actual_value =
        std::string(actual_header.value_string(), actual_header.value_size());
    std::string expected_key = expected_header.key();
    std::string expected_value =
        std::string(actual_header.value_string(), expected_header.value_size());

    Test::Say(3, tostr() << "Expected Key " << expected_key << ", Expected val "
                         << expected_value << ", Actual key " << actual_key
                         << ", Actual val " << actual_value << "\n");

    if (actual_key != expected_key) {
      Test::Fail(tostr() << "Header key does not match, expected '"
                         << actual_key << "' but got '" << expected_key
                         << "'\n");
    }
    if (actual_value != expected_value) {
      Test::Fail(tostr() << "Header value does not match, expected '"
                         << actual_value << "' but got '" << expected_value
                         << "'\n");
    }
  }
}

static void test_headers(RdKafka::Headers *produce_headers,
                         const RdKafka::Headers *compare_headers) {
  RdKafka::ErrorCode err;

  err = producer->produce(topic, 0, RdKafka::Producer::RK_MSG_COPY,
                          (void *)"message", 7, (void *)"key", 3, 0,
                          produce_headers, NULL);
  if (err)
    Test::Fail("produce() failed: " + RdKafka::err2str(err));

  producer->flush(tmout_multip(10 * 1000));

  if (producer->outq_len() > 0)
    Test::Fail(tostr() << "Expected producer to be flushed, "
                       << producer->outq_len() << " messages remain");

  int cnt      = 0;
  bool running = true;

  while (running) {
    RdKafka::Message *msg = consumer->consume(10 * 1000);

    if (msg->err() == RdKafka::ERR_NO_ERROR) {
      cnt++;
      RdKafka::Headers *headers = msg->headers();
      if (compare_headers->size() > 0) {
        assert_all_headers_match(headers, compare_headers);
      } else {
        if (headers != 0) {
          Test::Fail("Expected headers to return a NULL pointer");
        }
      }
      running = false;
    } else {
      Test::Fail("consume() failed: " + msg->errstr());
    }
    delete msg;
  }
}

static void test_headers(int num_hdrs) {
  Test::Say(tostr() << "Test " << num_hdrs
                    << " headers in consumed message.\n");
  RdKafka::Headers *produce_headers = RdKafka::Headers::create();
  RdKafka::Headers *compare_headers = RdKafka::Headers::create();
  for (int i = 0; i < num_hdrs; ++i) {
    std::stringstream key_s;
    key_s << "header_" << i;
    std::string key = key_s.str();

    if ((i % 4) == 0) {
      /* NULL value */
      produce_headers->add(key, NULL, 0);
      compare_headers->add(key, NULL, 0);
    } else if ((i % 5) == 0) {
      /* Empty value, use different methods for produce
       * and compare to make sure they behave the same way. */
      std::string val = "";
      produce_headers->add(key, val);
      compare_headers->add(key, "", 0);
    } else if ((i % 6) == 0) {
      /* Binary value (no nul-term) */
      produce_headers->add(key, "binary", 6);
      compare_headers->add(key, "binary"); /* auto-nul-terminated */
    } else {
      /* Standard string value */
      std::stringstream val_s;
      val_s << "value_" << i;
      std::string val = val_s.str();
      produce_headers->add(key, val);
      compare_headers->add(key, val);
    }
  }
  test_headers(produce_headers, compare_headers);
  delete compare_headers;
}

static void test_duplicate_keys() {
  Test::Say("Test multiple headers with duplicate keys.\n");
  int num_hdrs                      = 4;
  RdKafka::Headers *produce_headers = RdKafka::Headers::create();
  RdKafka::Headers *compare_headers = RdKafka::Headers::create();
  for (int i = 0; i < num_hdrs; ++i) {
    std::string dup_key = "dup_key";
    std::stringstream val_s;
    val_s << "value_" << i;
    std::string val = val_s.str();
    produce_headers->add(dup_key, val);
    compare_headers->add(dup_key, val);
  }
  test_headers(produce_headers, compare_headers);
  delete compare_headers;
}

static void test_remove_after_add() {
  Test::Say("Test removing after adding headers.\n");
  RdKafka::Headers *headers = RdKafka::Headers::create();

  // Add one unique key
  std::string key_one = "key1";
  std::string val_one = "val_one";
  headers->add(key_one, val_one);

  // Add a second unique key
  std::string key_two = "key2";
  std::string val_two = "val_two";
  headers->add(key_two, val_one);

  // Assert header length is 2
  size_t expected_size = 2;
  if (headers->size() != expected_size) {
    Test::Fail(tostr() << "Expected header->size() to equal " << expected_size
                       << ", instead got " << headers->size() << "\n");
  }

  // Remove key_one and assert headers == 1
  headers->remove(key_one);
  size_t expected_remove_size = 1;
  if (headers->size() != expected_remove_size) {
    Test::Fail(tostr() << "Expected header->size() to equal "
                       << expected_remove_size << ", instead got "
                       << headers->size() << "\n");
  }

  delete headers;
}

static void test_remove_all_duplicate_keys() {
  Test::Say("Test removing duplicate keys removes all headers.\n");
  RdKafka::Headers *headers = RdKafka::Headers::create();

  // Add one unique key
  std::string key_one = "key1";
  std::string val_one = "val_one";
  headers->add(key_one, val_one);

  // Add 2 duplicate keys
  std::string dup_key = "dup_key";
  std::string val_two = "val_two";
  headers->add(dup_key, val_one);
  headers->add(dup_key, val_two);

  // Assert header length is 3
  size_t expected_size = 3;
  if (headers->size() != expected_size) {
    Test::Fail(tostr() << "Expected header->size() to equal " << expected_size
                       << ", instead got " << headers->size() << "\n");
  }

  // Remove key_one and assert headers == 1
  headers->remove(dup_key);
  size_t expected_size_remove = 1;
  if (headers->size() != expected_size_remove) {
    Test::Fail(tostr() << "Expected header->size() to equal "
                       << expected_size_remove << ", instead got "
                       << headers->size() << "\n");
  }

  delete headers;
}

static void test_get_last_gives_last_added_val() {
  Test::Say("Test get_last returns the last added value of duplicate keys.\n");
  RdKafka::Headers *headers = RdKafka::Headers::create();

  // Add two duplicate keys
  std::string dup_key   = "dup_key";
  std::string val_one   = "val_one";
  std::string val_two   = "val_two";
  std::string val_three = "val_three";
  headers->add(dup_key, val_one);
  headers->add(dup_key, val_two);
  headers->add(dup_key, val_three);

  // Assert header length is 3
  size_t expected_size = 3;
  if (headers->size() != expected_size) {
    Test::Fail(tostr() << "Expected header->size() to equal " << expected_size
                       << ", instead got " << headers->size() << "\n");
  }

  // Get last of duplicate key and assert it equals val_two
  RdKafka::Headers::Header last = headers->get_last(dup_key);
  std::string value             = std::string(last.value_string());
  if (value != val_three) {
    Test::Fail(tostr() << "Expected get_last to return " << val_two
                       << " as the value of the header instead got " << value
                       << "\n");
  }

  delete headers;
}

static void test_get_of_key_returns_all() {
  Test::Say("Test get returns all the headers of a duplicate key.\n");
  RdKafka::Headers *headers = RdKafka::Headers::create();

  // Add two duplicate keys
  std::string unique_key = "unique";
  std::string dup_key    = "dup_key";
  std::string val_one    = "val_one";
  std::string val_two    = "val_two";
  std::string val_three  = "val_three";
  headers->add(unique_key, val_one);
  headers->add(dup_key, val_one);
  headers->add(dup_key, val_two);
  headers->add(dup_key, val_three);

  // Assert header length is 4
  size_t expected_size = 4;
  if (headers->size() != expected_size) {
    Test::Fail(tostr() << "Expected header->size() to equal " << expected_size
                       << ", instead got " << headers->size() << "\n");
  }

  // Get all of the duplicate key
  std::vector<RdKafka::Headers::Header> get = headers->get(dup_key);
  size_t expected_get_size                  = 3;
  if (get.size() != expected_get_size) {
    Test::Fail(tostr() << "Expected header->size() to equal "
                       << expected_get_size << ", instead got "
                       << headers->size() << "\n");
  }

  delete headers;
}

static void test_failed_produce() {
  RdKafka::Headers *headers = RdKafka::Headers::create();
  headers->add("my", "header");

  RdKafka::ErrorCode err;

  err = producer->produce(topic, 999 /* invalid partition */,
                          RdKafka::Producer::RK_MSG_COPY, (void *)"message", 7,
                          (void *)"key", 3, 0, headers, NULL);
  if (!err)
    Test::Fail("Expected produce() to fail");

  delete headers;
}

static void test_assignment_op() {
  Test::Say("Test Header assignment operator\n");

  RdKafka::Headers *headers = RdKafka::Headers::create();

  headers->add("abc", "123");
  headers->add("def", "456");

  RdKafka::Headers::Header h  = headers->get_last("abc");
  h                           = headers->get_last("def");
  RdKafka::Headers::Header h2 = h;
  h                           = headers->get_last("nope");
  RdKafka::Headers::Header h3 = h;
  h                           = headers->get_last("def");

  delete headers;
}


extern "C" {
int main_0085_headers(int argc, char **argv) {
  topic = Test::mk_topic_name("0085-headers", 1);

  RdKafka::Conf *conf;
  std::string errstr;

  Test::conf_init(&conf, NULL, 0);

  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create Producer: " + errstr);

  Test::conf_set(conf, "group.id", topic);

  RdKafka::KafkaConsumer *c = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!c)
    Test::Fail("Failed to create KafkaConsumer: " + errstr);

  delete conf;

  std::vector<RdKafka::TopicPartition *> parts;
  parts.push_back(RdKafka::TopicPartition::create(
      topic, 0, RdKafka::Topic::OFFSET_BEGINNING));
  RdKafka::ErrorCode err = c->assign(parts);
  if (err != RdKafka::ERR_NO_ERROR)
    Test::Fail("assign() failed: " + RdKafka::err2str(err));
  RdKafka::TopicPartition::destroy(parts);

  producer = p;
  consumer = c;

  test_headers(0);
  test_headers(1);
  test_headers(261);
  test_duplicate_keys();
  test_remove_after_add();
  test_remove_all_duplicate_keys();
  test_get_last_gives_last_added_val();
  test_get_of_key_returns_all();
  test_failed_produce();
  test_assignment_op();

  c->close();
  delete c;
  delete p;

  return 0;
}
}
