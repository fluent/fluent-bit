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
#ifndef _TESTCPP_H_
#define _TESTCPP_H_

#include <sstream>

#include "rdkafkacpp.h"

extern "C" {
#ifdef _WIN32
/* Win32/Visual Studio */
#include "../src/win32_config.h"
#include "../src/rdwin32.h"
#else
#include "../config.h"
/* POSIX / UNIX based systems */
#include "../src/rdposix.h"
#endif
#include "testshared.h"
}

// courtesy of http://stackoverview.blogspot.se/2011/04/create-string-on-fly-just-in-one-line.html
struct tostr {
  std::stringstream ss;
  template<typename T>
  tostr & operator << (const T &data)
  {
    ss << data;
    return *this;
  }
  operator std::string() { return ss.str(); }
};



#define TestMessageVerify(testid,exp_partition,msgidp,msg)              \
        test_msg_parse00(__FUNCTION__, __LINE__, testid, exp_partition, \
                         msgidp, (msg)->topic_name().c_str(),           \
                         (msg)->partition(), (msg)->offset(),           \
                         (const char *)(msg)->key_pointer(), (msg)->key_len())

namespace Test {

  /**
   * @brief Get test config object
   */

  static RD_UNUSED void Fail (std::string str) {
   test_fail0(__FILE__, __LINE__, "", 1/*do-lock*/, 1/*now*/,
              "%s", str.c_str());
  }
  static RD_UNUSED void FailLater (std::string str) {
   test_fail0(__FILE__, __LINE__, "", 1/*do-lock*/, 0/*later*/,
              "%s", str.c_str());
  }
  static RD_UNUSED void Skip (std::string str) {
          test_SKIP(__FILE__, __LINE__, str.c_str());
  }
  static RD_UNUSED void Say (int level, std::string str) {
    test_SAY(__FILE__, __LINE__, level, str.c_str());
  }
  static RD_UNUSED void Say (std::string str) {
    Test::Say(2, str);
  }

  /**
   * @brief Generate test topic name
   */
  static RD_UNUSED std::string mk_topic_name (std::string suffix,
                                              bool randomized) {
    return test_mk_topic_name(suffix.c_str(),
                              (int)randomized);
  }

  /**
   * @brief Generate random test group name
   */
  static RD_UNUSED std::string mk_unique_group_name (std::string suffix) {
    return test_mk_topic_name(suffix.c_str(), 1);
  }

  /**
   * @brief Create partitions
   */
  static RD_UNUSED void create_partitions (RdKafka::Handle *use_handle, const char *topicname,
                                           int new_partition_cnt) {
    rd_kafka_t *use_rk = NULL;
    if (use_handle != NULL)
      use_rk = use_handle->c_ptr();
    test_create_partitions(use_rk, topicname, new_partition_cnt);
  }

  /**
   * @brief Create a topic
   */
  static RD_UNUSED void create_topic (RdKafka::Handle *use_handle, const char *topicname,
                                      int partition_cnt, int replication_factor) {
    rd_kafka_t *use_rk = NULL;
    if (use_handle != NULL)
      use_rk = use_handle->c_ptr();
    test_create_topic(use_rk, topicname, partition_cnt, replication_factor);
  }

  /**
   * @brief Delete a topic
   */
  static RD_UNUSED void delete_topic (RdKafka::Handle *use_handle, const char *topicname) {
    rd_kafka_t *use_rk = NULL;
    if (use_handle != NULL)
      use_rk = use_handle->c_ptr();
    test_delete_topic(use_rk, topicname);
  }

  /**
   * @brief Get new configuration objects
   */
  void conf_init (RdKafka::Conf **conf,
                  RdKafka::Conf **topic_conf,
                  int timeout);


  static RD_UNUSED
      void conf_set (RdKafka::Conf *conf, std::string name, std::string val) {
    std::string errstr;
    if (conf->set(name, val, errstr) != RdKafka::Conf::CONF_OK)
      Test::Fail("Conf failed: " + errstr);
  }

  static RD_UNUSED
      void print_TopicPartitions (std::string header,
                                  const std::vector<RdKafka::TopicPartition*>&partitions) {
    Test::Say(tostr() << header << ": " << partitions.size() <<
              " TopicPartition(s):\n");
    for (unsigned int i = 0 ; i < partitions.size() ; i++)
      Test::Say(tostr() << " " << partitions[i]->topic() <<
                "[" << partitions[i]->partition() << "] " <<
                "offset " << partitions[i]->offset() <<
                ": " << RdKafka::err2str(partitions[i]->err())
                << "\n");
  }


  /* Convenience subscribe() */
  static RD_UNUSED void subscribe (RdKafka::KafkaConsumer *c,
                                   const std::string &topic) {
    Test::Say(c->name() + ": Subscribing to " + topic + "\n");
    std::vector<std::string> topics;
    topics.push_back(topic);
    RdKafka::ErrorCode err;
    if ((err = c->subscribe(topics)))
      Test::Fail("Subscribe failed: " + RdKafka::err2str(err));
  }


  /* Convenience subscribe() to two topics */
  static RD_UNUSED void subscribe (RdKafka::KafkaConsumer *c,
                                   const std::string &topic1,
                                   const std::string &topic2) {
    Test::Say(c->name() + ": Subscribing to " + topic1 + " and "
              + topic2 + "\n");
    std::vector<std::string> topics;
    topics.push_back(topic1);
    topics.push_back(topic2);
    RdKafka::ErrorCode err;
    if ((err = c->subscribe(topics)))
      Test::Fail("Subscribe failed: " + RdKafka::err2str(err));
  }

  /* Convenience unsubscribe() */
  static RD_UNUSED void unsubscribe (RdKafka::KafkaConsumer *c) {
    Test::Say(c->name() + ": Unsubscribing\n");
    RdKafka::ErrorCode err;
    if ((err = c->unsubscribe()))
      Test::Fail("Unsubscribe failed: " + RdKafka::err2str(err));
  }


  static RD_UNUSED void
  incremental_assign (RdKafka::KafkaConsumer *c,
                      const std::vector<RdKafka::TopicPartition *> &parts) {
    Test::Say(tostr() << c->name() <<
              ": incremental assign of " << parts.size() <<
              " partition(s)\n");
    if (test_level >= 2)
      print_TopicPartitions("incremental_assign()", parts);
    RdKafka::Error *error;
    if ((error = c->incremental_assign(parts)))
      Test::Fail(c->name() + ": Incremental assign failed: " + error->str());
  }

  static RD_UNUSED void
  incremental_unassign (RdKafka::KafkaConsumer *c,
                        const std::vector<RdKafka::TopicPartition *> &parts) {
    Test::Say(tostr() << c->name() <<
              ": incremental unassign of " << parts.size() <<
              " partition(s)\n");
    if (test_level >= 2)
      print_TopicPartitions("incremental_unassign()", parts);
    RdKafka::Error *error;
    if ((error = c->incremental_unassign(parts)))
      Test::Fail(c->name() + ": Incremental unassign failed: " + error->str());
  }

  /**
   * @brief Wait until the current assignment size is \p partition_count.
   *        If \p topic is not NULL, then additionally, each partition in
   *        the assignment must have topic \p topic.
   */
  static RD_UNUSED void wait_for_assignment (RdKafka::KafkaConsumer *c,
                                             size_t partition_count,
                                             const std::string *topic) {
    bool done = false;
    while (!done) {
      RdKafka::Message *msg1 = c->consume(500);
      delete msg1;

      std::vector<RdKafka::TopicPartition*> partitions;
      c->assignment(partitions);

      if (partitions.size() == partition_count) {
        done = true;
        if (topic) {
          for (size_t i = 0 ; i < partitions.size() ; i++) {
            if (partitions[i]->topic() != *topic) {
              done = false;
              break;
            }
          }
        }
      }

      RdKafka::TopicPartition::destroy(partitions);
    }
  }


  /**
   * @brief Check current assignment has size \p partition_count
   *        If \p topic is not NULL, then additionally check that
   *        each partition in the assignment has topic \p topic.
   */
  static RD_UNUSED void check_assignment (RdKafka::KafkaConsumer *c,
                                          size_t partition_count,
                                          const std::string *topic) {
    std::vector<RdKafka::TopicPartition*> partitions;
    c->assignment(partitions);
    if (partition_count != partitions.size())
      Test::Fail(tostr() << "Expecting current assignment to have size " << partition_count << ", not: " << partitions.size());
    for (size_t i = 0 ; i < partitions.size() ; i++) {
      if (topic != NULL) {
        if (partitions[i]->topic() != *topic)
          Test::Fail(tostr() << "Expecting assignment to be " << *topic << ", not " << partitions[i]->topic());
      }
      delete partitions[i];
    }
  }


  /**
   * @brief Current assignment partition count. If \p topic is
   *        NULL, then the total partition count, else the number
   *        of assigned partitions from \p topic.
   */
  static RD_UNUSED size_t assignment_partition_count (RdKafka::KafkaConsumer *c, std::string *topic) {
    std::vector<RdKafka::TopicPartition*> partitions;
    c->assignment(partitions);
    int cnt = 0;
    for (size_t i = 0 ; i < partitions.size() ; i++) {
      if (topic == NULL || *topic == partitions[i]->topic())
        cnt++;
      delete partitions[i];
    }
    return cnt;
  }


  /**
   * @brief Poll the consumer once, discarding the returned message
   *        or error event.
   * @returns true if a proper event/message was seen, or false on timeout.
   */
  static RD_UNUSED bool poll_once (RdKafka::KafkaConsumer *c,
                                   int timeout_ms) {
    RdKafka::Message *msg = c->consume(timeout_ms);
    bool ret = msg->err() != RdKafka::ERR__TIMED_OUT;
    delete msg;
    return ret;
  }


  /**
   * @brief Produce \p msgcnt messages to \p topic \p partition.
   */
  static RD_UNUSED void produce_msgs (RdKafka::Producer *p,
                                      const std::string &topic,
                                      int32_t partition,
                                      int msgcnt, int msgsize,
                                      bool flush) {
    char *buf = (char *)malloc(msgsize);

    for (int i = 0 ; i < msgsize ; i++)
      buf[i] = (char)((int)'a' + (i % 26));

    for (int i = 0 ; i < msgcnt ; i++) {
      RdKafka::ErrorCode err;
      err = p->produce(topic, partition,
                       RdKafka::Producer::RK_MSG_COPY,
                       (void *)buf, (size_t)msgsize,
                       NULL, 0, 0, NULL);
      TEST_ASSERT(!err, "produce() failed: %s", RdKafka::err2str(err).c_str());
      p->poll(0);
    }

    free(buf);

    if (flush)
      p->flush(10*1000);
  }



  /**
   * @brief Delivery report class
   */
  class DeliveryReportCb : public RdKafka::DeliveryReportCb {
 public:
    void dr_cb (RdKafka::Message &msg);
  };

  static DeliveryReportCb DrCb;
};

#endif /* _TESTCPP_H_ */
