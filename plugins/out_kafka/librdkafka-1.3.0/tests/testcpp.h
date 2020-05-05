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
#ifdef _MSC_VER
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
    test_FAIL(__FILE__, __LINE__, 1, str.c_str());
  }
  static RD_UNUSED void FailLater (std::string str) {
    test_FAIL(__FILE__, __LINE__, 0, str.c_str());
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
