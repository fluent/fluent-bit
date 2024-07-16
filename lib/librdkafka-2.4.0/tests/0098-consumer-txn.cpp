/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2016-2022, Magnus Edenhill
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

#if WITH_RAPIDJSON

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <assert.h>
#include <sstream>
#include <string>
#include <map>

#include <rapidjson/document.h>
#include <rapidjson/schema.h>
#include <rapidjson/filereadstream.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/error/en.h>
#include <rapidjson/prettywriter.h>


/**
 * @name Consumer Transactions.
 *
 * - Uses the TransactionProducerCli Java application to produce messages
 *   that are part of abort and commit transactions in various combinations
 *   and tests that librdkafka consumes them as expected. Refer to
 *   TransactionProducerCli.java for scenarios covered.
 */


class TestEventCb : public RdKafka::EventCb {
 public:
  static bool should_capture_stats;
  static bool has_captured_stats;
  static int64_t partition_0_hi_offset;
  static int64_t partition_0_ls_offset;
  static std::string topic;

  void event_cb(RdKafka::Event &event) {
    switch (event.type()) {
    case RdKafka::Event::EVENT_STATS:
      if (should_capture_stats) {
        partition_0_hi_offset = -1;
        partition_0_ls_offset = -1;

        has_captured_stats   = true;
        should_capture_stats = false;
        char path[256];

        /* Parse JSON to validate */
        rapidjson::Document d;
        if (d.Parse(event.str().c_str()).HasParseError())
          Test::Fail(tostr() << "Failed to parse stats JSON: "
                             << rapidjson::GetParseError_En(d.GetParseError())
                             << " at " << d.GetErrorOffset());

        rd_snprintf(path, sizeof(path), "/topics/%s/partitions/0",
                    topic.c_str());

        rapidjson::Pointer jpath((const char *)path);
        rapidjson::Value *pp = rapidjson::GetValueByPointer(d, jpath);
        if (pp == NULL)
          return;

        TEST_ASSERT(pp->HasMember("hi_offset"), "hi_offset not found in stats");
        TEST_ASSERT(pp->HasMember("ls_offset"), "ls_offset not found in stats");

        partition_0_hi_offset = (*pp)["hi_offset"].GetInt();
        partition_0_ls_offset = (*pp)["ls_offset"].GetInt();
      }
      break;

    case RdKafka::Event::EVENT_LOG:
      std::cerr << event.str() << "\n";
      break;

    default:
      break;
    }
  }
};

bool TestEventCb::should_capture_stats;
bool TestEventCb::has_captured_stats;
int64_t TestEventCb::partition_0_hi_offset;
int64_t TestEventCb::partition_0_ls_offset;
std::string TestEventCb::topic;

static TestEventCb ex_event_cb;


static void execute_java_produce_cli(std::string &bootstrapServers,
                                     const std::string &topic,
                                     const std::string &testidstr,
                                     const char **cmds,
                                     size_t cmd_cnt) {
  const std::string topicCmd  = "topic," + topic;
  const std::string testidCmd = "testid," + testidstr;
  const char **argv;
  size_t i = 0;

  argv = (const char **)rd_alloca(sizeof(*argv) * (1 + 1 + 1 + cmd_cnt + 1));
  argv[i++] = bootstrapServers.c_str();
  argv[i++] = topicCmd.c_str();
  argv[i++] = testidCmd.c_str();

  for (size_t j = 0; j < cmd_cnt; j++)
    argv[i++] = cmds[j];

  argv[i] = NULL;

  int pid = test_run_java("TransactionProducerCli", (const char **)argv);
  test_waitpid(pid);
}

static std::vector<RdKafka::Message *>
consume_messages(RdKafka::KafkaConsumer *c, std::string topic, int partition) {
  RdKafka::ErrorCode err;

  /* Assign partitions */
  std::vector<RdKafka::TopicPartition *> parts;
  parts.push_back(RdKafka::TopicPartition::create(topic, partition));
  if ((err = c->assign(parts)))
    Test::Fail("assign failed: " + RdKafka::err2str(err));
  RdKafka::TopicPartition::destroy(parts);

  Test::Say(tostr() << "Consuming from topic " << topic << " partition "
                    << partition << "\n");
  std::vector<RdKafka::Message *> result = std::vector<RdKafka::Message *>();

  while (true) {
    RdKafka::Message *msg = c->consume(tmout_multip(1000));
    switch (msg->err()) {
    case RdKafka::ERR__TIMED_OUT:
      delete msg;
      continue;
    case RdKafka::ERR__PARTITION_EOF:
      delete msg;
      break;
    case RdKafka::ERR_NO_ERROR:
      result.push_back(msg);
      continue;
    default:
      Test::Fail("Error consuming from topic " + topic + ": " + msg->errstr());
      delete msg;
      break;
    }
    break;
  }

  Test::Say("Read all messages from topic: " + topic + "\n");

  TestEventCb::should_capture_stats = true;

  /* rely on the test timeout to prevent an infinite loop in
   * the (unlikely) event that the statistics callback isn't
   * called. */
  while (!TestEventCb::has_captured_stats) {
    RdKafka::Message *msg = c->consume(tmout_multip(500));
    delete msg;
  }

  Test::Say("Captured consumer statistics event\n");

  return result;
}


static void delete_messages(std::vector<RdKafka::Message *> &messages) {
  for (size_t i = 0; i < messages.size(); ++i)
    delete messages[i];
}


static std::string get_bootstrap_servers() {
  RdKafka::Conf *conf;
  std::string bootstrap_servers;
  Test::conf_init(&conf, NULL, 40);
  conf->get("bootstrap.servers", bootstrap_servers);
  delete conf;
  return bootstrap_servers;
}


static RdKafka::KafkaConsumer *create_consumer(std::string &topic_name,
                                               const char *isolation_level) {
  RdKafka::Conf *conf;
  std::string errstr;

  Test::conf_init(&conf, NULL, 40);
  Test::conf_set(conf, "group.id", topic_name);
  Test::conf_set(conf, "enable.auto.commit", "false");
  Test::conf_set(conf, "auto.offset.reset", "earliest");
  Test::conf_set(conf, "enable.partition.eof", "true");
  Test::conf_set(conf, "isolation.level", isolation_level);
  Test::conf_set(conf, "statistics.interval.ms", "1000");
  conf->set("event_cb", &ex_event_cb, errstr);
  TestEventCb::should_capture_stats = false;
  TestEventCb::has_captured_stats   = false;

  RdKafka::KafkaConsumer *c = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!c)
    Test::Fail("Failed to create KafkaConsumer: " + errstr);

  delete conf;

  return c;
}


static std::vector<std::string> csv_split(const std::string &input) {
  std::stringstream ss(input);
  std::vector<std::string> res;

  while (ss.good()) {
    std::string substr;
    std::getline(ss, substr, ',');
    /* Trim */
    substr.erase(0, substr.find_first_not_of(' '));
    substr.erase(substr.find_last_not_of(' ') + 1);
    res.push_back(substr);
  }

  return res;
}



enum TransactionType {
  TransactionType_None,
  TransactionType_BeginAbort,
  TransactionType_BeginCommit,
  TransactionType_BeginOpen,
  TransactionType_ContinueAbort,
  TransactionType_ContinueCommit,
  TransactionType_ContinueOpen
};

static TransactionType TransactionType_from_string(std::string str) {
#define _CHKRET(NAME)                                                          \
  if (!str.compare(#NAME))                                                     \
  return TransactionType_##NAME

  _CHKRET(None);
  _CHKRET(BeginAbort);
  _CHKRET(BeginCommit);
  _CHKRET(BeginOpen);
  _CHKRET(ContinueAbort);
  _CHKRET(ContinueCommit);
  _CHKRET(ContinueOpen);

  Test::Fail("Unknown TransactionType: " + str);

  return TransactionType_None; /* NOTREACHED */
}


static void txn_producer_makeTestMessages(RdKafka::Producer *producer,
                                          const std::string &topic,
                                          const std::string &testidstr,
                                          int partition,
                                          int idStart,
                                          int msgcount,
                                          TransactionType tt,
                                          bool do_flush) {
  RdKafka::Error *error;

  if (tt != TransactionType_None && tt != TransactionType_ContinueOpen &&
      tt != TransactionType_ContinueCommit &&
      tt != TransactionType_ContinueAbort) {
    error = producer->begin_transaction();
    if (error) {
      Test::Fail("begin_transaction() failed: " + error->str());
      delete error;
    }
  }

  for (int i = 0; i < msgcount; i++) {
    char key[]     = {(char)((i + idStart) & 0xff)};
    char payload[] = {0x10, 0x20, 0x30, 0x40};
    RdKafka::ErrorCode err;

    err = producer->produce(topic, partition, producer->RK_MSG_COPY, payload,
                            sizeof(payload), key, sizeof(key), 0, NULL);
    if (err)
      Test::Fail("produce() failed: " + RdKafka::err2str(err));
  }

  if (do_flush)
    producer->flush(-1);

  switch (tt) {
  case TransactionType_BeginAbort:
  case TransactionType_ContinueAbort:
    error = producer->abort_transaction(30 * 1000);
    if (error) {
      Test::Fail("abort_transaction() failed: " + error->str());
      delete error;
    }
    break;

  case TransactionType_BeginCommit:
  case TransactionType_ContinueCommit:
    error = producer->commit_transaction(30 * 1000);
    if (error) {
      Test::Fail("commit_transaction() failed: " + error->str());
      delete error;
    }
    break;

  default:
    break;
  }
}


class txnDeliveryReportCb : public RdKafka::DeliveryReportCb {
 public:
  void dr_cb(RdKafka::Message &msg) {
    switch (msg.err()) {
    case RdKafka::ERR__PURGE_QUEUE:
    case RdKafka::ERR__PURGE_INFLIGHT:
      /* These are expected when transactions are aborted */
      break;

    case RdKafka::ERR_NO_ERROR:
      break;

    default:
      Test::Fail("Delivery failed: " + msg.errstr());
      break;
    }
  }
};


/**
 * @brief Transactional producer, performing the commands in \p cmds.
 *        This is the librdkafka counterpart of
 *        java/TransactionProducerCli.java
 */
static void txn_producer(const std::string &brokers,
                         const std::string &topic,
                         const std::string &testidstr,
                         const char **cmds,
                         size_t cmd_cnt) {
  RdKafka::Conf *conf;
  txnDeliveryReportCb txn_dr;

  Test::conf_init(&conf, NULL, 0);
  Test::conf_set(conf, "bootstrap.servers", brokers);


  std::map<std::string, RdKafka::Producer *> producers;

  for (size_t i = 0; i < cmd_cnt; i++) {
    std::string cmdstr = std::string(cmds[i]);

    Test::Say(_C_CLR "rdkafka txn producer command: " + cmdstr + "\n");

    std::vector<std::string> cmd = csv_split(cmdstr);

    if (!cmd[0].compare("sleep")) {
      rd_usleep(atoi(cmd[1].c_str()) * 1000, NULL);

    } else if (!cmd[0].compare("exit")) {
      break; /* We can't really simulate the Java exit behaviour
              * from in-process. */

    } else if (cmd[0].find("producer") == 0) {
      TransactionType txntype = TransactionType_from_string(cmd[4]);

      std::map<std::string, RdKafka::Producer *>::iterator it =
          producers.find(cmd[0]);

      RdKafka::Producer *producer;

      if (it == producers.end()) {
        /* Create producer if it doesn't exist */
        std::string errstr;

        Test::Say(tostr() << "Creating producer " << cmd[0]
                          << " with transactiontype " << txntype << " '"
                          << cmd[4] << "'\n");

        /* Config */
        Test::conf_set(conf, "enable.idempotence", "true");
        if (txntype != TransactionType_None)
          Test::conf_set(conf, "transactional.id",
                         "test-transactional-id-c-" + testidstr + "-" + cmd[0]);
        else
          Test::conf_set(conf, "transactional.id", "");
        Test::conf_set(conf, "linger.ms", "5"); /* ensure batching */
        conf->set("dr_cb", &txn_dr, errstr);

        /* Create producer */
        producer = RdKafka::Producer::create(conf, errstr);
        if (!producer)
          Test::Fail("Failed to create producer " + cmd[0] + ": " + errstr);

        /* Init transactions if producer is transactional */
        if (txntype != TransactionType_None) {
          RdKafka::Error *error = producer->init_transactions(20 * 1000);
          if (error) {
            Test::Fail("init_transactions() failed: " + error->str());
            delete error;
          }
        }


        producers[cmd[0]] = producer;
      } else {
        producer = it->second;
      }

      txn_producer_makeTestMessages(
          producer,                             /* producer */
          topic,                                /* topic */
          testidstr,                            /* testid */
          atoi(cmd[1].c_str()),                 /* partition */
          (int)strtol(cmd[2].c_str(), NULL, 0), /* idStart */
          atoi(cmd[3].c_str()),                 /* msg count */
          txntype,                              /* TransactionType */
          !cmd[5].compare("DoFlush") /* Flush */);

    } else {
      Test::Fail("Unknown command: " + cmd[0]);
    }
  }

  delete conf;

  for (std::map<std::string, RdKafka::Producer *>::iterator it =
           producers.begin();
       it != producers.end(); it++)
    delete it->second;
}



static void do_test_consumer_txn_test(bool use_java_producer) {
  std::string errstr;
  std::string topic_name;
  RdKafka::KafkaConsumer *c;
  std::vector<RdKafka::Message *> msgs;
  std::string testidstr = test_str_id_generate_tmp();

  std::string bootstrap_servers = get_bootstrap_servers();

  Test::Say(tostr() << _C_BLU "[ Consumer transaction tests using "
                    << (use_java_producer ? "java" : "librdkafka")
                    << " producer with testid " << testidstr << "]\n" _C_CLR);

#define run_producer(CMDS...)                                                  \
  do {                                                                         \
    const char *_cmds[] = {CMDS};                                              \
    size_t _cmd_cnt     = sizeof(_cmds) / sizeof(*_cmds);                      \
    if (use_java_producer)                                                     \
      execute_java_produce_cli(bootstrap_servers, topic_name, testidstr,       \
                               _cmds, _cmd_cnt);                               \
    else                                                                       \
      txn_producer(bootstrap_servers, topic_name, testidstr, _cmds, _cmd_cnt); \
  } while (0)

  if (test_quick) {
    Test::Say("Skipping consumer_txn tests 0->4 due to quick mode\n");
    goto test5;
  }


  Test::Say(_C_BLU "Test 0 - basic commit + abort\n" _C_CLR);

  topic_name = Test::mk_topic_name("0098-consumer_txn-0", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 1, 3);

  run_producer("producer1, -1, 0x0, 5, BeginCommit, DoFlush",
               "producer1, -1, 0x10, 5, BeginAbort, DoFlush");

  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 5,
              "Consumed unexpected number of messages. "
              "Expected 5, got: %d",
              (int)msgs.size());
  TEST_ASSERT(msgs[0]->key_len() >= 1 && 0 == msgs[0]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[4]->key_len() >= 1 && 4 == msgs[4]->key()->c_str()[0],
              "Unexpected key");
  delete_messages(msgs);
  c->close();
  delete c;

#define expect_msgcnt(msgcnt)                                                  \
  TEST_ASSERT(msgs.size() == msgcnt, "Expected %d messages, got %d",           \
              (int)msgs.size(), msgcnt)

#define expect_key(msgidx, value)                                              \
  do {                                                                         \
    TEST_ASSERT(msgs.size() > msgidx,                                          \
                "Expected at least %d message(s), only got %d", msgidx + 1,    \
                (int)msgs.size());                                             \
    TEST_ASSERT(msgs[msgidx]->key_len() == 1,                                  \
                "Expected msg #%d key to be of size 1, not %d\n", msgidx,      \
                (int)msgs[msgidx]->key_len());                                 \
    TEST_ASSERT(value == (int)msgs[msgidx]->key()->c_str()[0],                 \
                "Expected msg #%d key 0x%x, not 0x%x", msgidx, value,          \
                (int)msgs[msgidx]->key()->c_str()[0]);                         \
  } while (0)

  c    = create_consumer(topic_name, "READ_UNCOMMITTED");
  msgs = consume_messages(c, topic_name, 0);
  expect_msgcnt(10);
  expect_key(0, 0x0);
  expect_key(4, 0x4);
  expect_key(5, 0x10);
  expect_key(9, 0x14);
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;


  Test::Say(_C_BLU "Test 0.1\n" _C_CLR);

  topic_name = Test::mk_topic_name("0098-consumer_txn-0.1", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 1, 3);

  run_producer("producer1, -1, 0x0, 5, BeginCommit, DontFlush",
               "producer1, -1, 0x10, 5, BeginAbort, DoFlush");

  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 5,
              "Consumed unexpected number of messages. "
              "Expected 5, got: %d",
              (int)msgs.size());
  TEST_ASSERT(msgs[0]->key_len() >= 1 && 0 == msgs[0]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[4]->key_len() >= 1 && 4 == msgs[4]->key()->c_str()[0],
              "Unexpected key");
  delete_messages(msgs);
  c->close();
  delete c;

  c    = create_consumer(topic_name, "READ_UNCOMMITTED");
  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 10,
              "Consumed unexpected number of messages. "
              "Expected 10, got: %d",
              (int)msgs.size());
  TEST_ASSERT(msgs[0]->key_len() >= 1 && 0 == msgs[0]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[4]->key_len() >= 1 && 4 == msgs[4]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[5]->key_len() >= 1 && 0x10 == msgs[5]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[9]->key_len() >= 1 && 0x14 == msgs[9]->key()->c_str()[0],
              "Unexpected key");
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;


  Test::Say(_C_BLU "Test 0.2\n" _C_CLR);

  topic_name = Test::mk_topic_name("0098-consumer_txn-0.2", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 1, 3);

  run_producer("producer1, -1, 0x10, 5, BeginAbort, DoFlush",
               "producer1, -1, 0x30, 5, BeginCommit, DoFlush");

  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 5,
              "Consumed unexpected number of messages. "
              "Expected 5, got: %d",
              (int)msgs.size());
  TEST_ASSERT(msgs[0]->key_len() >= 1 && 0x30 == msgs[0]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[4]->key_len() >= 1 && 0x34 == msgs[4]->key()->c_str()[0],
              "Unexpected key");
  delete_messages(msgs);
  c->close();
  delete c;

  c    = create_consumer(topic_name, "READ_UNCOMMITTED");
  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 10,
              "Consumed unexpected number of messages. "
              "Expected 10, got: %d",
              (int)msgs.size());
  TEST_ASSERT(msgs[0]->key_len() >= 1 && 0x10 == msgs[0]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[4]->key_len() >= 1 && 0x14 == msgs[4]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[5]->key_len() >= 1 && 0x30 == msgs[5]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[9]->key_len() >= 1 && 0x34 == msgs[9]->key()->c_str()[0],
              "Unexpected key");
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;


  Test::Say(_C_BLU "Test 1 - mixed with non-transactional.\n" _C_CLR);

  topic_name = Test::mk_topic_name("0098-consumer_txn-1", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 1, 3);
  TestEventCb::topic = topic_name;

  run_producer("producer3, -1, 0x10, 5, None, DoFlush",
               "producer1, -1, 0x50, 5, BeginCommit, DoFlush",
               "producer1, -1, 0x80, 5, BeginAbort, DoFlush");

  msgs = consume_messages(c, topic_name, 0);

  TEST_ASSERT(TestEventCb::partition_0_ls_offset != -1 &&
                  TestEventCb::partition_0_ls_offset ==
                      TestEventCb::partition_0_hi_offset,
              "Expected hi_offset to equal ls_offset but "
              "got hi_offset: %" PRId64 ", ls_offset: %" PRId64,
              TestEventCb::partition_0_hi_offset,
              TestEventCb::partition_0_ls_offset);

  TEST_ASSERT(msgs.size() == 10,
              "Consumed unexpected number of messages. "
              "Expected 10, got: %d",
              (int)msgs.size());
  TEST_ASSERT(msgs[0]->key_len() >= 1 && 0x10 == msgs[0]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[4]->key_len() >= 1 && 0x14 == msgs[4]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[5]->key_len() >= 1 && 0x50 == msgs[5]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[9]->key_len() >= 1 && 0x54 == msgs[9]->key()->c_str()[0],
              "Unexpected key");
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;

  Test::Say(_C_BLU "Test 1.1\n" _C_CLR);

  topic_name = Test::mk_topic_name("0098-consumer_txn-1.1", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 1, 3);

  run_producer("producer1, -1, 0x30, 5, BeginAbort, DoFlush",
               "producer3, -1, 0x40, 5, None, DoFlush",
               "producer1, -1, 0x60, 5, BeginCommit, DoFlush");


  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 10,
              "Consumed unexpected number of messages. "
              "Expected 10, got: %d",
              (int)msgs.size());
  TEST_ASSERT(msgs[0]->key_len() >= 1 && 0x40 == msgs[0]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[4]->key_len() >= 1 && 0x44 == msgs[4]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[5]->key_len() >= 1 && 0x60 == msgs[5]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[9]->key_len() >= 1 && 0x64 == msgs[9]->key()->c_str()[0],
              "Unexpected key");
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;


  Test::Say(_C_BLU "Test 1.2\n" _C_CLR);

  topic_name = Test::mk_topic_name("0098-consumer_txn-1.2", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 1, 3);

  run_producer("producer1, -1, 0x10, 5, BeginCommit, DoFlush",
               "producer1, -1, 0x20, 5, BeginAbort, DoFlush",
               "producer3, -1, 0x30, 5, None, DoFlush");

  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 10,
              "Consumed unexpected number of messages. "
              "Expected 10, got: %d",
              (int)msgs.size());
  TEST_ASSERT(msgs[0]->key_len() >= 1 && 0x10 == msgs[0]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[4]->key_len() >= 1 && 0x14 == msgs[4]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[5]->key_len() >= 1 && 0x30 == msgs[5]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[9]->key_len() >= 1 && 0x34 == msgs[9]->key()->c_str()[0],
              "Unexpected key");
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;


  Test::Say(_C_BLU "Test 2 - rapid abort / committing.\n" _C_CLR);
  // note: aborted records never seem to make it to the broker when not flushed.

  topic_name = Test::mk_topic_name("0098-consumer_txn-2", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 1, 3);

  run_producer("producer1, -1, 0x10, 1, BeginAbort, DontFlush",
               "producer1, -1, 0x20, 1, BeginCommit, DontFlush",
               "producer1, -1, 0x30, 1, BeginAbort, DontFlush",
               "producer1, -1, 0x40, 1, BeginCommit, DontFlush",
               "producer1, -1, 0x50, 1, BeginAbort, DontFlush",
               "producer1, -1, 0x60, 1, BeginCommit, DontFlush",
               "producer1, -1, 0x70, 1, BeginAbort, DontFlush",
               "producer1, -1, 0x80, 1, BeginCommit, DontFlush",
               "producer1, -1, 0x90, 1, BeginAbort, DontFlush",
               "producer1, -1, 0xa0, 1, BeginCommit, DoFlush",
               "producer3, -1, 0xb0, 1, None, DontFlush",
               "producer3, -1, 0xc0, 1, None, DoFlush");

  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 7,
              "Consumed unexpected number of messages. "
              "Expected 7, got: %d",
              (int)msgs.size());
  TEST_ASSERT(msgs[0]->key_len() >= 1 &&
                  0x20 == (unsigned char)msgs[0]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[1]->key_len() >= 1 &&
                  0x40 == (unsigned char)msgs[1]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[2]->key_len() >= 1 &&
                  0x60 == (unsigned char)msgs[2]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[3]->key_len() >= 1 &&
                  0x80 == (unsigned char)msgs[3]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[4]->key_len() >= 1 &&
                  0xa0 == (unsigned char)msgs[4]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[5]->key_len() >= 1 &&
                  0xb0 == (unsigned char)msgs[5]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[6]->key_len() >= 1 &&
                  0xc0 == (unsigned char)msgs[6]->key()->c_str()[0],
              "Unexpected key");
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;


  Test::Say(_C_BLU "Test 2.1\n" _C_CLR);

  topic_name = Test::mk_topic_name("0098-consumer_txn-2.1", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 1, 3);

  run_producer("producer1, -1, 0x10, 1, BeginAbort, DoFlush",
               "producer1, -1, 0x20, 1, BeginCommit, DoFlush",
               "producer1, -1, 0x30, 1, BeginAbort, DoFlush",
               "producer1, -1, 0x40, 1, BeginCommit, DoFlush",
               "producer1, -1, 0x50, 1, BeginAbort, DoFlush",
               "producer1, -1, 0x60, 1, BeginCommit, DoFlush",
               "producer1, -1, 0x70, 1, BeginAbort, DoFlush",
               "producer1, -1, 0x80, 1, BeginCommit, DoFlush",
               "producer1, -1, 0x90, 1, BeginAbort, DoFlush",
               "producer1, -1, 0xa0, 1, BeginCommit, DoFlush",
               "producer3, -1, 0xb0, 1, None, DoFlush",
               "producer3, -1, 0xc0, 1, None, DoFlush");

  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 7,
              "Consumed unexpected number of messages. "
              "Expected 7, got: %d",
              (int)msgs.size());
  TEST_ASSERT(msgs[0]->key_len() >= 1 &&
                  0x20 == (unsigned char)msgs[0]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[1]->key_len() >= 1 &&
                  0x40 == (unsigned char)msgs[1]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[2]->key_len() >= 1 &&
                  0x60 == (unsigned char)msgs[2]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[3]->key_len() >= 1 &&
                  0x80 == (unsigned char)msgs[3]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[4]->key_len() >= 1 &&
                  0xa0 == (unsigned char)msgs[4]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[5]->key_len() >= 1 &&
                  0xb0 == (unsigned char)msgs[5]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[6]->key_len() >= 1 &&
                  0xc0 == (unsigned char)msgs[6]->key()->c_str()[0],
              "Unexpected key");
  delete_messages(msgs);
  c->close();
  delete c;

  c    = create_consumer(topic_name, "READ_UNCOMMITTED");
  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 12,
              "Consumed unexpected number of messages. "
              "Expected 12, got: %d",
              (int)msgs.size());
  TEST_ASSERT(msgs[0]->key_len() >= 1 &&
                  0x10 == (unsigned char)msgs[0]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[1]->key_len() >= 1 &&
                  0x20 == (unsigned char)msgs[1]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[2]->key_len() >= 1 &&
                  0x30 == (unsigned char)msgs[2]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[3]->key_len() >= 1 &&
                  0x40 == (unsigned char)msgs[3]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[4]->key_len() >= 1 &&
                  0x50 == (unsigned char)msgs[4]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[5]->key_len() >= 1 &&
                  0x60 == (unsigned char)msgs[5]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[6]->key_len() >= 1 &&
                  0x70 == (unsigned char)msgs[6]->key()->c_str()[0],
              "Unexpected key");
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;


  Test::Say(_C_BLU "Test 3 - cross partition (simple).\n" _C_CLR);

  topic_name = Test::mk_topic_name("0098-consumer_txn-3", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 2, 3);

  run_producer("producer1, 0, 0x10, 3, BeginOpen, DoFlush",
               "producer1, 1, 0x20, 3, ContinueOpen, DoFlush",
               "producer1, 0, 0x30, 3, ContinueCommit, DoFlush");

  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 6,
              "Consumed unexpected number of messages. "
              "Expected 6, got: %d",
              (int)msgs.size());
  delete_messages(msgs);
  msgs = consume_messages(c, topic_name, 1);
  TEST_ASSERT(msgs.size() == 3,
              "Consumed unexpected number of messages. "
              "Expected 3, got: %d",
              (int)msgs.size());
  delete_messages(msgs);
  c->close();
  delete c;

  c    = create_consumer(topic_name, "READ_UNCOMMITTED");
  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 6,
              "Consumed unexpected number of messages. "
              "Expected 6, got: %d",
              (int)msgs.size());
  delete_messages(msgs);
  msgs = consume_messages(c, topic_name, 1);
  TEST_ASSERT(msgs.size() == 3,
              "Consumed unexpected number of messages. "
              "Expected 3, got: %d",
              (int)msgs.size());
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;


  Test::Say(_C_BLU "Test 3.1\n" _C_CLR);

  topic_name = Test::mk_topic_name("0098-consumer_txn-3.1", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 2, 3);

  run_producer("producer1, 0, 0x55, 1, BeginCommit, DoFlush",
               "producer1, 0, 0x10, 3, BeginOpen, DoFlush",
               "producer1, 1, 0x20, 3, ContinueOpen, DoFlush",
               "producer1, 0, 0x30, 3, ContinueAbort, DoFlush",
               "producer3, 0, 0x00, 1, None, DoFlush",
               "producer1, 1, 0x44, 1, BeginCommit, DoFlush");

  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 2,
              "Consumed unexpected number of messages. "
              "Expected 2, got: %d",
              (int)msgs.size());
  TEST_ASSERT(msgs[0]->key_len() >= 1 &&
                  0x55 == (unsigned char)msgs[0]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[1]->key_len() >= 1 &&
                  0x00 == (unsigned char)msgs[1]->key()->c_str()[0],
              "Unexpected key");
  delete_messages(msgs);
  msgs = consume_messages(c, topic_name, 1);
  TEST_ASSERT(msgs.size() == 1,
              "Consumed unexpected number of messages. "
              "Expected 1, got: %d",
              (int)msgs.size());
  TEST_ASSERT(msgs[0]->key_len() >= 1 &&
                  0x44 == (unsigned char)msgs[0]->key()->c_str()[0],
              "Unexpected key");
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;


  Test::Say(_C_BLU "Test 4 - simultaneous transactions (simple).\n" _C_CLR);

  topic_name = Test::mk_topic_name("0098-consumer_txn-4", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 1, 3);

  run_producer("producer3, 0, 0x10, 1, None, DoFlush",
               "producer1, 0, 0x20, 3, BeginOpen, DoFlush",
               "producer2, 0, 0x30, 3, BeginOpen, DoFlush",
               "producer1, 0, 0x40, 3, ContinueCommit, DoFlush",
               "producer2, 0, 0x50, 3, ContinueAbort, DoFlush");

  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 7,
              "Consumed unexpected number of messages. "
              "Expected 7, got: %d",
              (int)msgs.size());
  delete_messages(msgs);
  c->close();
  delete c;

  c    = create_consumer(topic_name, "READ_UNCOMMITTED");
  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 13,
              "Consumed unexpected number of messages. "
              "Expected 13, got: %d",
              (int)msgs.size());
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;


  Test::Say(_C_BLU "Test 4.1\n" _C_CLR);

  topic_name = Test::mk_topic_name("0098-consumer_txn-4.1", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 1, 3);

  run_producer("producer3, 0, 0x10, 1, None, DoFlush",
               "producer1, 0, 0x20, 3, BeginOpen, DoFlush",
               "producer2, 0, 0x30, 3, BeginOpen, DoFlush",
               "producer1, 0, 0x40, 3, ContinueAbort, DoFlush",
               "producer2, 0, 0x50, 3, ContinueCommit, DoFlush");

  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 7,
              "Consumed unexpected number of messages. "
              "Expected 7, got: %d",
              (int)msgs.size());
  delete_messages(msgs);
  c->close();
  delete c;

  c    = create_consumer(topic_name, "READ_UNCOMMITTED");
  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 13,
              "Consumed unexpected number of messages. "
              "Expected 13, got: %d",
              (int)msgs.size());
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;


  Test::Say(_C_BLU "Test 4.2\n" _C_CLR);

  topic_name = Test::mk_topic_name("0098-consumer_txn-4.2", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 1, 3);

  run_producer("producer3, 0, 0x10, 1, None, DoFlush",
               "producer1, 0, 0x20, 3, BeginOpen, DoFlush",
               "producer2, 0, 0x30, 3, BeginOpen, DoFlush",
               "producer1, 0, 0x40, 3, ContinueCommit, DoFlush",
               "producer2, 0, 0x50, 3, ContinueCommit, DoFlush");

  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 13,
              "Consumed unexpected number of messages. "
              "Expected 7, got: %d",
              (int)msgs.size());
  delete_messages(msgs);
  c->close();
  delete c;

  c    = create_consumer(topic_name, "READ_UNCOMMITTED");
  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 13,
              "Consumed unexpected number of messages. "
              "Expected 13, got: %d",
              (int)msgs.size());
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;


  Test::Say(_C_BLU "Test 4.3\n" _C_CLR);

  topic_name = Test::mk_topic_name("0098-consumer_txn-4.3", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 1, 3);

  run_producer("producer3, 0, 0x10, 1, None, DoFlush",
               "producer1, 0, 0x20, 3, BeginOpen, DoFlush",
               "producer2, 0, 0x30, 3, BeginOpen, DoFlush",
               "producer1, 0, 0x40, 3, ContinueAbort, DoFlush",
               "producer2, 0, 0x50, 3, ContinueAbort, DoFlush");

  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 1,
              "Consumed unexpected number of messages. "
              "Expected 7, got: %d",
              (int)msgs.size());
  delete_messages(msgs);
  c->close();
  delete c;

  c    = create_consumer(topic_name, "READ_UNCOMMITTED");
  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 13,
              "Consumed unexpected number of messages. "
              "Expected 13, got: %d",
              (int)msgs.size());
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;



  Test::Say(_C_BLU "Test 5 - split transaction across message sets.\n" _C_CLR);

test5:
  topic_name = Test::mk_topic_name("0098-consumer_txn-5", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 1, 3);

  run_producer("producer1, 0, 0x10, 2, BeginOpen, DontFlush", "sleep,200",
               "producer1, 0, 0x20, 2, ContinueAbort, DontFlush",
               "producer1, 0, 0x30, 2, BeginOpen, DontFlush", "sleep,200",
               "producer1, 0, 0x40, 2, ContinueCommit, DontFlush",
               "producer1, 0, 0x50, 2, BeginOpen, DontFlush", "sleep,200",
               "producer1, 0, 0x60, 2, ContinueAbort, DontFlush",
               "producer1, 0, 0xa0, 2, BeginOpen, DontFlush", "sleep,200",
               "producer1, 0, 0xb0, 2, ContinueCommit, DontFlush",
               "producer3, 0, 0x70, 1, None, DoFlush");

  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 9,
              "Consumed unexpected number of messages. "
              "Expected 9, got: %d",
              (int)msgs.size());
  TEST_ASSERT(msgs[0]->key_len() >= 1 &&
                  0x30 == (unsigned char)msgs[0]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[1]->key_len() >= 1 &&
                  0x31 == (unsigned char)msgs[1]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[2]->key_len() >= 1 &&
                  0x40 == (unsigned char)msgs[2]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[3]->key_len() >= 1 &&
                  0x41 == (unsigned char)msgs[3]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[4]->key_len() >= 1 &&
                  0xa0 == (unsigned char)msgs[4]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[5]->key_len() >= 1 &&
                  0xa1 == (unsigned char)msgs[5]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[6]->key_len() >= 1 &&
                  0xb0 == (unsigned char)msgs[6]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[7]->key_len() >= 1 &&
                  0xb1 == (unsigned char)msgs[7]->key()->c_str()[0],
              "Unexpected key");
  TEST_ASSERT(msgs[8]->key_len() >= 1 &&
                  0x70 == (unsigned char)msgs[8]->key()->c_str()[0],
              "Unexpected key");
  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;


  Test::Say(_C_BLU "Test 6 - transaction left open\n" _C_CLR);

  topic_name = Test::mk_topic_name("0098-consumer_txn-0", 1);
  c          = create_consumer(topic_name, "READ_COMMITTED");
  Test::create_topic(c, topic_name.c_str(), 1, 3);
  TestEventCb::topic = topic_name;

  run_producer("producer3, 0, 0x10, 1, None, DoFlush",
               "producer1, 0, 0x20, 3, BeginOpen, DoFlush",
               // prevent abort control message from being written.
               "exit,0");

  msgs = consume_messages(c, topic_name, 0);
  TEST_ASSERT(msgs.size() == 1,
              "Consumed unexpected number of messages. "
              "Expected 1, got: %d",
              (int)msgs.size());

  TEST_ASSERT(TestEventCb::partition_0_ls_offset + 3 ==
                  TestEventCb::partition_0_hi_offset,
              "Expected hi_offset to be 3 greater than ls_offset "
              "but got hi_offset: %" PRId64 ", ls_offset: %" PRId64,
              TestEventCb::partition_0_hi_offset,
              TestEventCb::partition_0_ls_offset);

  delete_messages(msgs);

  Test::delete_topic(c, topic_name.c_str());

  c->close();
  delete c;
}
#endif


extern "C" {
int main_0098_consumer_txn(int argc, char **argv) {
  if (test_needs_auth()) {
    Test::Skip(
        "Authentication or security configuration "
        "required on client: not supported in "
        "Java transactional producer: skipping tests\n");
    return 0;
  }
#if WITH_RAPIDJSON
  do_test_consumer_txn_test(true /* with java producer */);
  do_test_consumer_txn_test(false /* with librdkafka producer */);
#else
  Test::Skip("RapidJSON >=1.1.0 not available\n");
#endif
  return 0;
}
}
