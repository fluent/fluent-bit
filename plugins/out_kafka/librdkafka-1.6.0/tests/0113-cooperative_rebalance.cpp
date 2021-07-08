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

extern "C" {
#include "../src/rdkafka_protocol.h"
#include "test.h"
}
#include <iostream>
#include <map>
#include <set>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <assert.h>
#include "testcpp.h"
#include <fstream>

using namespace std;

/** Topic+Partition helper class */
class Toppar {
public:
  Toppar(const string &topic, int32_t partition):
    topic(topic), partition(partition) { }

  Toppar(const RdKafka::TopicPartition *tp):
    topic(tp->topic()), partition(tp->partition()) {}

  friend bool operator== (const Toppar &a, const Toppar &b) {
    return a.partition == b.partition && a.topic == b.topic;
  }

  friend bool operator< (const Toppar &a, const Toppar &b) {
    if (a.partition < b.partition)
      return true;
    return a.topic < b.topic;
  }

  string str () const {
    return tostr() << topic << "[" << partition << "]";
  }

  std::string topic;
  int32_t partition;
};



static std::string get_bootstrap_servers() {
  RdKafka::Conf *conf;
  std::string bootstrap_servers;
  Test::conf_init(&conf, NULL, 0);
  conf->get("bootstrap.servers", bootstrap_servers);
  delete conf;
  return bootstrap_servers;
}


class DrCb : public RdKafka::DeliveryReportCb {
 public:
  void dr_cb (RdKafka::Message &msg) {
    if (msg.err())
      Test::Fail("Delivery failed: " + RdKafka::err2str(msg.err()));
  }
};


/**
 * @brief Produce messages to partitions.
 *
 * The pair is Toppar,msg_cnt_per_partition.
 * The Toppar is topic,partition_cnt.
 */
static void produce_msgs (vector<pair<Toppar,int> > partitions) {

  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 0);

  string errstr;
  DrCb dr;
  conf->set("dr_cb", &dr, errstr);
  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create producer: " + errstr);

  for (vector<pair<Toppar,int> >::iterator it = partitions.begin() ;
       it != partitions.end() ; it++) {
    for (int part = 0 ; part < it->first.partition ; part++) {
      for (int i = 0 ; i < it->second ; i++) {
        RdKafka::ErrorCode err = p->produce(it->first.topic, part,
                                            RdKafka::Producer::RK_MSG_COPY,
                                            (void *)"Hello there", 11,
                                            NULL, 0,
                                            0, NULL);
        TEST_ASSERT(!err, "produce(%s, %d) failed: %s",
                    it->first.topic.c_str(), part,
                    RdKafka::err2str(err).c_str());

        p->poll(0);
      }
    }
  }

  p->flush(10000);

  delete p;
}



static RdKafka::KafkaConsumer *
make_consumer (string client_id,
               string group_id,
               string assignment_strategy,
               vector<pair<string, string> > *additional_conf,
               RdKafka::RebalanceCb *rebalance_cb,
               int timeout_s) {

  std::string bootstraps;
  std::string errstr;
  std::vector<std::pair<std::string, std::string> >::iterator itr;

  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, timeout_s);
  Test::conf_set(conf, "client.id", client_id);
  Test::conf_set(conf, "group.id", group_id);
  Test::conf_set(conf, "auto.offset.reset", "earliest");
  Test::conf_set(conf, "enable.auto.commit", "false");
  Test::conf_set(conf, "partition.assignment.strategy", assignment_strategy);
  if (additional_conf != NULL) {
    for (itr = (*additional_conf).begin(); itr != (*additional_conf).end(); itr++)
      Test::conf_set(conf, itr->first, itr->second);
  }

  if (rebalance_cb) {
    if (conf->set("rebalance_cb", rebalance_cb, errstr))
      Test::Fail("Failed to set rebalance_cb: " + errstr);
  }
  RdKafka::KafkaConsumer *consumer = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!consumer)
    Test::Fail("Failed to create KafkaConsumer: " + errstr);
  delete conf;

  return consumer;
}

/**
 * @returns a CSV string of the vector
 */
static string string_vec_to_str (const vector<string> &v) {
  ostringstream ss;
  for (vector<string>::const_iterator it = v.begin();
      it != v.end();
      it++)
    ss << (it == v.begin() ? "" : ", ") << *it;
  return ss.str();
}

void expect_assignment(RdKafka::KafkaConsumer *consumer, size_t count) {
  std::vector<RdKafka::TopicPartition*> partitions;
  RdKafka::ErrorCode err;
  err = consumer->assignment(partitions);
  if (err)
    Test::Fail(consumer->name() + " assignment() failed: " +
               RdKafka::err2str(err));
  if (partitions.size() != count)
    Test::Fail(tostr() << "Expecting consumer " << consumer->name() << " to have " << count << " assigned partition(s), not: " << partitions.size());
  RdKafka::TopicPartition::destroy(partitions);
}


static bool TopicPartition_cmp (const RdKafka::TopicPartition *a,
                                const RdKafka::TopicPartition *b) {
  if (a->topic() < b->topic())
    return true;
  else if (a->topic() > b->topic())
    return false;
  return a->partition() < b->partition();
}


void expect_assignment (RdKafka::KafkaConsumer *consumer,
                        vector<RdKafka::TopicPartition*> &expected) {
  vector<RdKafka::TopicPartition*> partitions;
  RdKafka::ErrorCode err;
  err = consumer->assignment(partitions);
  if (err)
    Test::Fail(consumer->name() + " assignment() failed: " +
               RdKafka::err2str(err));

  if (partitions.size() != expected.size())
    Test::Fail(tostr() << "Expecting consumer " << consumer->name() <<
               " to have " << expected.size() <<
               " assigned partition(s), not " << partitions.size());

  sort(partitions.begin(), partitions.end(), TopicPartition_cmp);
  sort(expected.begin(), expected.end(), TopicPartition_cmp);

  int fails = 0;
  for (int i = 0 ; i < (int)partitions.size() ; i++) {
    if (!TopicPartition_cmp(partitions[i], expected[i]))
      continue;

    Test::Say(tostr() << _C_RED << consumer->name() <<
              ": expected assignment #" << i << " " <<
              expected[i]->topic() <<
              " [" << expected[i]->partition() << "], not " <<
              partitions[i]->topic() <<
              " [" << partitions[i]->partition() << "]\n");
    fails++;
  }

  if (fails)
    Test::Fail(consumer->name() + ": Expected assignment mismatch, see above");

  RdKafka::TopicPartition::destroy(partitions);
}


class DefaultRebalanceCb : public RdKafka::RebalanceCb {

private:

  static string part_list_print (const vector<RdKafka::TopicPartition*>
                                 &partitions) {
    ostringstream ss;
    for (unsigned int i = 0 ; i < partitions.size() ; i++)
      ss << (i == 0 ? "" : ", ") <<
        partitions[i]->topic() << " [" << partitions[i]->partition() << "]";
    return ss.str();
  }

public:

  int assign_call_cnt;
  int revoke_call_cnt;
  int nonempty_assign_call_cnt; /**< ASSIGN_PARTITIONS with partitions */
  int lost_call_cnt;
  int partitions_assigned_net;
  bool wait_rebalance;
  int64_t ts_last_assign; /**< Timestamp of last rebalance assignment */
  map<Toppar,int> msg_cnt; /**< Number of consumed messages per partition. */

  ~DefaultRebalanceCb () {
    reset_msg_cnt();
  }

  DefaultRebalanceCb ():
    assign_call_cnt(0),
    revoke_call_cnt(0),
    nonempty_assign_call_cnt(0),
    lost_call_cnt(0),
    partitions_assigned_net(0),
    wait_rebalance(false),
    ts_last_assign(0) { }


  void rebalance_cb (RdKafka::KafkaConsumer *consumer,
                     RdKafka::ErrorCode err,
                     std::vector<RdKafka::TopicPartition*> &partitions) {
    wait_rebalance = false;

    std::string protocol = consumer->rebalance_protocol();

    TEST_ASSERT(protocol == "COOPERATIVE",
                "%s: Expected rebalance_protocol \"COOPERATIVE\", not %s",
                consumer->name().c_str(), protocol.c_str());

    const char *lost_str = consumer->assignment_lost() ? " (LOST)" : "";
    Test::Say(tostr() << _C_YEL "RebalanceCb " << protocol <<
              ": " << consumer->name() <<
              " " << RdKafka::err2str(err) << lost_str << ": " <<
              part_list_print(partitions) << "\n");

    if (err == RdKafka::ERR__ASSIGN_PARTITIONS) {
      if (consumer->assignment_lost())
        Test::Fail("unexpected lost assignment during ASSIGN rebalance");
      RdKafka::Error *error = consumer->incremental_assign(partitions);
      if (error)
        Test::Fail(tostr() << "consumer->incremental_assign() failed: " <<
                   error->str());
      if (partitions.size() > 0)
        nonempty_assign_call_cnt++;
      assign_call_cnt += 1;
      partitions_assigned_net += (int)partitions.size();
      ts_last_assign = test_clock();

    } else {
      if (consumer->assignment_lost())
        lost_call_cnt += 1;
      RdKafka::Error *error = consumer->incremental_unassign(partitions);
      if (error)
        Test::Fail(tostr() << "consumer->incremental_unassign() failed: " <<
                   error->str());
      if (partitions.size() == 0)
        Test::Fail("revoked partitions size should never be 0");
      revoke_call_cnt += 1;
      partitions_assigned_net -= (int)partitions.size();
    }

    /* Reset message counters for the given partitions. */
    Test::Say(consumer->name() + ": resetting message counters:\n");
    reset_msg_cnt(partitions);
  }

  bool poll_once (RdKafka::KafkaConsumer *c, int timeout_ms) {
    RdKafka::Message *msg = c->consume(timeout_ms);
    bool ret = msg->err() != RdKafka::ERR__TIMED_OUT;
    if (!msg->err())
      msg_cnt[Toppar(msg->topic_name(), msg->partition())]++;
    delete msg;
    return ret;
  }

  void reset_msg_cnt () {
    msg_cnt.clear();
  }

  void reset_msg_cnt (Toppar &tp) {
    int msgcnt = get_msg_cnt(tp);
    Test::Say(tostr() << " RESET " << tp.topic  << " [" << tp.partition << "]"
              << " with " << msgcnt << " messages\n");
    if (!msg_cnt.erase(tp) && msgcnt)
      Test::Fail("erase failed!");

  }

  void reset_msg_cnt (const vector<RdKafka::TopicPartition*> &partitions) {
    for (unsigned int i = 0 ; i < partitions.size() ; i++) {
      Toppar tp(partitions[i]->topic(), partitions[i]->partition());
      reset_msg_cnt(tp);
    }
  }

  int get_msg_cnt (const Toppar &tp) {
    map<Toppar,int>::iterator it = msg_cnt.find(tp);
    if (it == msg_cnt.end())
      return 0;
    return it->second;
  }

};




/**
 * @brief Verify that the consumer's assignment is a subset of the
 *        subscribed topics.
 *
 * @param allow_mismatch Allow assignment of not subscribed topics.
 *                       This can happen when the subscription is updated
 *                       but a rebalance callback hasn't been seen yet.
 * @param all_assignments Accumulated assignments for all consumers.
 *                        If an assigned partition already exists it means
 *                        the partition is assigned to multiple consumers and
 *                        the test will fail.
 * @param exp_msg_cnt Expected message count per assigned partition, or -1
 *                    if not to check.
 *
 * @returns the number of assigned partitions, or fails if the
 *          assignment is empty or there is an assignment for
 *          topic that is not subscribed.
 */
static int verify_consumer_assignment (RdKafka::KafkaConsumer *consumer,
                                       DefaultRebalanceCb &rebalance_cb,
                                       const vector<string> &topics,
                                       bool allow_empty,
                                       bool allow_mismatch,
                                       map<Toppar,RdKafka::KafkaConsumer*>
                                       *all_assignments,
                                       int exp_msg_cnt) {
  vector<RdKafka::TopicPartition*> partitions;
  RdKafka::ErrorCode err;
  int fails = 0;
  int count;
  ostringstream ss;

  err = consumer->assignment(partitions);
  TEST_ASSERT(!err,
              "Failed to get assignment for consumer %s: %s",
              consumer->name().c_str(),
              RdKafka::err2str(err).c_str());

  count = (int)partitions.size();

  for (vector<RdKafka::TopicPartition*>::iterator it = partitions.begin() ;
       it != partitions.end() ; it++) {
    RdKafka::TopicPartition *p = *it;

    if (find(topics.begin(), topics.end(), p->topic()) == topics.end()) {
      Test::Say(tostr() <<
                (allow_mismatch ? _C_YEL "Warning (allowed)" : _C_RED "Error")
                << ": " << consumer->name() << " is assigned "
                << p->topic() << " [" << p->partition() << "] which is "
                << "not in the list of subscribed topics: " <<
                string_vec_to_str(topics) << "\n");
      if (!allow_mismatch)
        fails++;
    }

    Toppar tp(p);
    pair<map<Toppar,RdKafka::KafkaConsumer*>::iterator,bool> ret;
    ret = all_assignments->insert(pair<Toppar,
                                  RdKafka::KafkaConsumer*>(tp, consumer));
    if (!ret.second) {
      Test::Say(tostr() << _C_RED << "Error: "
                << consumer->name() << " is assigned "
                << p->topic() << " [" << p->partition() << "] which is "
                "already assigned to consumer " <<
                ret.first->second->name() << "\n");
      fails++;
    }


    int msg_cnt = rebalance_cb.get_msg_cnt(tp);

    if (exp_msg_cnt != -1 && msg_cnt != exp_msg_cnt) {
      Test::Say(tostr() << _C_RED << "Error: "
                << consumer->name() << " expected " << exp_msg_cnt <<
                " messages on " <<
                p->topic() << " [" << p->partition() << "], not " <<
                msg_cnt << "\n");
      fails++;
    }

    ss << (it == partitions.begin() ? "" : ", ") << p->topic() <<
      " [" << p->partition() << "] (" << msg_cnt << "msgs)";
  }

  RdKafka::TopicPartition::destroy(partitions);

  Test::Say(tostr() << "Consumer " << consumer->name() <<
            " assignment (" << count << "): " << ss.str() << "\n");

  if (count == 0 && !allow_empty)
    Test::Fail("Consumer " + consumer->name() +
               " has unexpected empty assignment");

  if (fails)
    Test::Fail(tostr() << "Consumer " + consumer->name() <<
               " assignment verification failed (see previous error)");

  return count;
}







/* -------- a_assign_tests
 *
 * check behavior incremental assign / unassign outside the context of a rebalance.
 */


/** Incremental assign, then assign(NULL).
 */
static void assign_test_1 (RdKafka::KafkaConsumer *consumer,
                           std::vector<RdKafka::TopicPartition *> toppars1,
                           std::vector<RdKafka::TopicPartition *> toppars2) {
  RdKafka::ErrorCode err;
  RdKafka::Error *error;

  Test::Say("Incremental assign, then assign(NULL)\n");

  if ((error = consumer->incremental_assign(toppars1)))
    Test::Fail(tostr() << "Incremental assign failed: " << error->str());
  Test::check_assignment(consumer, 1, &toppars1[0]->topic());

  if ((err = consumer->unassign()))
    Test::Fail("Unassign failed: " + RdKafka::err2str(err));
  Test::check_assignment(consumer, 0, NULL);
}


/** Assign, then incremental unassign.
 */
static void assign_test_2 (RdKafka::KafkaConsumer *consumer,
                           std::vector<RdKafka::TopicPartition *> toppars1,
                           std::vector<RdKafka::TopicPartition *> toppars2) {
  RdKafka::ErrorCode err;
  RdKafka::Error *error;

  Test::Say("Assign, then incremental unassign\n");

  if ((err = consumer->assign(toppars1)))
    Test::Fail("Assign failed: " + RdKafka::err2str(err));
  Test::check_assignment(consumer, 1, &toppars1[0]->topic());

  if ((error = consumer->incremental_unassign(toppars1)))
    Test::Fail("Incremental unassign failed: " + error->str());
  Test::check_assignment(consumer, 0, NULL);
}


/** Incremental assign, then incremental unassign.
 */
static void assign_test_3 (RdKafka::KafkaConsumer *consumer,
                           std::vector<RdKafka::TopicPartition *> toppars1,
                           std::vector<RdKafka::TopicPartition *> toppars2) {
  RdKafka::Error *error;

  Test::Say("Incremental assign, then incremental unassign\n");

  if ((error = consumer->incremental_assign(toppars1)))
    Test::Fail("Incremental assign failed: " + error->str());
  Test::check_assignment(consumer, 1, &toppars1[0]->topic());

  if ((error = consumer->incremental_unassign(toppars1)))
    Test::Fail("Incremental unassign failed: " + error->str());
  Test::check_assignment(consumer, 0, NULL);
}


/** Multi-topic incremental assign and unassign + message consumption.
 */
static void assign_test_4 (RdKafka::KafkaConsumer *consumer,
                           std::vector<RdKafka::TopicPartition *> toppars1,
                           std::vector<RdKafka::TopicPartition *> toppars2) {
  RdKafka::Error *error;

  Test::Say("Multi-topic incremental assign and unassign + message consumption\n");

  if ((error = consumer->incremental_assign(toppars1)))
    Test::Fail("Incremental assign failed: " + error->str());
  Test::check_assignment(consumer, 1, &toppars1[0]->topic());

  RdKafka::Message *m = consumer->consume(5000);
  if (m->err() != RdKafka::ERR_NO_ERROR)
    Test::Fail("Expecting a consumed message.");
  if (m->len() != 100)
    Test::Fail(tostr() << "Expecting msg len to be 100, not: " << m->len()); /* implies read from topic 1. */
  delete m;

  if ((error = consumer->incremental_unassign(toppars1)))
    Test::Fail("Incremental unassign failed: " + error->str());
  Test::check_assignment(consumer, 0, NULL);

  m = consumer->consume(100);
  if (m->err() != RdKafka::ERR__TIMED_OUT)
    Test::Fail("Not expecting a consumed message.");
  delete m;

  if ((error = consumer->incremental_assign(toppars2)))
    Test::Fail("Incremental assign failed: " + error->str());
  Test::check_assignment(consumer, 1, &toppars2[0]->topic());

  m = consumer->consume(5000);
  if (m->err() != RdKafka::ERR_NO_ERROR)
    Test::Fail("Expecting a consumed message.");
  if (m->len() != 200)
    Test::Fail(tostr() << "Expecting msg len to be 200, not: " << m->len()); /* implies read from topic 2. */
  delete m;

  if ((error = consumer->incremental_assign(toppars1)))
    Test::Fail("Incremental assign failed: " + error->str());
  if (Test::assignment_partition_count(consumer, NULL) != 2)
    Test::Fail(tostr() << "Expecting current assignment to have size 2, not: " << Test::assignment_partition_count(consumer, NULL));

  m = consumer->consume(5000);
  if (m->err() != RdKafka::ERR_NO_ERROR)
    Test::Fail("Expecting a consumed message.");
  delete m;

  if ((error = consumer->incremental_unassign(toppars2)))
    Test::Fail("Incremental unassign failed: " + error->str());
  if ((error = consumer->incremental_unassign(toppars1)))
    Test::Fail("Incremental unassign failed: " + error->str());
  Test::check_assignment(consumer, 0, NULL);
}


/** Incremental assign and unassign of empty collection.
 */
static void assign_test_5 (RdKafka::KafkaConsumer *consumer,
                           std::vector<RdKafka::TopicPartition *> toppars1,
                           std::vector<RdKafka::TopicPartition *> toppars2) {
  RdKafka::Error *error;
  std::vector<RdKafka::TopicPartition *> toppars3;

  Test::Say("Incremental assign and unassign of empty collection\n");

  if ((error = consumer->incremental_assign(toppars3)))
    Test::Fail("Incremental assign failed: " + error->str());
  Test::check_assignment(consumer, 0, NULL);

  if ((error = consumer->incremental_unassign(toppars3)))
    Test::Fail("Incremental unassign failed: " + error->str());
  Test::check_assignment(consumer, 0, NULL);
}




static void
run_test (const std::string &t1, const std::string &t2,
          void (*test)(RdKafka::KafkaConsumer *consumer,
                       std::vector<RdKafka::TopicPartition *> toppars1,
                       std::vector<RdKafka::TopicPartition *> toppars2)) {
    std::vector<RdKafka::TopicPartition *> toppars1;
    toppars1.push_back(RdKafka::TopicPartition::create(t1, 0));
    std::vector<RdKafka::TopicPartition *> toppars2;
    toppars2.push_back(RdKafka::TopicPartition::create(t2, 0));

    RdKafka::KafkaConsumer *consumer = make_consumer("C_1", t1,
                                                     "cooperative-sticky",
                                                     NULL, NULL, 10);

    test(consumer, toppars1, toppars2);

    RdKafka::TopicPartition::destroy(toppars1);
    RdKafka::TopicPartition::destroy(toppars2);

    consumer->close();
    delete consumer;
}


static void a_assign_tests () {
    SUB_TEST_QUICK();

    int msgcnt = 1000;
    const int msgsize1 = 100;
    const int msgsize2 = 200;

    std::string topic1_str = Test::mk_topic_name("0113-a1", 1);
    test_create_topic(NULL, topic1_str.c_str(), 1, 1);
    std::string topic2_str = Test::mk_topic_name("0113-a2", 1);
    test_create_topic(NULL, topic2_str.c_str(), 1, 1);

    test_produce_msgs_easy_size(topic1_str.c_str(), 0, 0, msgcnt, msgsize1);
    test_produce_msgs_easy_size(topic2_str.c_str(), 0, 0, msgcnt, msgsize2);

    run_test(topic1_str, topic2_str, assign_test_1);
    run_test(topic1_str, topic2_str, assign_test_2);
    run_test(topic1_str, topic2_str, assign_test_3);
    run_test(topic1_str, topic2_str, assign_test_4);
    run_test(topic1_str, topic2_str, assign_test_5);

    SUB_TEST_PASS();
}



/**
 * @brief Quick Assign 1,2, Assign 2,3, Assign 1,2,3 test to verify
 *        that the correct OffsetFetch response is used.
 *        See note in rdkafka_assignment.c for details.
 *
 * Makes use of the mock cluster to induce latency.
 */
static void a_assign_rapid () {
  SUB_TEST_QUICK();

  std::string group_id = __FUNCTION__;

  rd_kafka_mock_cluster_t *mcluster;
  const char *bootstraps;

  mcluster = test_mock_cluster_new(3, &bootstraps);
  int32_t coord_id = 1;
  rd_kafka_mock_coordinator_set(mcluster, "group", group_id.c_str(), coord_id);

  rd_kafka_mock_topic_create(mcluster, "topic1", 1, 1);
  rd_kafka_mock_topic_create(mcluster, "topic2", 1, 1);
  rd_kafka_mock_topic_create(mcluster, "topic3", 1, 1);

  /*
   * Produce messages to topics
   */
  const int msgs_per_partition = 1000;

  RdKafka::Conf *pconf;
  Test::conf_init(&pconf, NULL, 10);
  Test::conf_set(pconf, "bootstrap.servers", bootstraps);
  std::string errstr;
  RdKafka::Producer *p = RdKafka::Producer::create(pconf, errstr);
  if (!p)
    Test::Fail(tostr() << __FUNCTION__ << ": Failed to create producer: " <<
               errstr);
  delete pconf;

  Test::produce_msgs(p, "topic1", 0, msgs_per_partition, 10, false/*no flush*/);
  Test::produce_msgs(p, "topic2", 0, msgs_per_partition, 10, false/*no flush*/);
  Test::produce_msgs(p, "topic3", 0, msgs_per_partition, 10, false/*no flush*/);
  p->flush(10*1000);

  delete p;

  vector<RdKafka::TopicPartition *> toppars1;
  toppars1.push_back(RdKafka::TopicPartition::create("topic1", 0));
  vector<RdKafka::TopicPartition *> toppars2;
  toppars2.push_back(RdKafka::TopicPartition::create("topic2", 0));
  vector<RdKafka::TopicPartition *> toppars3;
  toppars3.push_back(RdKafka::TopicPartition::create("topic3", 0));


  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 20);
  Test::conf_set(conf, "bootstrap.servers", bootstraps);
  Test::conf_set(conf, "client.id", __FUNCTION__);
  Test::conf_set(conf, "group.id", group_id);
  Test::conf_set(conf, "auto.offset.reset", "earliest");
  Test::conf_set(conf, "enable.auto.commit", "false");

  RdKafka::KafkaConsumer *consumer;
  consumer = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!consumer)
    Test::Fail(tostr() << __FUNCTION__ << ": Failed to create consumer: " <<
               errstr);
  delete conf;

  vector<RdKafka::TopicPartition *> toppars;
  vector<RdKafka::TopicPartition *> expected;

  map<Toppar, int64_t> pos;  /* Expected consume position per partition */
  pos[Toppar(toppars1[0]->topic(), toppars1[0]->partition())] = 0;
  pos[Toppar(toppars2[0]->topic(), toppars2[0]->partition())] = 0;
  pos[Toppar(toppars3[0]->topic(), toppars3[0]->partition())] = 0;

  /* To make sure offset commits are fetched in proper assign sequence
   * we commit an offset that should not be used in the final consume loop.
   * This commit will be overwritten below with another commit. */
  vector<RdKafka::TopicPartition *> offsets;
  offsets.push_back(RdKafka::TopicPartition::create(toppars1[0]->topic(),
                                                    toppars1[0]->partition(),
                                                    11));
  /* This partition should start at this position even though
   * there will be a sub-sequent commit to overwrite it, that should not
   * be used since this partition is never unassigned. */
  offsets.push_back(RdKafka::TopicPartition::create(toppars2[0]->topic(),
                                                    toppars2[0]->partition(),
                                                    22));
  pos[Toppar(toppars2[0]->topic(), toppars2[0]->partition())] = 22;

  Test::print_TopicPartitions("pre-commit", offsets);

  RdKafka::ErrorCode err;
  err = consumer->commitSync(offsets);
  if (err)
    Test::Fail(tostr() << __FUNCTION__ << ": pre-commit failed: " <<
               RdKafka::err2str(err) << "\n");

  /* Add coordinator delay so that the OffsetFetchRequest originating
   * from the coming incremental_assign() will not finish before
   * we call incremental_unassign() and incremental_assign() again, resulting
   * in a situation where the initial OffsetFetchResponse will contain
   * an older offset for a previous assignment of one partition. */
  rd_kafka_mock_broker_set_rtt(mcluster, coord_id, 5000);


  /* Assign 1,2 == 1,2 */
  toppars.push_back(toppars1[0]);
  toppars.push_back(toppars2[0]);
  expected.push_back(toppars1[0]);
  expected.push_back(toppars2[0]);
  Test::incremental_assign(consumer, toppars);
  expect_assignment(consumer, expected);

  /* Unassign -1 == 2 */
  toppars.clear();
  toppars.push_back(toppars1[0]);
  vector<RdKafka::TopicPartition *>::iterator it = find(expected.begin(),
                                                        expected.end(),
                                                        toppars1[0]);
  expected.erase(it);

  Test::incremental_unassign(consumer, toppars);
  expect_assignment(consumer, expected);


  /* Commit offset for the removed partition and the partition that is
   * unchanged in the assignment. */
  RdKafka::TopicPartition::destroy(offsets);
  offsets.push_back(RdKafka::TopicPartition::create(toppars1[0]->topic(),
                                                    toppars1[0]->partition(),
                                                    55));
  offsets.push_back(RdKafka::TopicPartition::create(toppars2[0]->topic(),
                                                    toppars2[0]->partition(),
                                                    33)); /* should not be
                                                           * used. */
  pos[Toppar(toppars1[0]->topic(), toppars1[0]->partition())] = 55;
  Test::print_TopicPartitions("commit", offsets);

  err = consumer->commitAsync(offsets);
  if (err)
    Test::Fail(tostr() << __FUNCTION__ << ": commit failed: " <<
               RdKafka::err2str(err) << "\n");

  /* Assign +3 == 2,3 */
  toppars.clear();
  toppars.push_back(toppars3[0]);
  expected.push_back(toppars3[0]);
  Test::incremental_assign(consumer, toppars);
  expect_assignment(consumer, expected);

  /* Now remove the latency */
  Test::Say(_C_MAG "Clearing rtt\n");
  rd_kafka_mock_broker_set_rtt(mcluster, coord_id, 0);

  /* Assign +1 == 1,2,3 */
  toppars.clear();
  toppars.push_back(toppars1[0]);
  expected.push_back(toppars1[0]);
  Test::incremental_assign(consumer, toppars);
  expect_assignment(consumer, expected);

  /*
   * Verify consumed messages
   */
  int wait_end = (int)expected.size();
  while (wait_end > 0) {
    RdKafka::Message *msg = consumer->consume(10*1000);
    if (msg->err() == RdKafka::ERR__TIMED_OUT)
      Test::Fail(tostr() << __FUNCTION__ << ": Consume timed out waiting "
                 "for " << wait_end << " more partitions");

    Toppar tp = Toppar(msg->topic_name(), msg->partition());
    int64_t *exp_pos = &pos[tp];

    Test::Say(3, tostr() << __FUNCTION__ << ": Received " <<
              tp.topic << " [" << tp.partition << "] at offset " <<
              msg->offset() << " (expected offset " << *exp_pos << ")\n");

    if (*exp_pos != msg->offset())
      Test::Fail(tostr() << __FUNCTION__ << ": expected message offset " <<
                 *exp_pos << " for " << msg->topic_name() <<
                 " [" << msg->partition() << "], not " << msg->offset() <<
                 "\n");
    (*exp_pos)++;
    if (*exp_pos == msgs_per_partition) {
      TEST_ASSERT(wait_end > 0, "");
      wait_end--;
    } else if (msg->offset() > msgs_per_partition)
      Test::Fail(tostr() << __FUNCTION__ << ": unexpected message with " <<
                 "offset " << msg->offset() << " on " << tp.topic <<
                 " [" << tp.partition << "]\n");

    delete msg;
  }

  RdKafka::TopicPartition::destroy(offsets);
  RdKafka::TopicPartition::destroy(toppars1);
  RdKafka::TopicPartition::destroy(toppars2);
  RdKafka::TopicPartition::destroy(toppars3);

  delete consumer;

  test_mock_cluster_destroy(mcluster);

  SUB_TEST_PASS();
}


/* Check behavior when:
 *   1. single topic with 2 partitions.
 *   2. consumer 1 (with rebalance_cb) subscribes to it.
 *   3. consumer 2 (with rebalance_cb) subscribes to it.
 *   4. close.
 */

static void b_subscribe_with_cb_test (rd_bool_t close_consumer) {
  SUB_TEST();

  std::string topic_name = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  std::string group_name = Test::mk_unique_group_name("0113-cooperative_rebalance");
  test_create_topic(NULL, topic_name.c_str(), 2, 1);

  DefaultRebalanceCb rebalance_cb1;
  RdKafka::KafkaConsumer *c1 = make_consumer("C_1", group_name, "cooperative-sticky", NULL, &rebalance_cb1, 25);
  DefaultRebalanceCb rebalance_cb2;
  RdKafka::KafkaConsumer *c2 = make_consumer("C_2", group_name, "cooperative-sticky", NULL, &rebalance_cb2, 25);
  test_wait_topic_exists(c1->c_ptr(), topic_name.c_str(), 10*1000);

  Test::subscribe(c1, topic_name);

  bool c2_subscribed = false;
  while (true) {
    Test::poll_once(c1, 500);
    Test::poll_once(c2, 500);

    /* Start c2 after c1 has received initial assignment */
    if (!c2_subscribed && rebalance_cb1.assign_call_cnt > 0) {
      Test::subscribe(c2, topic_name);
      c2_subscribed = true;
    }

    /* Failure case: test will time out. */
    if (rebalance_cb1.assign_call_cnt == 3 &&
        rebalance_cb2.assign_call_cnt == 2) {
      break;
    }
  }

  /* Sequence of events:
   *
   * 1. c1 joins group.
   * 2. c1 gets assigned 2 partitions.
   *     - there isn't a follow-on rebalance because there aren't any revoked partitions.
   * 3. c2 joins group.
   * 4. This results in a rebalance with one partition being revoked from c1, and no
   *    partitions assigned to either c1 or c2 (however the rebalance callback will be
   *    called in each case with an empty set).
   * 5. c1 then re-joins the group since it had a partition revoked.
   * 6. c2 is now assigned a single partition, and c1's incremental assignment is empty.
   * 7. Since there were no revoked partitions, no further rebalance is triggered.
   */

  /* The rebalance cb is always called on assign, even if empty. */
  if (rebalance_cb1.assign_call_cnt != 3)
    Test::Fail(tostr() << "Expecting 3 assign calls on consumer 1, not " << rebalance_cb1.assign_call_cnt);
  if (rebalance_cb2.assign_call_cnt != 2)
    Test::Fail(tostr() << "Expecting 2 assign calls on consumer 2, not: " << rebalance_cb2.assign_call_cnt);

  /* The rebalance cb is not called on and empty revoke (unless partitions lost, which is not the case here) */
  if (rebalance_cb1.revoke_call_cnt != 1)
    Test::Fail(tostr() << "Expecting 1 revoke call on consumer 1, not: " << rebalance_cb1.revoke_call_cnt);
  if (rebalance_cb2.revoke_call_cnt != 0)
    Test::Fail(tostr() << "Expecting 0 revoke calls on consumer 2, not: " << rebalance_cb2.revoke_call_cnt);

  /* Final state */

  /* Expect both consumers to have 1 assigned partition (via net calculation in rebalance_cb) */
  if (rebalance_cb1.partitions_assigned_net != 1)
    Test::Fail(tostr() << "Expecting consumer 1 to have net 1 assigned partition, not: " << rebalance_cb1.partitions_assigned_net);
  if (rebalance_cb2.partitions_assigned_net != 1)
    Test::Fail(tostr() << "Expecting consumer 2 to have net 1 assigned partition, not: " << rebalance_cb2.partitions_assigned_net);

  /* Expect both consumers to have 1 assigned partition (via ->assignment() query) */
  expect_assignment(c1, 1);
  expect_assignment(c2, 1);

  /* Make sure the fetchers are running */
  int msgcnt = 100;
  const int msgsize1 = 100;
  test_produce_msgs_easy_size(topic_name.c_str(), 0, 0, msgcnt, msgsize1);
  test_produce_msgs_easy_size(topic_name.c_str(), 0, 1, msgcnt, msgsize1);

  bool consumed_from_c1 = false;
  bool consumed_from_c2 = false;
  while (true) {
    RdKafka::Message *msg1 = c1->consume(100);
    RdKafka::Message *msg2 = c2->consume(100);

    if (msg1->err() == RdKafka::ERR_NO_ERROR)
      consumed_from_c1 = true;
    if (msg1->err() == RdKafka::ERR_NO_ERROR)
      consumed_from_c2 = true;

    delete msg1;
    delete msg2;

    /* Failure case: test will timeout. */
    if (consumed_from_c1 && consumed_from_c2)
      break;
  }

  if (!close_consumer) {
    delete c1;
    delete c2;
    return;
  }

  c1->close();
  c2->close();

  /* Closing the consumer should trigger rebalance_cb (revoke): */
  if (rebalance_cb1.revoke_call_cnt != 2)
    Test::Fail(tostr() << "Expecting 2 revoke calls on consumer 1, not: " << rebalance_cb1.revoke_call_cnt);
  if (rebalance_cb2.revoke_call_cnt != 1)
    Test::Fail(tostr() << "Expecting 1 revoke call on consumer 2, not: " << rebalance_cb2.revoke_call_cnt);

  /* ..and net assigned partitions should drop to 0 in both cases: */
  if (rebalance_cb1.partitions_assigned_net != 0)
    Test::Fail(tostr() << "Expecting consumer 1 to have net 0 assigned partitions, not: " << rebalance_cb1.partitions_assigned_net);
  if (rebalance_cb2.partitions_assigned_net != 0)
    Test::Fail(tostr() << "Expecting consumer 2 to have net 0 assigned partitions, not: " << rebalance_cb2.partitions_assigned_net);

  /* Nothing in this test should result in lost partitions */
  if (rebalance_cb1.lost_call_cnt > 0)
    Test::Fail(tostr() << "Expecting consumer 1 to have 0 lost partition events, not: " << rebalance_cb1.lost_call_cnt);
  if (rebalance_cb2.lost_call_cnt > 0)
    Test::Fail(tostr() << "Expecting consumer 2 to have 0 lost partition events, not: " << rebalance_cb2.lost_call_cnt);

  delete c1;
  delete c2;

  SUB_TEST_PASS();
}



/* Check behavior when:
 *   1. Single topic with 2 partitions.
 *   2. Consumer 1 (no rebalance_cb) subscribes to it.
 *   3. Consumer 2 (no rebalance_cb) subscribes to it.
 *   4. Close.
 */

static void c_subscribe_no_cb_test (rd_bool_t close_consumer) {
  SUB_TEST();

  std::string topic_name = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  std::string group_name = Test::mk_unique_group_name("0113-cooperative_rebalance");
  test_create_topic(NULL, topic_name.c_str(), 2, 1);

  RdKafka::KafkaConsumer *c1 = make_consumer("C_1", group_name, "cooperative-sticky", NULL, NULL, 20);
  RdKafka::KafkaConsumer *c2 = make_consumer("C_2", group_name, "cooperative-sticky", NULL, NULL, 20);
  test_wait_topic_exists(c1->c_ptr(), topic_name.c_str(), 10*1000);

  Test::subscribe(c1, topic_name);

  bool c2_subscribed = false;
  bool done = false;
  while (!done) {
    Test::poll_once(c1, 500);
    Test::poll_once(c2, 500);

    if (Test::assignment_partition_count(c1, NULL) == 2 && !c2_subscribed) {
      Test::subscribe(c2, topic_name);
      c2_subscribed = true;
    }

    if (Test::assignment_partition_count(c1, NULL) == 1 &&
        Test::assignment_partition_count(c2, NULL) == 1) {
      Test::Say("Consumer 1 and 2 are both assigned to single partition.\n");
      done = true;
    }
  }

  if (close_consumer) {
    Test::Say("Closing consumer 1\n");
    c1->close();
    Test::Say("Closing consumer 2\n");
    c2->close();
  } else {
    Test::Say("Skipping close() of consumer 1 and 2.\n");
  }

  delete c1;
  delete c2;

  SUB_TEST_PASS();
}



/* Check behavior when:
 *   1. Single consumer (no rebalance_cb) subscribes to topic.
 *   2. Subscription is changed (topic added).
 *   3. Consumer is closed.
 */

static void d_change_subscription_add_topic (rd_bool_t close_consumer) {
  SUB_TEST();

  std::string topic_name_1 = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  test_create_topic(NULL, topic_name_1.c_str(), 2, 1);
  std::string topic_name_2 = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  test_create_topic(NULL, topic_name_2.c_str(), 2, 1);

  std::string group_name = Test::mk_unique_group_name("0113-cooperative_rebalance");

  RdKafka::KafkaConsumer *c = make_consumer("C_1", group_name, "cooperative-sticky", NULL, NULL, 15);
  test_wait_topic_exists(c->c_ptr(), topic_name_1.c_str(), 10*1000);
  test_wait_topic_exists(c->c_ptr(), topic_name_2.c_str(), 10*1000);

  Test::subscribe(c, topic_name_1);

  bool subscribed_to_one_topic = false;
  bool done = false;
  while (!done) {
    Test::poll_once(c, 500);

    if (Test::assignment_partition_count(c, NULL) == 2 && !subscribed_to_one_topic) {
      subscribed_to_one_topic = true;
      Test::subscribe(c, topic_name_1, topic_name_2);
    }

    if (Test::assignment_partition_count(c, NULL) == 4) {
      Test::Say("Consumer is assigned to two topics.\n");
      done = true;
    }
  }

  if (close_consumer) {
    Test::Say("Closing consumer\n");
    c->close();
  } else
    Test::Say("Skipping close() of consumer\n");

  delete c;

  SUB_TEST_PASS();
}



/* Check behavior when:
 *   1. Single consumer (no rebalance_cb) subscribes to topic.
 *   2. Subscription is changed (topic added).
 *   3. Consumer is closed.
 */

static void e_change_subscription_remove_topic (rd_bool_t close_consumer) {
  SUB_TEST();

  std::string topic_name_1 = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  test_create_topic(NULL, topic_name_1.c_str(), 2, 1);
  std::string topic_name_2 = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  test_create_topic(NULL, topic_name_2.c_str(), 2, 1);

  std::string group_name = Test::mk_unique_group_name("0113-cooperative_rebalance");

  RdKafka::KafkaConsumer *c = make_consumer("C_1", group_name, "cooperative-sticky", NULL, NULL, 15);
  test_wait_topic_exists(c->c_ptr(), topic_name_1.c_str(), 10*1000);
  test_wait_topic_exists(c->c_ptr(), topic_name_2.c_str(), 10*1000);

  Test::subscribe(c, topic_name_1, topic_name_2);

  bool subscribed_to_two_topics = false;
  bool done = false;
  while (!done) {
    Test::poll_once(c, 500);

    if (Test::assignment_partition_count(c, NULL) == 4 && !subscribed_to_two_topics) {
      subscribed_to_two_topics = true;
      Test::subscribe(c, topic_name_1);
    }

    if (Test::assignment_partition_count(c, NULL) == 2) {
      Test::Say("Consumer is assigned to one topic\n");
      done = true;
    }
  }

  if (!close_consumer) {
    Test::Say("Closing consumer\n");
    c->close();
  } else
    Test::Say("Skipping close() of consumer\n");

  delete c;

  SUB_TEST_PASS();
}



/* Check that use of consumer->assign() and consumer->unassign() is disallowed when a
 * COOPERATIVE assignor is in use.
 */

class FTestRebalanceCb : public RdKafka::RebalanceCb {
public:
  rd_bool_t assigned;

  FTestRebalanceCb () {
    assigned = rd_false;
  }

  void rebalance_cb (RdKafka::KafkaConsumer *consumer,
                     RdKafka::ErrorCode err,
                     std::vector<RdKafka::TopicPartition*> &partitions) {
    Test::Say(tostr() << "RebalanceCb: " << consumer->name() << " " << RdKafka::err2str(err) << "\n");

    if (err == RdKafka::ERR__ASSIGN_PARTITIONS) {
      RdKafka::ErrorCode err_resp = consumer->assign(partitions);
      Test::Say(tostr() << "consumer->assign() response code: " << err_resp << "\n");
      if (err_resp != RdKafka::ERR__STATE)
        Test::Fail(tostr() << "Expected assign to fail with error code: " << RdKafka::ERR__STATE << "(ERR__STATE)");

      RdKafka::Error *error = consumer->incremental_assign(partitions);
      if (error)
        Test::Fail(tostr() << "consumer->incremental_unassign() failed: " << error->str());

      assigned = rd_true;

    } else {
      RdKafka::ErrorCode err_resp = consumer->unassign();
      Test::Say(tostr() << "consumer->unassign() response code: " << err_resp << "\n");
      if (err_resp != RdKafka::ERR__STATE)
        Test::Fail(tostr() << "Expected assign to fail with error code: " << RdKafka::ERR__STATE << "(ERR__STATE)");

      RdKafka::Error *error = consumer->incremental_unassign(partitions);
      if (error)
        Test::Fail(tostr() << "consumer->incremental_unassign() failed: " << error->str());
    }
  }
};


static void f_assign_call_cooperative () {
  SUB_TEST();

  std::string topic_name = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  test_create_topic(NULL, topic_name.c_str(), 1, 1);

  std::string group_name = Test::mk_unique_group_name("0113-cooperative_rebalance");

  std::vector<std::pair<std::string, std::string> > additional_conf;
  additional_conf.push_back(std::pair<std::string, std::string>(std::string("topic.metadata.refresh.interval.ms"), std::string("3000")));
  FTestRebalanceCb rebalance_cb;
  RdKafka::KafkaConsumer *c = make_consumer("C_1", group_name, "cooperative-sticky", &additional_conf, &rebalance_cb, 15);
  test_wait_topic_exists(c->c_ptr(), topic_name.c_str(), 10*1000);

  Test::subscribe(c, topic_name);

  while (!rebalance_cb.assigned)
    Test::poll_once(c, 500);

  c->close();
  delete c;

  SUB_TEST_PASS();
}



/* Check that use of consumer->incremental_assign() and consumer->incremental_unassign() is
 * disallowed when an EAGER assignor is in use.
 */
class GTestRebalanceCb : public RdKafka::RebalanceCb {
public:
  rd_bool_t assigned;

  GTestRebalanceCb () {
    assigned = rd_false;
  }

  void rebalance_cb (RdKafka::KafkaConsumer *consumer,
                                 RdKafka::ErrorCode err,
                     std::vector<RdKafka::TopicPartition*> &partitions) {
    Test::Say(tostr() << "RebalanceCb: " << consumer->name() << " " << RdKafka::err2str(err) << "\n");

    if (err == RdKafka::ERR__ASSIGN_PARTITIONS) {
      RdKafka::Error *error = consumer->incremental_assign(partitions);
      Test::Say(tostr() << "consumer->incremental_assign() response: " << (!error ? "NULL" : error->str()) << "\n");
      if (!error)
        Test::Fail("Expected consumer->incremental_assign() to fail");
      if (error->code() != RdKafka::ERR__STATE)
        Test::Fail(tostr() << "Expected consumer->incremental_assign() to fail with error code " << RdKafka::ERR__STATE);
      delete error;

      RdKafka::ErrorCode err_resp = consumer->assign(partitions);
      if (err_resp)
        Test::Fail(tostr() << "consumer->assign() failed: " << err_resp);

      assigned = rd_true;

    } else {
      RdKafka::Error *error = consumer->incremental_unassign(partitions);
      Test::Say(tostr() << "consumer->incremental_unassign() response: " << (!error ? "NULL" : error->str()) << "\n");
      if (!error)
        Test::Fail("Expected consumer->incremental_unassign() to fail");
      if (error->code() != RdKafka::ERR__STATE)
        Test::Fail(tostr() << "Expected consumer->incremental_unassign() to fail with error code " << RdKafka::ERR__STATE);
      delete error;

      RdKafka::ErrorCode err_resp = consumer->unassign();
      if (err_resp)
        Test::Fail(tostr() << "consumer->unassign() failed: " << err_resp);
    }
  }
};

static void g_incremental_assign_call_eager() {
  SUB_TEST();

  std::string topic_name = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  test_create_topic(NULL, topic_name.c_str(), 1, 1);

  std::string group_name = Test::mk_unique_group_name("0113-cooperative_rebalance");

  std::vector<std::pair<std::string, std::string> > additional_conf;
  additional_conf.push_back(std::pair<std::string, std::string>(std::string("topic.metadata.refresh.interval.ms"), std::string("3000")));
  GTestRebalanceCb rebalance_cb;
  RdKafka::KafkaConsumer *c = make_consumer("C_1", group_name, "roundrobin", &additional_conf, &rebalance_cb, 15);
  test_wait_topic_exists(c->c_ptr(), topic_name.c_str(), 10*1000);

  Test::subscribe(c, topic_name);

  while (!rebalance_cb.assigned)
    Test::poll_once(c, 500);

  c->close();
  delete c;

  SUB_TEST_PASS();
}



/* Check behavior when:
 *   1. Single consumer (rebalance_cb) subscribes to two topics.
 *   2. One of the topics is deleted.
 *   3. Consumer is closed.
 */

static void h_delete_topic () {
  SUB_TEST();

  std::string topic_name_1 = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  test_create_topic(NULL, topic_name_1.c_str(), 1, 1);
  std::string topic_name_2 = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  test_create_topic(NULL, topic_name_2.c_str(), 1, 1);

  std::string group_name = Test::mk_unique_group_name("0113-cooperative_rebalance");

  std::vector<std::pair<std::string, std::string> > additional_conf;
  additional_conf.push_back(std::pair<std::string, std::string>(std::string("topic.metadata.refresh.interval.ms"), std::string("3000")));
  DefaultRebalanceCb rebalance_cb;
  RdKafka::KafkaConsumer *c = make_consumer("C_1", group_name, "cooperative-sticky", &additional_conf, &rebalance_cb, 15);
  test_wait_topic_exists(c->c_ptr(), topic_name_1.c_str(), 10*1000);
  test_wait_topic_exists(c->c_ptr(), topic_name_2.c_str(), 10*1000);

  Test::subscribe(c, topic_name_1, topic_name_2);

  bool deleted = false;
  bool done = false;
  while (!done) {
    Test::poll_once(c, 500);

    std::vector<RdKafka::TopicPartition*> partitions;
    c->assignment(partitions);

    if (partitions.size() == 2 && !deleted) {
      if (rebalance_cb.assign_call_cnt != 1)
        Test::Fail(tostr() << "Expected 1 assign call, saw " << rebalance_cb.assign_call_cnt << "\n");
      Test::delete_topic(c, topic_name_2.c_str());
      deleted = true;
    }

    if (partitions.size() == 1 && deleted) {
      if (partitions[0]->topic() != topic_name_1)
        Test::Fail(tostr() << "Expecting subscribed topic to be '" << topic_name_1 << "' not '" << partitions[0]->topic() << "'");
      Test::Say(tostr() << "Assignment no longer includes deleted topic '" << topic_name_2 << "'\n");
      done = true;
    }

    RdKafka::TopicPartition::destroy(partitions);
  }

  Test::Say("Closing consumer\n");
  c->close();

  delete c;

  SUB_TEST_PASS();
}



/* Check behavior when:
 *   1. Single consumer (rebalance_cb) subscribes to a single topic.
 *   2. That topic is deleted leaving no topics.
 *   3. Consumer is closed.
 */

static void i_delete_topic_2 () {
  SUB_TEST();

  std::string topic_name_1 = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  test_create_topic(NULL, topic_name_1.c_str(), 1, 1);
  std::string group_name = Test::mk_unique_group_name("0113-cooperative_rebalance");

  std::vector<std::pair<std::string, std::string> > additional_conf;
  additional_conf.push_back(std::pair<std::string, std::string>(std::string("topic.metadata.refresh.interval.ms"), std::string("3000")));
  DefaultRebalanceCb rebalance_cb;
  RdKafka::KafkaConsumer *c = make_consumer("C_1", group_name, "cooperative-sticky", &additional_conf, &rebalance_cb, 15);
  test_wait_topic_exists(c->c_ptr(), topic_name_1.c_str(), 10*1000);

  Test::subscribe(c, topic_name_1);

  bool deleted = false;
  bool done = false;
  while (!done) {
    Test::poll_once(c, 500);

    if (Test::assignment_partition_count(c, NULL) == 1 && !deleted) {
      if (rebalance_cb.assign_call_cnt != 1)
        Test::Fail(tostr() << "Expected one assign call, saw " << rebalance_cb.assign_call_cnt << "\n");
      Test::delete_topic(c, topic_name_1.c_str());
      deleted = true;
    }

    if (Test::assignment_partition_count(c, NULL) == 0 && deleted) {
      Test::Say(tostr() << "Assignment is empty following deletion of topic\n");
      done = true;
    }
  }

  Test::Say("Closing consumer\n");
  c->close();

  delete c;

  SUB_TEST_PASS();
}



/* Check behavior when:
 *   1. single consumer (without rebalance_cb) subscribes to a single topic.
 *   2. that topic is deleted leaving no topics.
 *   3. consumer is closed.
 */

static void j_delete_topic_no_rb_callback () {
  SUB_TEST();

  std::string topic_name_1 = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  test_create_topic(NULL, topic_name_1.c_str(), 1, 1);

  std::string group_name = Test::mk_unique_group_name("0113-cooperative_rebalance");

  std::vector<std::pair<std::string, std::string> > additional_conf;
  additional_conf.push_back(std::pair<std::string, std::string>(std::string("topic.metadata.refresh.interval.ms"), std::string("3000")));
  RdKafka::KafkaConsumer *c = make_consumer("C_1", group_name, "cooperative-sticky", &additional_conf, NULL, 15);
  test_wait_topic_exists(c->c_ptr(), topic_name_1.c_str(), 10*1000);

  Test::subscribe(c, topic_name_1);

  bool deleted = false;
  bool done = false;
  while (!done) {
    Test::poll_once(c, 500);

    if (Test::assignment_partition_count(c, NULL) == 1 && !deleted) {
      Test::delete_topic(c, topic_name_1.c_str());
      deleted = true;
    }

    if (Test::assignment_partition_count(c, NULL) == 0 && deleted) {
      Test::Say(tostr() << "Assignment is empty following deletion of topic\n");
      done = true;
    }
  }

  Test::Say("Closing consumer\n");
  c->close();

  delete c;

  SUB_TEST_PASS();
}



/* Check behavior when:
 *   1. Single consumer (rebalance_cb) subscribes to a 1 partition topic.
 *   2. Number of partitions is increased to 2.
 *   3. Consumer is closed.
 */

static void k_add_partition () {
  SUB_TEST();

  std::string topic_name = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  test_create_topic(NULL, topic_name.c_str(), 1, 1);

  std::string group_name = Test::mk_unique_group_name("0113-cooperative_rebalance");

  std::vector<std::pair<std::string, std::string> > additional_conf;
  additional_conf.push_back(std::pair<std::string, std::string>(std::string("topic.metadata.refresh.interval.ms"), std::string("3000")));
  DefaultRebalanceCb rebalance_cb;
  RdKafka::KafkaConsumer *c = make_consumer("C_1", group_name, "cooperative-sticky", &additional_conf, &rebalance_cb, 15);
  test_wait_topic_exists(c->c_ptr(), topic_name.c_str(), 10*1000);

  Test::subscribe(c, topic_name);

  bool subscribed = false;
  bool done = false;
  while (!done) {
    Test::poll_once(c, 500);

    if (Test::assignment_partition_count(c, NULL) == 1 && !subscribed) {
      if (rebalance_cb.assign_call_cnt != 1)
        Test::Fail(tostr() << "Expected 1 assign call, saw " << rebalance_cb.assign_call_cnt);
      if (rebalance_cb.revoke_call_cnt != 0)
        Test::Fail(tostr() << "Expected 0 revoke calls, saw " << rebalance_cb.revoke_call_cnt);
      Test::create_partitions(c, topic_name.c_str(), 2);
      subscribed = true;
    }

    if (Test::assignment_partition_count(c, NULL) == 2 && subscribed) {
      if (rebalance_cb.assign_call_cnt != 2)
        Test::Fail(tostr() << "Expected 2 assign calls, saw " << rebalance_cb.assign_call_cnt);
      if (rebalance_cb.revoke_call_cnt != 0)
        Test::Fail(tostr() << "Expected 0 revoke calls, saw " << rebalance_cb.revoke_call_cnt);
      done = true;
    }
  }

  Test::Say("Closing consumer\n");
  c->close();
  delete c;

  if (rebalance_cb.assign_call_cnt != 2)
    Test::Fail(tostr() << "Expected 2 assign calls, saw " << rebalance_cb.assign_call_cnt);
  if (rebalance_cb.revoke_call_cnt != 1)
    Test::Fail(tostr() << "Expected 1 revoke call, saw " << rebalance_cb.revoke_call_cnt);

  SUB_TEST_PASS();
}



/* Check behavior when:
 *   1. two consumers (with rebalance_cb's) subscribe to two topics.
 *   2. one of the consumers calls unsubscribe.
 *   3. consumers closed.
 */

static void l_unsubscribe () {
  SUB_TEST();

  std::string topic_name_1 = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  std::string topic_name_2 = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  std::string group_name = Test::mk_unique_group_name("0113-cooperative_rebalance");
  test_create_topic(NULL, topic_name_1.c_str(), 2, 1);
  test_create_topic(NULL, topic_name_2.c_str(), 2, 1);

  DefaultRebalanceCb rebalance_cb1;
  RdKafka::KafkaConsumer *c1 = make_consumer("C_1", group_name, "cooperative-sticky", NULL, &rebalance_cb1, 30);
  test_wait_topic_exists(c1->c_ptr(), topic_name_1.c_str(), 10*1000);
  test_wait_topic_exists(c1->c_ptr(), topic_name_2.c_str(), 10*1000);

  Test::subscribe(c1, topic_name_1, topic_name_2);

  DefaultRebalanceCb rebalance_cb2;
  RdKafka::KafkaConsumer *c2 = make_consumer("C_2", group_name, "cooperative-sticky", NULL, &rebalance_cb2, 30);
  Test::subscribe(c2, topic_name_1, topic_name_2);

  bool done = false;
  bool unsubscribed = false;
  while (!done) {
    Test::poll_once(c1, 500);
    Test::poll_once(c2, 500);

    if (Test::assignment_partition_count(c1, NULL) == 2 && Test::assignment_partition_count(c2, NULL) == 2) {
      if (rebalance_cb1.assign_call_cnt != 1)
        Test::Fail(tostr() << "Expecting consumer 1's assign_call_cnt to be 1 not: " << rebalance_cb1.assign_call_cnt);
      if (rebalance_cb2.assign_call_cnt != 1)
        Test::Fail(tostr() << "Expecting consumer 2's assign_call_cnt to be 1 not: " << rebalance_cb2.assign_call_cnt);
      Test::Say("Unsubscribing consumer 1 from both topics\n");
      c1->unsubscribe();
      unsubscribed = true;
    }

    if (unsubscribed && Test::assignment_partition_count(c1, NULL) == 0 && Test::assignment_partition_count(c2, NULL) == 4) {
      if (rebalance_cb1.assign_call_cnt != 1) /* is now unsubscribed, so rebalance_cb will no longer be called. */
        Test::Fail(tostr() << "Expecting consumer 1's assign_call_cnt to be 1 not: " << rebalance_cb1.assign_call_cnt);
      if (rebalance_cb2.assign_call_cnt != 2)
        Test::Fail(tostr() << "Expecting consumer 2's assign_call_cnt to be 2 not: " << rebalance_cb2.assign_call_cnt);
      if (rebalance_cb1.revoke_call_cnt != 1)
        Test::Fail(tostr() << "Expecting consumer 1's revoke_call_cnt to be 1 not: " << rebalance_cb1.revoke_call_cnt);
      if (rebalance_cb2.revoke_call_cnt != 0) /* the rebalance_cb should not be called if the revoked partition list is empty */
        Test::Fail(tostr() << "Expecting consumer 2's revoke_call_cnt to be 0 not: " << rebalance_cb2.revoke_call_cnt);
      Test::Say("Unsubscribe completed");
      done = true;
    }
  }

  Test::Say("Closing consumer 1\n");
  c1->close();
  Test::Say("Closing consumer 2\n");
  c2->close();

  /* there should be no assign rebalance_cb calls on close */
  if (rebalance_cb1.assign_call_cnt != 1)
    Test::Fail(tostr() << "Expecting consumer 1's assign_call_cnt to be 1 not: " << rebalance_cb1.assign_call_cnt);
  if (rebalance_cb2.assign_call_cnt != 2)
    Test::Fail(tostr() << "Expecting consumer 2's assign_call_cnt to be 2 not: " << rebalance_cb2.assign_call_cnt);

  if (rebalance_cb1.revoke_call_cnt != 1) /* should not be called a second revoke rebalance_cb */
    Test::Fail(tostr() << "Expecting consumer 1's revoke_call_cnt to be 1 not: " << rebalance_cb1.revoke_call_cnt);
  if (rebalance_cb2.revoke_call_cnt != 1)
    Test::Fail(tostr() << "Expecting consumer 2's revoke_call_cnt to be 1 not: " << rebalance_cb2.revoke_call_cnt);

  if (rebalance_cb1.lost_call_cnt != 0)
    Test::Fail(tostr() << "Expecting consumer 1's lost_call_cnt to be 0, not: " << rebalance_cb1.lost_call_cnt);
  if (rebalance_cb2.lost_call_cnt != 0)
    Test::Fail(tostr() << "Expecting consumer 2's lost_call_cnt to be 0, not: " << rebalance_cb2.lost_call_cnt);

  delete c1;
  delete c2;

  SUB_TEST_PASS();
}



/* Check behavior when:
 *   1. A consumers (with no rebalance_cb) subscribes to a topic.
 *   2. The consumer calls unsubscribe.
 *   3. Consumers closed.
 */

static void m_unsubscribe_2 () {
  SUB_TEST();

  std::string topic_name = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  std::string group_name = Test::mk_unique_group_name("0113-cooperative_rebalance");
  test_create_topic(NULL, topic_name.c_str(), 2, 1);

  RdKafka::KafkaConsumer *c = make_consumer("C_1", group_name, "cooperative-sticky", NULL, NULL, 15);
  test_wait_topic_exists(c->c_ptr(), topic_name.c_str(), 10*1000);

  Test::subscribe(c, topic_name);

  bool done = false;
  bool unsubscribed = false;
  while (!done) {
    Test::poll_once(c, 500);

    if (Test::assignment_partition_count(c, NULL) == 2) {
      Test::unsubscribe(c);
      unsubscribed = true;
    }

    if (unsubscribed && Test::assignment_partition_count(c, NULL) == 0) {
      Test::Say("Unsubscribe completed");
      done = true;
    }
  }

  Test::Say("Closing consumer\n");
  c->close();

  delete c;

  SUB_TEST_PASS();
}



/* Check behavior when:
 *   1. Two consumers (with rebalance_cb) subscribe to a regex (no matching topics exist)
 *   2. Create two topics.
 *   3. Remove one of the topics.
 *   3. Consumers closed.
 */

static void n_wildcard () {
  SUB_TEST();

  const string topic_base_name = Test::mk_topic_name("0113-n_wildcard", 1);
  const string topic_name_1 = topic_base_name + "_1";
  const string topic_name_2 = topic_base_name + "_2";
  const string topic_regex = "^" + topic_base_name + "_.";
  const string group_name = Test::mk_unique_group_name("0113-n_wildcard");

  std::vector<std::pair<std::string, std::string> > additional_conf;
  additional_conf.push_back(std::pair<std::string, std::string>(std::string("topic.metadata.refresh.interval.ms"), std::string("3000")));

  DefaultRebalanceCb rebalance_cb1;
  RdKafka::KafkaConsumer *c1 = make_consumer("C_1", group_name, "cooperative-sticky", &additional_conf, &rebalance_cb1, 30);
  Test::subscribe(c1, topic_regex);

  DefaultRebalanceCb rebalance_cb2;
  RdKafka::KafkaConsumer *c2 = make_consumer("C_2", group_name, "cooperative-sticky", &additional_conf, &rebalance_cb2, 30);
  Test::subscribe(c2, topic_regex);

  /* There are no matching topics, so the consumers should not join the group initially */
  Test::poll_once(c1, 500);
  Test::poll_once(c2, 500);

  if (rebalance_cb1.assign_call_cnt != 0)
    Test::Fail(tostr() << "Expecting consumer 1's assign_call_cnt to be 0 not: " << rebalance_cb1.assign_call_cnt);
  if (rebalance_cb2.assign_call_cnt != 0)
    Test::Fail(tostr() << "Expecting consumer 2's assign_call_cnt to be 0 not: " << rebalance_cb2.assign_call_cnt);

  bool done = false;
  bool created_topics = false;
  bool deleted_topic = false;
  int last_cb1_assign_call_cnt = 0;
  int last_cb2_assign_call_cnt = 0;
  while (!done) {
    Test::poll_once(c1, 500);
    Test::poll_once(c2, 500);

    if (Test::assignment_partition_count(c1, NULL) == 0 &&
        Test::assignment_partition_count(c2, NULL) == 0 && !created_topics) {
      Test::Say("Creating two topics with 2 partitions each that match regex\n");
      test_create_topic(NULL, topic_name_1.c_str(), 2, 1);
      test_create_topic(NULL, topic_name_2.c_str(), 2, 1);
      /* The consumers should autonomously discover these topics and start
       * consuming from them. This happens in the background - is not
       * influenced by whether we wait for the topics to be created before
       * continuing the main loop. It is possible that both topics are
       * discovered simultaneously, requiring a single rebalance OR that
       * topic 1 is discovered first (it was created first), a rebalance
       * initiated, then topic 2 discovered, then another rebalance
       * initiated to include it.
       */
      created_topics = true;
    }

    if (Test::assignment_partition_count(c1, NULL) == 2 &&
        Test::assignment_partition_count(c2, NULL) == 2 && !deleted_topic) {

      if (rebalance_cb1.nonempty_assign_call_cnt == 1) {
        /* just one rebalance was required */
        TEST_ASSERT(rebalance_cb1.nonempty_assign_call_cnt == 1,
                    "Expecting C_1's nonempty_assign_call_cnt to be 1 not %d ",
                    rebalance_cb1.nonempty_assign_call_cnt);
        TEST_ASSERT(rebalance_cb2.nonempty_assign_call_cnt == 1,
                    "Expecting C_2's nonempty_assign_call_cnt to be 1 not %d ",
                    rebalance_cb2.nonempty_assign_call_cnt);
      } else {
        /* two rebalances were required (occurs infrequently) */
        TEST_ASSERT(rebalance_cb1.nonempty_assign_call_cnt == 2,
                    "Expecting C_1's nonempty_assign_call_cnt to be 2 not %d ",
                    rebalance_cb1.nonempty_assign_call_cnt);
        TEST_ASSERT(rebalance_cb2.nonempty_assign_call_cnt == 2,
                    "Expecting C_2's nonempty_assign_call_cnt to be 2 not %d ",
                    rebalance_cb2.nonempty_assign_call_cnt);
      }

      TEST_ASSERT(rebalance_cb1.revoke_call_cnt == 0,
                  "Expecting C_1's revoke_call_cnt to be 0 not %d ",
                  rebalance_cb1.revoke_call_cnt);
      TEST_ASSERT(rebalance_cb2.revoke_call_cnt == 0,
                  "Expecting C_2's revoke_call_cnt to be 0 not %d ",
                  rebalance_cb2.revoke_call_cnt);

      last_cb1_assign_call_cnt = rebalance_cb1.assign_call_cnt;
      last_cb2_assign_call_cnt = rebalance_cb2.assign_call_cnt;

      Test::Say("Deleting topic 1\n");
      Test::delete_topic(c1, topic_name_1.c_str());
      deleted_topic = true;
    }

    if (Test::assignment_partition_count(c1, NULL) == 1 &&
        Test::assignment_partition_count(c2, NULL) == 1 && deleted_topic) {
      /* accumulated in lost case as well */
      TEST_ASSERT(rebalance_cb1.revoke_call_cnt == 1,
                  "Expecting C_1's revoke_call_cnt to be 1 not %d",
                  rebalance_cb1.revoke_call_cnt);
      TEST_ASSERT(rebalance_cb2.revoke_call_cnt == 1,
                  "Expecting C_2's revoke_call_cnt to be 1 not %d",
                  rebalance_cb2.revoke_call_cnt);
      TEST_ASSERT(rebalance_cb1.lost_call_cnt == 1,
                  "Expecting C_1's lost_call_cnt to be 1 not %d",
                  rebalance_cb1.lost_call_cnt);
      TEST_ASSERT(rebalance_cb2.lost_call_cnt == 1,
                  "Expecting C_2's lost_call_cnt to be 1 not %d",
                  rebalance_cb2.lost_call_cnt);

      /* Consumers will rejoin group after revoking the lost partitions.
       * this will result in an rebalance_cb assign (empty partitions).
       * it follows the revoke, which has already been confirmed to have
       * happened. */
      Test::Say("Waiting for rebalance_cb assigns\n");
      while (rebalance_cb1.assign_call_cnt == last_cb1_assign_call_cnt ||
             rebalance_cb2.assign_call_cnt == last_cb2_assign_call_cnt) {
        Test::poll_once(c1, 500);
        Test::poll_once(c2, 500);
      }

      Test::Say("Consumers are subscribed to one partition each\n");
      done = true;
    }
  }

  Test::Say("Closing consumer 1\n");
  last_cb1_assign_call_cnt = rebalance_cb1.assign_call_cnt;
  c1->close();

  /* There should be no assign rebalance_cb calls on close */
  TEST_ASSERT(rebalance_cb1.assign_call_cnt == last_cb1_assign_call_cnt,
              "Expecting C_1's assign_call_cnt to be %d not %d",
              last_cb1_assign_call_cnt, rebalance_cb1.assign_call_cnt);

  /* Let C_2 catch up on the rebalance and get assigned C_1's partitions. */
  last_cb2_assign_call_cnt = rebalance_cb2.nonempty_assign_call_cnt;
  while (rebalance_cb2.nonempty_assign_call_cnt == last_cb2_assign_call_cnt)
    Test::poll_once(c2, 500);

  Test::Say("Closing consumer 2\n");
  last_cb2_assign_call_cnt = rebalance_cb2.assign_call_cnt;
  c2->close();

  /* There should be no assign rebalance_cb calls on close */
  TEST_ASSERT(rebalance_cb2.assign_call_cnt == last_cb2_assign_call_cnt,
              "Expecting C_2's assign_call_cnt to be %d not %d",
              last_cb2_assign_call_cnt, rebalance_cb2.assign_call_cnt);

  TEST_ASSERT(rebalance_cb1.revoke_call_cnt == 2,
              "Expecting C_1's revoke_call_cnt to be 2 not %d",
              rebalance_cb1.revoke_call_cnt);
  TEST_ASSERT(rebalance_cb2.revoke_call_cnt == 2,
              "Expecting C_2's revoke_call_cnt to be 2 not %d",
              rebalance_cb2.revoke_call_cnt);

  TEST_ASSERT(rebalance_cb1.lost_call_cnt == 1,
              "Expecting C_1's lost_call_cnt to be 1, not %d",
              rebalance_cb1.lost_call_cnt);
  TEST_ASSERT(rebalance_cb2.lost_call_cnt == 1,
              "Expecting C_2's lost_call_cnt to be 1, not %d",
              rebalance_cb2.lost_call_cnt);

  delete c1;
  delete c2;

  SUB_TEST_PASS();
}



/* Check behavior when:
 *   1. Consumer (librdkafka) subscribes to two topics (2 and 6 partitions).
 *   2. Consumer (java) subscribes to the same two topics.
 *   3. Consumer (librdkafka) unsubscribes from the two partition topic.
 *   4. Consumer (java) process closes upon detecting the above unsubscribe.
 *   5. Consumer (librdkafka) will now be subscribed to 6 partitions.
 *   6. Close librdkafka consumer.
 */

static void o_java_interop() {
  SUB_TEST();

  std::string topic_name_1 = Test::mk_topic_name("0113_o_2", 1);
  std::string topic_name_2 = Test::mk_topic_name("0113_o_6", 1);
  std::string group_name = Test::mk_unique_group_name("0113_o");
  test_create_topic(NULL, topic_name_1.c_str(), 2, 1);
  test_create_topic(NULL, topic_name_2.c_str(), 6, 1);

  DefaultRebalanceCb rebalance_cb;
  RdKafka::KafkaConsumer *c = make_consumer("C_1", group_name, "cooperative-sticky", NULL, &rebalance_cb, 25);
  test_wait_topic_exists(c->c_ptr(), topic_name_1.c_str(), 10*1000);
  test_wait_topic_exists(c->c_ptr(), topic_name_2.c_str(), 10*1000);

  Test::subscribe(c, topic_name_1, topic_name_2);

  bool done = false;
  bool changed_subscription = false;
  bool changed_subscription_done = false;
  int java_pid = 0;
  while (!done) {
    Test::poll_once(c, 500);

    if (1) // FIXME: Remove after debugging
      Test::Say(tostr() << "Assignment partition count: " <<
                Test::assignment_partition_count(c, NULL) <<
                ", changed_sub " << changed_subscription <<
                ", changed_sub_done " << changed_subscription_done <<
                ", assign_call_cnt " << rebalance_cb.assign_call_cnt <<
                "\n");
    if (Test::assignment_partition_count(c, NULL) == 8 && !java_pid) {
      Test::Say(_C_GRN "librdkafka consumer assigned to 8 partitions\n");
      string bootstrapServers = get_bootstrap_servers();
      const char *argv[1 + 1 + 1 + 1 + 1 + 1];
      size_t i = 0;
      argv[i++] = "test1";
      argv[i++] = bootstrapServers.c_str();
      argv[i++] = topic_name_1.c_str();
      argv[i++] = topic_name_2.c_str();
      argv[i++] = group_name.c_str();
      argv[i] = NULL;
      java_pid = test_run_java("IncrementalRebalanceCli", argv);
      if (java_pid <= 0)
        Test::Fail(tostr() << "Unexpected pid: " << java_pid);
    }

    if (Test::assignment_partition_count(c, NULL) == 4 &&
        java_pid != 0 &&
        !changed_subscription &&
        rebalance_cb.assign_call_cnt == 3) {
      Test::Say(_C_GRN "Java consumer is now part of the group\n");
      Test::subscribe(c, topic_name_1);
      changed_subscription = true;
    }

    if (Test::assignment_partition_count(c, NULL) == 1 &&
        changed_subscription && rebalance_cb.assign_call_cnt == 4 &&
        changed_subscription && !changed_subscription_done) {
      /* All topic 1 partitions will be allocated to this consumer whether or not the Java
       * consumer has unsubscribed yet because the sticky algorithm attempts to ensure
       * partition counts are even. */
      Test::Say(_C_GRN "Consumer 1 has unsubscribed from topic 2\n");
      changed_subscription_done = true;
    }

    if (Test::assignment_partition_count(c, NULL) == 2 &&
        changed_subscription && rebalance_cb.assign_call_cnt == 5 &&
        changed_subscription_done) {
      /* When the java consumer closes, this will cause an empty assign rebalance_cb event,
       * allowing detection of when this has happened. */
      Test::Say(_C_GRN "Java consumer has left the group\n");
      done = true;
    }
  }

  Test::Say("Closing consumer\n");
  c->close();

  /* Expected behavior is IncrementalRebalanceCli will exit cleanly, timeout otherwise. */
  test_waitpid(java_pid);

  delete c;

  SUB_TEST_PASS();
}



/* Check behavior when:
 *  - Single consumer subscribes to topic.
 *  - Soon after (timing such that rebalance is probably in progress) it subscribes to a different topic.
 */

static void s_subscribe_when_rebalancing (int variation) {
  SUB_TEST("variation %d", variation);

  std::string topic_name_1 = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  std::string topic_name_2 = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  std::string topic_name_3 = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  std::string group_name = Test::mk_unique_group_name("0113-cooperative_rebalance");
  test_create_topic(NULL, topic_name_1.c_str(), 1, 1);
  test_create_topic(NULL, topic_name_2.c_str(), 1, 1);
  test_create_topic(NULL, topic_name_3.c_str(), 1, 1);

  DefaultRebalanceCb rebalance_cb;
  RdKafka::KafkaConsumer *c = make_consumer("C_1", group_name, "cooperative-sticky", NULL, &rebalance_cb, 25);
  test_wait_topic_exists(c->c_ptr(), topic_name_1.c_str(), 10*1000);
  test_wait_topic_exists(c->c_ptr(), topic_name_2.c_str(), 10*1000);
  test_wait_topic_exists(c->c_ptr(), topic_name_3.c_str(), 10*1000);

  if (variation == 2 || variation == 4 || variation == 6) {
    /* Pre-cache metadata for all topics. */
    class RdKafka::Metadata *metadata;
    c->metadata(true, NULL, &metadata, 5000);
    delete metadata;
  }

  Test::subscribe(c, topic_name_1);
  Test::wait_for_assignment(c, 1, &topic_name_1);

  Test::subscribe(c, topic_name_2);

  if (variation == 3 || variation == 5)
    Test::poll_once(c, 500);

  if (variation < 5) {
    // Very quickly after subscribing to topic 2, subscribe to topic 3.
    Test::subscribe(c, topic_name_3);
    Test::wait_for_assignment(c, 1, &topic_name_3);
  } else {
    // ..or unsubscribe.
    Test::unsubscribe(c);
    Test::wait_for_assignment(c, 0, NULL);
  }

  delete c;

  SUB_TEST_PASS();
}



/* Check behavior when:
 *  - Two consumer subscribe to a topic.
 *  - Max poll interval is exceeded on the first consumer.
 */

static void t_max_poll_interval_exceeded(int variation) {
  SUB_TEST("variation %d", variation);

  std::string topic_name_1 = Test::mk_topic_name("0113-cooperative_rebalance", 1);
  std::string group_name = Test::mk_unique_group_name("0113-cooperative_rebalance");
  test_create_topic(NULL, topic_name_1.c_str(), 2, 1);

  std::vector<std::pair<std::string, std::string> > additional_conf;
  additional_conf.push_back(std::pair<std::string, std::string>(std::string("session.timeout.ms"), std::string("6000")));
  additional_conf.push_back(std::pair<std::string, std::string>(std::string("max.poll.interval.ms"), std::string("7000")));

  DefaultRebalanceCb rebalance_cb1;
  RdKafka::KafkaConsumer *c1 = make_consumer("C_1", group_name, "cooperative-sticky", &additional_conf, &rebalance_cb1, 30);
  DefaultRebalanceCb rebalance_cb2;
  RdKafka::KafkaConsumer *c2 = make_consumer("C_2", group_name, "cooperative-sticky", &additional_conf, &rebalance_cb2, 30);

  test_wait_topic_exists(c1->c_ptr(), topic_name_1.c_str(), 10*1000);
  test_wait_topic_exists(c2->c_ptr(), topic_name_1.c_str(), 10*1000);

  Test::subscribe(c1, topic_name_1);
  Test::subscribe(c2, topic_name_1);

  bool done = false;
  bool both_have_been_assigned = false;
  while (!done) {
    if (!both_have_been_assigned)
      Test::poll_once(c1, 500);
    Test::poll_once(c2, 500);

    if (Test::assignment_partition_count(c1, NULL) == 1 && Test::assignment_partition_count(c2, NULL) == 1 && !both_have_been_assigned) {
      Test::Say(tostr() << "Both consumers are assigned to topic " << topic_name_1 << ". WAITING 7 seconds for max.poll.interval.ms to be exceeded\n");
      both_have_been_assigned = true;
    }

    if (Test::assignment_partition_count(c2, NULL) == 2 && both_have_been_assigned) {
      Test::Say("Consumer 1 is no longer assigned any partitions, done\n");
      done = true;
    }
  }

  if (variation == 1) {
    if (rebalance_cb1.lost_call_cnt != 0)
      Test::Fail(tostr() << "Expected consumer 1 lost revoke count to be 0, not: " << rebalance_cb1.lost_call_cnt);
    Test::poll_once(c1, 500); /* Eat the max poll interval exceeded error message */
    Test::poll_once(c1, 500); /* Trigger the rebalance_cb with lost partitions */
    if (rebalance_cb1.lost_call_cnt != 1)
      Test::Fail(tostr() << "Expected consumer 1 lost revoke count to be 1, not: " << rebalance_cb1.lost_call_cnt);
  }

  c1->close();
  c2->close();

  if (rebalance_cb1.lost_call_cnt != 1)
    Test::Fail(tostr() << "Expected consumer 1 lost revoke count to be 1, not: " << rebalance_cb1.lost_call_cnt);

  if (rebalance_cb1.assign_call_cnt != 1)
    Test::Fail(tostr() << "Expected consumer 1 assign count to be 1, not: " << rebalance_cb1.assign_call_cnt);
  if (rebalance_cb2.assign_call_cnt != 2)
    Test::Fail(tostr() << "Expected consumer 1 assign count to be 2, not: " << rebalance_cb1.assign_call_cnt);

  if (rebalance_cb1.revoke_call_cnt != 1)
    Test::Fail(tostr() << "Expected consumer 1 revoke count to be 1, not: " << rebalance_cb1.revoke_call_cnt);
  if (rebalance_cb2.revoke_call_cnt != 1)
    Test::Fail(tostr() << "Expected consumer 2 revoke count to be 1, not: " << rebalance_cb1.revoke_call_cnt);

  delete c1;
  delete c2;

  SUB_TEST_PASS();
}


/**
 * @brief Poll all consumers until there are no more events or messages
 *        and the timeout has expired.
 */
static void poll_all_consumers (RdKafka::KafkaConsumer **consumers,
                                DefaultRebalanceCb *rebalance_cbs,
                                size_t num, int timeout_ms) {
  int64_t ts_end = test_clock() + (timeout_ms * 1000);

  /* Poll all consumers until no more events are seen,
   * this makes sure we exhaust the current state events before returning. */
  bool evented;
  do {
    evented = false;
    for (size_t i = 0 ; i < num ; i++) {
      int block_ms =
        min(10, (int)((ts_end - test_clock()) / 1000));
      while (rebalance_cbs[i].poll_once(consumers[i], max(block_ms, 0)))
        evented = true;
    }
  } while (evented || test_clock() < ts_end);
}


/**
 * @brief Stress test with 8 consumers subscribing, fetching and committing.
 *
 * @param subscription_variation 0..2
 *
 * TODO: incorporate committing offsets.
 */

static void u_multiple_subscription_changes (bool use_rebalance_cb, int subscription_variation) {
  const int N_CONSUMERS = 8;
  const int N_TOPICS = 2;
  const int N_PARTS_PER_TOPIC = N_CONSUMERS * N_TOPICS;
  const int N_PARTITIONS = N_PARTS_PER_TOPIC * N_TOPICS;
  const int N_MSGS_PER_PARTITION = 1000;

  SUB_TEST("use_rebalance_cb: %d, subscription_variation: %d",
           (int)use_rebalance_cb, subscription_variation);

  string topic_name_1 = Test::mk_topic_name("0113u_1", 1);
  string topic_name_2 = Test::mk_topic_name("0113u_2", 1);
  string group_name = Test::mk_unique_group_name("0113u");

  test_create_topic(NULL, topic_name_1.c_str(), N_PARTS_PER_TOPIC, 1);
  test_create_topic(NULL, topic_name_2.c_str(), N_PARTS_PER_TOPIC, 1);

  Test::Say("Creating consumers\n");
  DefaultRebalanceCb rebalance_cbs[N_CONSUMERS];
  RdKafka::KafkaConsumer *consumers[N_CONSUMERS];

  for (int i = 0 ; i < N_CONSUMERS ; i++) {
    std::string name = tostr() << "C_" << i;
    consumers[i] = make_consumer(name.c_str(), group_name, "cooperative-sticky",
                                 NULL,
                                 use_rebalance_cb ? &rebalance_cbs[i] : NULL,
                                 120);
  }

  test_wait_topic_exists(consumers[0]->c_ptr(), topic_name_1.c_str(), 10*1000);
  test_wait_topic_exists(consumers[0]->c_ptr(), topic_name_2.c_str(), 10*1000);


  /*
   * Seed all partitions with the same number of messages so we later can
   * verify that consumption is working.
   */
  vector<pair<Toppar,int> >ptopics;
  ptopics.push_back(pair<Toppar,int>(Toppar(topic_name_1, N_PARTS_PER_TOPIC),
                                     N_MSGS_PER_PARTITION));
  ptopics.push_back(pair<Toppar,int>(Toppar(topic_name_2, N_PARTS_PER_TOPIC),
                                     N_MSGS_PER_PARTITION));
  produce_msgs(ptopics);


  /*
   * Track what topics a consumer should be subscribed to and use this to
   * verify both its subscription and assignment throughout the test.
   */

  /* consumer -> currently subscribed topics */
  map<int, vector<string> > consumer_topics;

  /* topic -> consumers subscribed to topic */
  map<string, set<int> > topic_consumers;

  /* The subscription alternatives that consumers
   * alter between in the playbook. */
  vector<string> SUBSCRIPTION_1;
  vector<string> SUBSCRIPTION_2;

  SUBSCRIPTION_1.push_back(topic_name_1);

  switch (subscription_variation) {
  case 0:
    SUBSCRIPTION_2.push_back(topic_name_1);
    SUBSCRIPTION_2.push_back(topic_name_2);
    break;

  case 1:
    SUBSCRIPTION_2.push_back(topic_name_2);
    break;

  case 2:
    /* No subscription */
    break;
  }

  sort(SUBSCRIPTION_1.begin(), SUBSCRIPTION_1.end());
  sort(SUBSCRIPTION_2.begin(), SUBSCRIPTION_2.end());


  /*
   * Define playbook
   */
  const struct {
    int timestamp_ms;
    int consumer;
    const vector<string> *topics;
  } playbook[] = {
                  /* timestamp_ms, consumer_number, subscribe-to-topics */
                  { 0,     0, &SUBSCRIPTION_1 },  /* Cmd 0 */
                  { 4000,  1, &SUBSCRIPTION_1 },
                  { 4000,  1, &SUBSCRIPTION_1 },
                  { 4000,  1, &SUBSCRIPTION_1 },
                  { 4000,  2, &SUBSCRIPTION_1 },
                  { 6000,  3, &SUBSCRIPTION_1 },  /* Cmd 5 */
                  { 6000,  4, &SUBSCRIPTION_1 },
                  { 6000,  5, &SUBSCRIPTION_1 },
                  { 6000,  6, &SUBSCRIPTION_1 },
                  { 6000,  7, &SUBSCRIPTION_2 },
                  { 6000,  1, &SUBSCRIPTION_1 },  /* Cmd 10 */
                  { 6000,  1, &SUBSCRIPTION_2 },
                  { 6000,  1, &SUBSCRIPTION_1 },
                  { 6000,  2, &SUBSCRIPTION_2 },
                  { 7000,  2, &SUBSCRIPTION_1 },
                  { 7000,  1, &SUBSCRIPTION_2 },  /* Cmd 15 */
                  { 8000,  0, &SUBSCRIPTION_2 },
                  { 8000,  1, &SUBSCRIPTION_1 },
                  { 8000,  0, &SUBSCRIPTION_1 },
                  { 13000, 2, &SUBSCRIPTION_1 },
                  { 13000, 1, &SUBSCRIPTION_2 },  /* Cmd 20 */
                  { 13000, 5, &SUBSCRIPTION_2 },
                  { 14000, 6, &SUBSCRIPTION_2 },
                  { 15000, 7, &SUBSCRIPTION_1 },
                  { 15000, 1, &SUBSCRIPTION_1 },
                  { 15000, 5, &SUBSCRIPTION_1 },  /* Cmd 25 */
                  { 15000, 6, &SUBSCRIPTION_1 },
                  { INT_MAX, 0, 0 }
  };

  /*
   * Run the playbook
   */
  int cmd_number = 0;
  uint64_t ts_start = test_clock();

  while (playbook[cmd_number].timestamp_ms != INT_MAX) {

    TEST_ASSERT(playbook[cmd_number].consumer < N_CONSUMERS);

    Test::Say(tostr() << "Cmd #" << cmd_number << ": wait " <<
              playbook[cmd_number].timestamp_ms << "ms\n");

    poll_all_consumers(consumers, rebalance_cbs, N_CONSUMERS,
                       playbook[cmd_number].timestamp_ms -
                       (int)((test_clock() - ts_start) / 1000));

    /* Verify consumer assignments match subscribed topics */
    map<Toppar, RdKafka::KafkaConsumer*> all_assignments;
    for (int i = 0 ; i < N_CONSUMERS ; i++)
      verify_consumer_assignment(consumers[i],
                                 rebalance_cbs[i],
                                 consumer_topics[i],
                                 /* Allow empty assignment */
                                 true,
                                 /* Allow mismatch between subscribed topics
                                  * and actual assignment since we can't
                                  * synchronize the last subscription
                                  * to the current assignment due to
                                  * an unknown number of rebalances required
                                  * for the final assignment to settle.
                                  * This is instead checked at the end of
                                  * this test case. */
                                 true,
                                 &all_assignments,
                                 -1/* no msgcnt check*/);

    int cid = playbook[cmd_number].consumer;
    RdKafka::KafkaConsumer *consumer = consumers[playbook[cmd_number].consumer];
    const vector<string> *topics = playbook[cmd_number].topics;

    /*
     * Update our view of the consumer's subscribed topics and vice versa.
     */
    for (vector<string>::const_iterator it = consumer_topics[cid].begin();
         it != consumer_topics[cid].end(); it++) {
      topic_consumers[*it].erase(cid);
    }

    consumer_topics[cid].clear();

    for (vector<string>::const_iterator it = topics->begin();
         it != topics->end(); it++) {
      consumer_topics[cid].push_back(*it);
      topic_consumers[*it].insert(cid);
    }

    RdKafka::ErrorCode err;

    /*
     * Change subscription
     */
    if (!topics->empty()) {
      Test::Say(tostr() << "Consumer: " << consumer->name() <<
                " is subscribing to topics " << string_vec_to_str(*topics) <<
                " after " << ((test_clock() - ts_start) / 1000) << "ms\n");
      err = consumer->subscribe(*topics);
      TEST_ASSERT(!err, "Expected subscribe() to succeed, got %s",
                  RdKafka::err2str(err).c_str());
    } else {
      Test::Say(tostr() << "Consumer: " << consumer->name() <<
                " is unsubscribing after " <<
                ((test_clock() - ts_start) / 1000) << "ms\n");
      Test::unsubscribe(consumer);
    }

    /* Mark this consumer as waiting for rebalance so that
     * verify_consumer_assignment() allows assigned partitions that
     * (no longer) match the subscription. */
    rebalance_cbs[cid].wait_rebalance = true;


    /*
     * Verify subscription matches what we think it should be.
     */
    vector<string> subscription;
    err = consumer->subscription(subscription);
    TEST_ASSERT(!err, "consumer %s subscription() failed: %s",
                consumer->name().c_str(), RdKafka::err2str(err).c_str());

    sort(subscription.begin(), subscription.end());

    Test::Say(tostr() << "Consumer " << consumer->name() <<
              " subscription is now " << string_vec_to_str(subscription)
              << "\n");

    if (subscription != *topics)
      Test::Fail(tostr() << "Expected consumer " << consumer->name() <<
                 " subscription: " << string_vec_to_str(*topics) <<
                 " but got: " << string_vec_to_str(subscription));

    cmd_number++;
  }


  /*
   * Wait for final rebalances and all consumers to settle,
   * then verify assignments and received message counts.
   */
  Test::Say(_C_YEL "Waiting for final assignment state\n");
  int done_count = 0;
  /* Allow at least 20 seconds for group to stabilize. */
  int64_t stabilize_until = test_clock() + (20 * 1000*1000); /* 20s */

  while (done_count < 2) {
    bool stabilized = test_clock() > stabilize_until;

    poll_all_consumers(consumers, rebalance_cbs, N_CONSUMERS, 5000);

    /* Verify consumer assignments */
    int counts[N_CONSUMERS];
    map<Toppar, RdKafka::KafkaConsumer*> all_assignments;
    Test::Say(tostr() << "Consumer assignments " <<
              "(subscription_variation " << subscription_variation << ")" <<
              (stabilized ? " (stabilized)" : "") <<
              (use_rebalance_cb ?
               " (use_rebalance_cb)" : " (no rebalance cb)") <<
              ":\n");
    for (int i = 0 ; i < N_CONSUMERS ; i++) {
      bool last_rebalance_stabilized =
        stabilized &&
        (!use_rebalance_cb ||
         /* session.timeout.ms * 2 + 1 */
         test_clock() > rebalance_cbs[i].ts_last_assign + (13 * 1000*1000));

      counts[i] = verify_consumer_assignment(consumers[i],
                                             rebalance_cbs[i],
                                             consumer_topics[i],
                                             /* allow empty */
                                             true,
                                             /* if we're waiting for a
                                              * rebalance it is okay for the
                                              * current assignment to contain
                                              * topics that this consumer
                                              * (no longer) subscribes to. */
                                             !last_rebalance_stabilized ||
                                             !use_rebalance_cb ||
                                             rebalance_cbs[i].wait_rebalance,
                                             /* do not allow assignments for
                                              * topics that are not subscribed*/
                                             &all_assignments,
                                             /* Verify received message counts
                                              * once the assignments have
                                              * stabilized.
                                              * Requires the rebalance cb.*/
                                             done_count > 0 &&
                                             use_rebalance_cb ?
                                             N_MSGS_PER_PARTITION : -1);
    }

    Test::Say(tostr() << all_assignments.size() << "/" << N_PARTITIONS <<
              " partitions assigned\n");

    bool done = true;
    for (int i = 0 ; i < N_CONSUMERS ; i++) {
      /* For each topic the consumer subscribes to it should
       * be assigned its share of partitions. */
      int exp_parts = 0;
      for (vector<string>::const_iterator it = consumer_topics[i].begin();
           it != consumer_topics[i].end(); it++)
        exp_parts += N_PARTS_PER_TOPIC / (int)topic_consumers[*it].size();

      Test::Say(tostr() <<
                (counts[i] == exp_parts ? "" : _C_YEL) <<
                "Consumer " << consumers[i]->name() << " has " <<
                counts[i] << " assigned partitions (" <<
                consumer_topics[i].size() << " subscribed topic(s))" <<
                ", expecting " << exp_parts << " assigned partitions\n");

      if (counts[i] != exp_parts)
        done = false;
    }

    if (done && stabilized) {
      done_count++;
      Test::Say(tostr() << "All assignments verified, done count is " <<
                done_count << "\n");
    }
  }

  Test::Say("Disposing consumers\n");
  for (int i = 0 ; i < N_CONSUMERS ; i++) {
    TEST_ASSERT(!use_rebalance_cb ||
                !rebalance_cbs[i].wait_rebalance,
                "Consumer %d still waiting for rebalance", i);
    if (i & 1)
      consumers[i]->close();
    delete consumers[i];
  }

  SUB_TEST_PASS();
}



extern "C" {

  static int rebalance_cnt;
  static rd_kafka_resp_err_t rebalance_exp_event;
  static rd_bool_t rebalance_exp_lost;

  extern void test_print_partition_list (const rd_kafka_topic_partition_list_t
                                         *partitions);


  static void rebalance_cb (rd_kafka_t *rk,
                            rd_kafka_resp_err_t err,
                            rd_kafka_topic_partition_list_t *parts,
                            void *opaque) {
    rebalance_cnt++;
    TEST_SAY("Rebalance #%d: %s: %d partition(s)\n",
             rebalance_cnt, rd_kafka_err2name(err), parts->cnt);

    test_print_partition_list(parts);

    TEST_ASSERT(err == rebalance_exp_event ||
                rebalance_exp_event == RD_KAFKA_RESP_ERR_NO_ERROR,
                "Expected rebalance event %s, not %s",
                rd_kafka_err2name(rebalance_exp_event),
                rd_kafka_err2name(err));

    if (rebalance_exp_lost) {
      TEST_ASSERT(rd_kafka_assignment_lost(rk),
                  "Expected partitions lost");
      TEST_SAY("Partitions were lost\n");
    }

    if (err == RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS) {
      test_consumer_incremental_assign("assign", rk, parts);
    } else {
      test_consumer_incremental_unassign("unassign", rk, parts);
    }
  }

  /**
   * @brief Wait for an expected rebalance event, or fail.
   */
  static void expect_rebalance0 (const char *func, int line,
                                 const char *what, rd_kafka_t *c,
                                 rd_kafka_resp_err_t exp_event,
                                 rd_bool_t exp_lost,
                                 int timeout_s) {
    int64_t tmout = test_clock() + (timeout_s * 1000000);
    int start_cnt = rebalance_cnt;

    TEST_SAY("%s:%d: Waiting for %s (%s) for %ds\n",
             func, line, what, rd_kafka_err2name(exp_event), timeout_s);

    rebalance_exp_lost = exp_lost;
    rebalance_exp_event = exp_event;

    while (tmout > test_clock() && rebalance_cnt == start_cnt) {
      test_consumer_poll_once(c, NULL, 1000);
    }

    if (rebalance_cnt == start_cnt + 1) {
      rebalance_exp_event = RD_KAFKA_RESP_ERR_NO_ERROR;
      rebalance_exp_lost = exp_lost = rd_false;
      return;
    }

    TEST_FAIL("%s:%d: Timed out waiting for %s (%s)",
              func, line, what, rd_kafka_err2name(exp_event));
  }

#define expect_rebalance(WHAT,C,EXP_EVENT,EXP_LOST,TIMEOUT_S)    \
  expect_rebalance0(__FUNCTION__, __LINE__,                      \
                    WHAT, C, EXP_EVENT, EXP_LOST, TIMEOUT_S)


  /* Check lost partitions revoke occurs on ILLEGAL_GENERATION heartbeat error.
   */

  static void p_lost_partitions_heartbeat_illegal_generation_test () {
    const char *bootstraps;
    rd_kafka_mock_cluster_t *mcluster;
    const char *groupid = "mygroup";
    const char *topic = "test";
    rd_kafka_t *c;
    rd_kafka_conf_t *conf;

    SUB_TEST_QUICK();

    mcluster = test_mock_cluster_new(3, &bootstraps);

    rd_kafka_mock_coordinator_set(mcluster, "group", groupid, 1);

    /* Seed the topic with messages */
    test_produce_msgs_easy_v(topic, 0, 0, 0, 100, 10,
                             "bootstrap.servers", bootstraps,
                             "batch.num.messages", "10",
                             NULL);

    test_conf_init(&conf, NULL, 30);
    test_conf_set(conf, "bootstrap.servers", bootstraps);
    test_conf_set(conf, "security.protocol", "PLAINTEXT");
    test_conf_set(conf, "group.id", groupid);
    test_conf_set(conf, "session.timeout.ms", "5000");
    test_conf_set(conf, "heartbeat.interval.ms", "1000");
    test_conf_set(conf, "auto.offset.reset", "earliest");
    test_conf_set(conf, "enable.auto.commit", "false");
    test_conf_set(conf, "partition.assignment.strategy", "cooperative-sticky");

    c = test_create_consumer(groupid, rebalance_cb, conf, NULL);

    test_consumer_subscribe(c, topic);

    expect_rebalance("initial assignment", c,
                     RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS,
                     rd_false/*don't expect lost*/, 5+2);

    /* Fail heartbeats */
    rd_kafka_mock_push_request_errors(
      mcluster, RD_KAFKAP_Heartbeat,
      5,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION);

    expect_rebalance("lost partitions", c,
                     RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS,
                     rd_true/*expect lost*/, 10+2);

    rd_kafka_mock_clear_request_errors(
      mcluster, RD_KAFKAP_Heartbeat);

    expect_rebalance("rejoin after lost", c,
                     RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS,
                     rd_false/*don't expect lost*/, 10+2);

    TEST_SAY("Closing consumer\n");
    test_consumer_close(c);

    TEST_SAY("Destroying consumer\n");
    rd_kafka_destroy(c);

    TEST_SAY("Destroying mock cluster\n");
    test_mock_cluster_destroy(mcluster);

    SUB_TEST_PASS();
  }



  /* Check lost partitions revoke occurs on ILLEGAL_GENERATION JoinGroup
   * or SyncGroup error.
   */

  static void q_lost_partitions_illegal_generation_test (
      rd_bool_t test_joingroup_fail) {

    const char *bootstraps;
    rd_kafka_mock_cluster_t *mcluster;
    const char *groupid = "mygroup";
    const char *topic1 = "test1";
    const char *topic2 = "test2";
    rd_kafka_t *c;
    rd_kafka_conf_t *conf;
    rd_kafka_resp_err_t err;
    rd_kafka_topic_partition_list_t *topics;

    SUB_TEST0(!test_joingroup_fail/*quick*/,
              "test_joingroup_fail=%d", test_joingroup_fail);

    mcluster = test_mock_cluster_new(3, &bootstraps);

    rd_kafka_mock_coordinator_set(mcluster, "group", groupid, 1);

    /* Seed the topic1 with messages */
    test_produce_msgs_easy_v(topic1, 0, 0, 0, 100, 10,
                             "bootstrap.servers", bootstraps,
                             "batch.num.messages", "10",
                             NULL);

    /* Seed the topic2 with messages */
    test_produce_msgs_easy_v(topic2, 0, 0, 0, 100, 10,
                             "bootstrap.servers", bootstraps,
                             "batch.num.messages", "10",
                             NULL);

    test_conf_init(&conf, NULL, 30);
    test_conf_set(conf, "bootstrap.servers", bootstraps);
    test_conf_set(conf, "security.protocol", "PLAINTEXT");
    test_conf_set(conf, "group.id", groupid);
    test_conf_set(conf, "session.timeout.ms", "5000");
    test_conf_set(conf, "heartbeat.interval.ms", "1000");
    test_conf_set(conf, "auto.offset.reset", "earliest");
    test_conf_set(conf, "enable.auto.commit", "false");
    test_conf_set(conf, "partition.assignment.strategy", "cooperative-sticky");

    c = test_create_consumer(groupid, rebalance_cb, conf, NULL);

    test_consumer_subscribe(c, topic1);

    expect_rebalance("initial assignment", c,
                     RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS,
                     rd_false/*don't expect lost*/, 5+2);

    /* Fail JoinGroups or SyncGroups */
    rd_kafka_mock_push_request_errors(
      mcluster,
      test_joingroup_fail ? RD_KAFKAP_JoinGroup : RD_KAFKAP_SyncGroup,
      5,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION);

          topics = rd_kafka_topic_partition_list_new(2);
    rd_kafka_topic_partition_list_add(topics, topic1,
                                          RD_KAFKA_PARTITION_UA);
    rd_kafka_topic_partition_list_add(topics, topic2,
                                          RD_KAFKA_PARTITION_UA);
    err = rd_kafka_subscribe(c, topics);
    if (err)
            TEST_FAIL("%s: Failed to subscribe to topics: %s\n",
                      rd_kafka_name(c), rd_kafka_err2str(err));
    rd_kafka_topic_partition_list_destroy(topics);

    expect_rebalance("lost partitions", c,
                     RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS,
                     rd_true/*expect lost*/, 10+2);

    rd_kafka_mock_clear_request_errors(
      mcluster,
      test_joingroup_fail ? RD_KAFKAP_JoinGroup : RD_KAFKAP_SyncGroup);

    expect_rebalance("rejoin group", c,
                     RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS,
                     rd_false/*expect lost*/, 10+2);

    TEST_SAY("Closing consumer\n");
    test_consumer_close(c);

    TEST_SAY("Destroying consumer\n");
    rd_kafka_destroy(c);

    TEST_SAY("Destroying mock cluster\n");
    test_mock_cluster_destroy(mcluster);

    SUB_TEST_PASS();
  }



  /* Check lost partitions revoke occurs on ILLEGAL_GENERATION Commit
   * error.
   */

  static void r_lost_partitions_commit_illegal_generation_test_local () {
    const char *bootstraps;
    rd_kafka_mock_cluster_t *mcluster;
    const char *groupid = "mygroup";
    const char *topic = "test";
    const int msgcnt = 100;
    rd_kafka_t *c;
    rd_kafka_conf_t *conf;

    SUB_TEST();

    mcluster = test_mock_cluster_new(3, &bootstraps);

    rd_kafka_mock_coordinator_set(mcluster, "group", groupid, 1);

    /* Seed the topic with messages */
    test_produce_msgs_easy_v(topic, 0, 0, 0, msgcnt, 10,
                             "bootstrap.servers", bootstraps,
                             "batch.num.messages", "10",
                             NULL);

    test_conf_init(&conf, NULL, 30);
    test_conf_set(conf, "bootstrap.servers", bootstraps);
    test_conf_set(conf, "security.protocol", "PLAINTEXT");
    test_conf_set(conf, "group.id", groupid);
    test_conf_set(conf, "auto.offset.reset", "earliest");
    test_conf_set(conf, "enable.auto.commit", "false");
    test_conf_set(conf, "partition.assignment.strategy", "cooperative-sticky");

    c = test_create_consumer(groupid, rebalance_cb, conf, NULL);

    test_consumer_subscribe(c, topic);

    expect_rebalance("initial assignment", c,
                     RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS,
                     rd_false/*don't expect lost*/, 5+2);


    /* Consume some messages so that the commit has something to commit. */
    test_consumer_poll("consume", c, -1, -1, -1, msgcnt/2, NULL);

    /* Fail Commit */
    rd_kafka_mock_push_request_errors(
      mcluster, RD_KAFKAP_OffsetCommit,
      5,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION,
      RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION);

    rd_kafka_commit(c, NULL, rd_false);

    expect_rebalance("lost partitions", c,
                     RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS,
                     rd_true/*expect lost*/, 10+2);

    expect_rebalance("rejoin group", c,
                     RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS,
                     rd_false/*expect lost*/, 20+2);

    TEST_SAY("Closing consumer\n");
    test_consumer_close(c);

    TEST_SAY("Destroying consumer\n");
    rd_kafka_destroy(c);

    TEST_SAY("Destroying mock cluster\n");
    test_mock_cluster_destroy(mcluster);
  }

  /* Local tests not needing a cluster */
  int main_0113_cooperative_rebalance_local (int argc, char **argv) {
    a_assign_rapid();
    p_lost_partitions_heartbeat_illegal_generation_test();
    q_lost_partitions_illegal_generation_test(rd_false/*joingroup*/);
    q_lost_partitions_illegal_generation_test(rd_true/*syncgroup*/);
    r_lost_partitions_commit_illegal_generation_test_local();
    return 0;
  }

  int main_0113_cooperative_rebalance (int argc, char **argv) {
    int i;

    a_assign_tests();
    b_subscribe_with_cb_test(true/*close consumer*/);
    b_subscribe_with_cb_test(false/*don't close consumer*/);
    c_subscribe_no_cb_test(true/*close consumer*/);

    if (test_quick) {
      Test::Say("Skipping tests c -> s due to quick mode\n");
      return 0;
    }

    c_subscribe_no_cb_test(false/*don't close consumer*/);
    d_change_subscription_add_topic(true/*close consumer*/);
    d_change_subscription_add_topic(false/*don't close consumer*/);
    e_change_subscription_remove_topic(true/*close consumer*/);
    e_change_subscription_remove_topic(false/*don't close consumer*/);
    f_assign_call_cooperative();
    g_incremental_assign_call_eager();
    h_delete_topic();
    i_delete_topic_2();
    j_delete_topic_no_rb_callback();
    k_add_partition();
    l_unsubscribe();
    m_unsubscribe_2();
    n_wildcard();
    o_java_interop();
    for (i = 1 ; i <= 6 ; i++) /* iterate over 6 different test variations */
      s_subscribe_when_rebalancing(i);
    for (i = 1 ; i <= 2 ; i++)
      t_max_poll_interval_exceeded(i);
    /* Run all 2*3 variations of the u_.. test */
    for (i = 0 ; i < 3 ; i++) {
      u_multiple_subscription_changes(true/*with rebalance_cb*/, i);
      u_multiple_subscription_changes(false/*without rebalance_cb*/, i);
    }

    return 0;
  }
}
