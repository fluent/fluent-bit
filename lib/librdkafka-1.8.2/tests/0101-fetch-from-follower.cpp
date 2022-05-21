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

#include "testcpp.h"

#if WITH_RAPIDJSON

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <assert.h>
#include <sstream>
#include <string>
#include <map>
#include <set>
#include "rdkafka.h"

#include <rapidjson/document.h>
#include <rapidjson/schema.h>
#include <rapidjson/filereadstream.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/error/en.h>
#include <rapidjson/prettywriter.h>


/**
 * @brief A basic test of fetch from follower funtionality
 *  - produces a bunch of messages to a replicated topic.
 *  - configure the consumer such that `client.rack` is different from the
 *    broker's `broker.rack` (and use
 *    org.apache.kafka.common.replica.RackAwareReplicaSelector).
 *  - consume the messages, and check they are as expected.
 *  - use rxbytes from the statistics event to confirm that 
 *    the messages were retrieved from the replica broker (not the
 *    leader).
 */


static void test_assert (bool cond, std::string msg) {
  if (!cond)
    Test::Say(msg);
  assert(cond);
}


class TestEvent2Cb : public RdKafka::EventCb {
 public:
  static bool should_capture_stats;
  static bool has_captured_stats;
  static std::map<int32_t, int64_t> rxbytes;

  void event_cb (RdKafka::Event &event) {

    switch (event.type())
    {
      case RdKafka::Event::EVENT_LOG:
        Test::Say(event.str() + "\n");
        break;
      case RdKafka::Event::EVENT_STATS:
        if (should_capture_stats) {

          rapidjson::Document d;
          if (d.Parse(event.str().c_str()).HasParseError())
            Test::Fail(tostr() << "Failed to parse stats JSON: " <<
                       rapidjson::GetParseError_En(d.GetParseError()) <<
                       " at " << d.GetErrorOffset());

          /* iterate over brokers. */
          rapidjson::Pointer jpath((const char *)"/brokers");
          rapidjson::Value *pp = rapidjson::GetValueByPointer(d, jpath);
          if (pp == NULL)
            return;

          for (rapidjson::Value::ConstMemberIterator itr = pp->MemberBegin(); itr != pp->MemberEnd(); ++itr) {
            std::string broker_name = itr->name.GetString();
            size_t broker_id_idx = broker_name.rfind('/');
            if (broker_id_idx == (size_t)-1)
              continue;
            std::string broker_id = broker_name.substr(broker_id_idx + 1, broker_name.size() - broker_id_idx - 1);

            int64_t broker_rxbytes = itr->value.FindMember("rxbytes")->value.GetInt64();
            rxbytes[atoi(broker_id.c_str())] = broker_rxbytes;
          }

          has_captured_stats = true;
          break;
        }
      default:
        break;
    }
  }
};

bool TestEvent2Cb::should_capture_stats;
bool TestEvent2Cb::has_captured_stats;
std::map<int32_t, int64_t> TestEvent2Cb::rxbytes;
static TestEvent2Cb ex_event_cb;


static void get_brokers_info (std::string &topic_str, int32_t *leader, std::vector<int> &brokers) {
  std::string errstr;
  RdKafka::ErrorCode err;
  class RdKafka::Metadata *metadata;

  /* Determine the ids of the brokers that the partition has replicas
   * on and which one of those is the leader.
   */
  RdKafka::Conf *pConf;
  Test::conf_init(&pConf, NULL, 10);
  RdKafka::Producer *p = RdKafka::Producer::create(pConf, errstr);
  delete pConf;
  test_assert(p, tostr() << "Failed to create producer: " << errstr);

  RdKafka::Topic *topic = RdKafka::Topic::create(p, topic_str, NULL, errstr);
  test_assert(topic, tostr() << "Failed to create topic: " << errstr);

  err = p->metadata(0, topic, &metadata, tmout_multip(5000));
  test_assert(err == RdKafka::ERR_NO_ERROR,
    tostr() <<  "%% Failed to acquire metadata: "
            << RdKafka::err2str(err));

  test_assert(metadata->topics()->size() == 1,
    tostr() << "expecting metadata for exactly one topic. "
            << "have metadata for " << metadata->topics()->size()
            << "topics");

  RdKafka::Metadata::TopicMetadataIterator topicMetadata = metadata->topics()->begin();
  RdKafka::TopicMetadata::PartitionMetadataIterator partitionMetadata = (*topicMetadata)->partitions()->begin();

  *leader = (*partitionMetadata)->leader();

  size_t idx = 0;
  RdKafka::PartitionMetadata::ReplicasIterator replicasIterator;
  for (replicasIterator = (*partitionMetadata)->replicas()->begin();
           replicasIterator != (*partitionMetadata)->replicas()->end();
           ++replicasIterator) {
    brokers.push_back(*replicasIterator);
    idx++;
  }

  delete metadata;
  delete topic;
  delete p;
}


/**
 * @brief Wait for up to \p tmout for any type of admin result.
 * @returns the event
 */
rd_kafka_event_t *
test_wait_admin_result (rd_kafka_queue_t *q,
                        rd_kafka_event_type_t evtype,
                        int tmout) {
  rd_kafka_event_t *rkev;

  while (1) {
    rkev = rd_kafka_queue_poll(q, tmout);
    if (!rkev)
      Test::Fail(tostr() << "Timed out waiting for admin result ("
                          << evtype << ")\n");

    if (rd_kafka_event_type(rkev) == evtype)
      return rkev;

    if (rd_kafka_event_type(rkev) == RD_KAFKA_EVENT_ERROR) {
      Test::Say(tostr() << "Received error event while waiting for "
                        << evtype << ": "
                        << rd_kafka_event_error_string(rkev)
                        << ": ignoring");
      continue;
    }

    test_assert(rd_kafka_event_type(rkev) == evtype,
                tostr() << "Expected event type " << evtype
                        << ", got " << rd_kafka_event_type(rkev) << " ("
                        << rd_kafka_event_name(rkev) << ")");
  }

  return NULL;
}


/**
 * @returns the number of broker.rack values configured across all brokers.
 */
static int get_broker_rack_count (std::vector<int> &replica_ids)
{
  std::string errstr;
  RdKafka::Conf *pConf;
  Test::conf_init(&pConf, NULL, 10);
  RdKafka::Producer *p = RdKafka::Producer::create(pConf, errstr);
  delete pConf;

  rd_kafka_queue_t *mainq = rd_kafka_queue_get_main(p->c_ptr());

  std::set<std::string> racks;
  for (size_t i=0; i<replica_ids.size(); ++i) {
    std::string name = tostr() << replica_ids[i];

    rd_kafka_ConfigResource_t *config = rd_kafka_ConfigResource_new(
                    RD_KAFKA_RESOURCE_BROKER, &name[0]);

    rd_kafka_AdminOptions_t *options;
    char cerrstr[128];
    options = rd_kafka_AdminOptions_new(p->c_ptr(), RD_KAFKA_ADMIN_OP_ANY);
    rd_kafka_resp_err_t err = rd_kafka_AdminOptions_set_request_timeout(options, 10000, cerrstr, sizeof(cerrstr));
    test_assert(!err, cerrstr);

    rd_kafka_DescribeConfigs(p->c_ptr(), &config, 1, options, mainq);
    rd_kafka_AdminOptions_destroy(options);
    rd_kafka_event_t *rkev = test_wait_admin_result(mainq, RD_KAFKA_EVENT_DESCRIBECONFIGS_RESULT, 5000);

    const rd_kafka_DescribeConfigs_result_t *res = rd_kafka_event_DescribeConfigs_result(rkev);
    test_assert(res, "expecting describe config results to be not NULL");

    err = rd_kafka_event_error(rkev);
    const char *errstr2 = rd_kafka_event_error_string(rkev);
    test_assert(!err, tostr() << "Expected success, not " << rd_kafka_err2name(err) << ": " << errstr2);

    size_t rconfig_cnt;
    const rd_kafka_ConfigResource_t **rconfigs = rd_kafka_DescribeConfigs_result_resources(res, &rconfig_cnt);
    test_assert(rconfig_cnt == 1, tostr() << "Expecting 1 resource, got " << rconfig_cnt);

    err = rd_kafka_ConfigResource_error(rconfigs[0]);
    errstr2 = rd_kafka_ConfigResource_error_string(rconfigs[0]);

    size_t entry_cnt;
    const rd_kafka_ConfigEntry_t **entries = rd_kafka_ConfigResource_configs(rconfigs[0], &entry_cnt);

    for (size_t j = 0; j<entry_cnt; ++j) {
      const rd_kafka_ConfigEntry_t *e = entries[j];
      const char *cname = rd_kafka_ConfigEntry_name(e);
      if (!strcmp(cname, "broker.rack")) {
        const char *val = rd_kafka_ConfigEntry_value(e) ? rd_kafka_ConfigEntry_value(e) : "(NULL)";
        racks.insert(std::string(val));
      }
    }

    rd_kafka_event_destroy(rkev);
  }

  delete p;

  return (int)racks.size();
}


static void do_fff_test (void) {

  /* Produce some messages to a single partition topic
   * with 3 replicas.
   */
  int msgcnt = 1000;
  const int msgsize = 100;
  std::string topic_str = Test::mk_topic_name("0101-fetch-from-follower", 1);
  test_create_topic(NULL, topic_str.c_str(), 1, 3);
  test_produce_msgs_easy_size(topic_str.c_str(), 0, 0, msgcnt, msgsize);

  int leader_id;
  std::vector<int> replica_ids;
  get_brokers_info(topic_str, &leader_id, replica_ids);
  test_assert(replica_ids.size() == 3, tostr() << "expecting three replicas, but " << replica_ids.size() << " were reported.");
  Test::Say(tostr() << topic_str << " leader id: " << leader_id << ", all replica ids: [" << replica_ids[0] << ", " << replica_ids[1] << ", " << replica_ids[2] << "]\n");

  if (get_broker_rack_count(replica_ids) != 3) {
    Test::Skip("unexpected broker.rack configuration: skipping test.\n");
  }

  /* arrange for the consumer's client.rack to align with a broker that is not the leader. */
  int client_rack_id = -1;
  size_t i;
  for (i=0; i<replica_ids.size(); ++i) {
    if (replica_ids[i] != leader_id) {
      client_rack_id = replica_ids[i];
      break;
    }
  }
  
  std::string client_rack = tostr() << "RACK" << client_rack_id;
  Test::Say("client.rack: " + client_rack + "\n");

  std::string errstr;
  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 10);
  Test::conf_set(conf, "group.id", topic_str);
  Test::conf_set(conf, "auto.offset.reset", "earliest");
  Test::conf_set(conf, "enable.auto.commit", "false");
  Test::conf_set(conf, "statistics.interval.ms", "1000");
  conf->set("event_cb", &ex_event_cb, errstr);
  Test::conf_set(conf, "client.rack", client_rack);

  RdKafka::KafkaConsumer *c = RdKafka::KafkaConsumer::create(conf, errstr);
  test_assert(c, "Failed to create KafkaConsumer: " + errstr);
  delete conf;

  /* Subscribe */
  std::vector<std::string> topics;
  topics.push_back(topic_str);
  RdKafka::ErrorCode err;
  if ((err = c->subscribe(topics)))
    Test::Fail("subscribe failed: " + RdKafka::err2str(err));

  /* Start consuming */
  Test::Say("Consuming topic " + topic_str + "\n");
  int cnt = 0;
  while (cnt < msgcnt) {
    RdKafka::Message *msg = c->consume(tmout_multip(1000));

    switch (msg->err())
      {
      case RdKafka::ERR__TIMED_OUT:
        break;

      case RdKafka::ERR_NO_ERROR:
        {
          test_assert(msg->len() == 100, "expecting message value size to be 100");
          char *cnt_str_start_ptr = strstr((char *)msg->payload(), "msg=") + 4;
          test_assert(cnt_str_start_ptr, "expecting 'msg=' in message payload");
          char *cnt_str_end_ptr = strstr(cnt_str_start_ptr, "\n");
          test_assert(cnt_str_start_ptr, "expecting '\n' following 'msg=' in message payload");
          *cnt_str_end_ptr = '\0';
          int msg_cnt = atoi(cnt_str_start_ptr);
          test_assert(msg_cnt == cnt, "message consumed out of order");
          cnt++;
        }
        break;

      default:
        Test::Fail("Consume error: " + msg->errstr());
        break;
      }

    delete msg;
  }

  /* rely on the test timeout to prevent an infinite loop in
   * the (unlikely) event that the statistics callback isn't
   * called. */
  Test::Say("Capturing rxbytes statistics\n");
  TestEvent2Cb::should_capture_stats = true;
  while (!TestEvent2Cb::has_captured_stats) {
    RdKafka::Message *msg = c->consume(tmout_multip(500));
    delete msg;
  }

  for (i=0; i<replica_ids.size(); ++i)
    Test::Say(tostr() << _C_YEL << "rxbytes for replica on broker " << replica_ids[i] << ": " << TestEvent2Cb::rxbytes[replica_ids[i]]
                      << (replica_ids[i] == leader_id ? " (leader)" : "")
                      << (replica_ids[i] == client_rack_id ? " (preferred replica)" : "")
                      << "\n");

  for (i=0; i<replica_ids.size(); ++i)
    if (replica_ids[i] != client_rack_id)
      test_assert(TestEvent2Cb::rxbytes[replica_ids[i]] < TestEvent2Cb::rxbytes[client_rack_id],
                  "rxbytes was not highest on broker corresponding to client.rack.");

  test_assert(TestEvent2Cb::rxbytes[client_rack_id] > msgcnt * msgsize,
              tostr() << "expecting rxbytes of client.rack broker to be at least " << msgcnt * msgsize
                      << " but it was " << TestEvent2Cb::rxbytes[client_rack_id]);

  Test::Say("Done\n");

  // Manual test 1:
  //  - change the lease period from 5 minutes to 5 seconds (modify rdkafka_partition.c)
  //  - change the max lease grant period from 1 minute to 10 seconds (modify rdkafka_broker.c)
  //  - add infinite consume loop to the end of this test.
  //  - observe:
  //     - the partition gets delegated to the preferred replica.
  //     - the messages get consumed.
  //     - the lease expires.
  //     - the partition is reverted to the leader.
  //     - the toppar is backed off, and debug message noting the faster than expected delegation to a replica.

  // Manual test 2:
  //  - same modifications as above.
  //  - add Test::conf_set(conf, "topic.metadata.refresh.interval.ms", "3000");
  //  - observe:
  //     - that metadata being periodically received and not interfering with anything.

  c->close();
  delete c;
}
#endif

extern "C" {
int main_0101_fetch_from_follower (int argc, char **argv) {
#if WITH_RAPIDJSON
    do_fff_test();
#else
    Test::Skip("RapidJSON >=1.1.0 not available\n");
#endif
    return 0;
  }
}
