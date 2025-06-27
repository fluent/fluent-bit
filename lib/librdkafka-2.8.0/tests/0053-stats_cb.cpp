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

#include <iostream>
#include <fstream>
#include <iterator>
#include <string>
#include "testcpp.h"

#if WITH_RAPIDJSON
#include <rapidjson/document.h>
#include <rapidjson/schema.h>
#include <rapidjson/filereadstream.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/error/en.h>
#include <rapidjson/prettywriter.h>
#endif

static const char *stats_schema_path = "../src/statistics_schema.json";

#if WITH_RAPIDJSON
/**
 * @brief Statistics schema validator
 */
class TestSchemaValidator {
 public:
  TestSchemaValidator() {
  }
  TestSchemaValidator(const std::string schema_path) {
    /* Read schema from file */
    schema_path_ = schema_path;

    std::ifstream f(schema_path.c_str());
    if (!f.is_open())
      Test::Fail(tostr() << "Failed to open schema " << schema_path << ": "
                         << strerror(errno));
    std::string schema_str((std::istreambuf_iterator<char>(f)),
                           (std::istreambuf_iterator<char>()));

    /* Parse schema */
    sd_ = new rapidjson::Document();
    if (sd_->Parse(schema_str.c_str()).HasParseError())
      Test::Fail(tostr() << "Failed to parse statistics schema: "
                         << rapidjson::GetParseError_En(sd_->GetParseError())
                         << " at " << sd_->GetErrorOffset());

    schema_    = new rapidjson::SchemaDocument(*sd_);
    validator_ = new rapidjson::SchemaValidator(*schema_);
  }

  ~TestSchemaValidator() {
    if (sd_)
      delete sd_;
    if (schema_)
      delete schema_;
    if (validator_)
      delete validator_;
  }

  void validate(const std::string &json_doc) {
    /* Parse JSON to validate */
    rapidjson::Document d;
    if (d.Parse(json_doc.c_str()).HasParseError())
      Test::Fail(tostr() << "Failed to parse stats JSON: "
                         << rapidjson::GetParseError_En(d.GetParseError())
                         << " at " << d.GetErrorOffset());

    /* Validate using schema */
    if (!d.Accept(*validator_)) {
      rapidjson::StringBuffer sb;

      validator_->GetInvalidSchemaPointer().StringifyUriFragment(sb);
      Test::Say(tostr() << "Schema: " << sb.GetString() << "\n");
      Test::Say(tostr() << "Invalid keyword: "
                        << validator_->GetInvalidSchemaKeyword() << "\n");
      sb.Clear();

      validator_->GetInvalidDocumentPointer().StringifyUriFragment(sb);
      Test::Say(tostr() << "Invalid document: " << sb.GetString() << "\n");
      sb.Clear();

      Test::Fail(tostr() << "JSON validation using schema " << schema_path_
                         << " failed");
    }

    Test::Say(3, "JSON document validated using schema " + schema_path_ + "\n");
  }

 private:
  std::string schema_path_;
  rapidjson::Document *sd_;
  rapidjson::SchemaDocument *schema_;
  rapidjson::SchemaValidator *validator_;
};


#else

/* Dummy validator doing nothing when RapidJSON is unavailable */
class TestSchemaValidator {
 public:
  TestSchemaValidator() {
  }
  TestSchemaValidator(const std::string schema_path) {
  }

  ~TestSchemaValidator() {
  }

  void validate(const std::string &json_doc) {
  }
};

#endif

class myEventCb : public RdKafka::EventCb {
 public:
  myEventCb(const std::string schema_path) :
      validator_(TestSchemaValidator(schema_path)) {
    stats_cnt = 0;
  }

  int stats_cnt;
  std::string last; /**< Last stats document */

  void event_cb(RdKafka::Event &event) {
    switch (event.type()) {
    case RdKafka::Event::EVENT_STATS:
      if (!(stats_cnt % 10))
        Test::Say(tostr() << "Stats (#" << stats_cnt << "): " << event.str()
                          << "\n");
      if (event.str().length() > 20)
        stats_cnt += 1;
      validator_.validate(event.str());
      last = event.str();
      break;
    default:
      break;
    }
  }

 private:
  TestSchemaValidator validator_;
};


/**
 * @brief Verify that stats are emitted according to statistics.interval.ms
 */
void test_stats_timing() {
  RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
  myEventCb my_event  = myEventCb(stats_schema_path);
  std::string errstr;

  if (conf->set("statistics.interval.ms", "100", errstr) !=
      RdKafka::Conf::CONF_OK)
    Test::Fail(errstr);

  if (conf->set("event_cb", &my_event, errstr) != RdKafka::Conf::CONF_OK)
    Test::Fail(errstr);

  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create Producer: " + errstr);
  delete conf;

  int64_t t_start = test_clock();

  while (my_event.stats_cnt < 12)
    p->poll(1000);

  int elapsed             = (int)((test_clock() - t_start) / 1000);
  const int expected_time = 1200;

  Test::Say(tostr() << my_event.stats_cnt
                    << " (expected 12) stats callbacks received in " << elapsed
                    << "ms (expected " << expected_time << "ms +-25%)\n");

  if (elapsed < expected_time * 0.75 || elapsed > expected_time * 1.25) {
    /* We can't rely on CIs giving our test job enough CPU to finish
     * in time, so don't error out even if the time is outside the window */
    if (test_on_ci)
      Test::Say(tostr() << "WARNING: Elapsed time " << elapsed
                        << "ms outside +-25% window (" << expected_time
                        << "ms), cnt " << my_event.stats_cnt);
    else
      Test::Fail(tostr() << "Elapsed time " << elapsed
                         << "ms outside +-25% window (" << expected_time
                         << "ms), cnt " << my_event.stats_cnt);
  }
  delete p;
}



#if WITH_RAPIDJSON

/**
 * @brief Expected partition stats
 */
struct exp_part_stats {
  std::string topic; /**< Topic */
  int32_t part;      /**< Partition id */
  int msgcnt;        /**< Expected message count */
  int msgsize;       /**< Expected per message size.
                      *   This includes both key and value lengths */

  /* Calculated */
  int64_t totsize; /**< Message size sum */
};

/**
 * @brief Verify end-to-end producer and consumer stats.
 */
static void verify_e2e_stats(const std::string &prod_stats,
                             const std::string &cons_stats,
                             struct exp_part_stats *exp_parts,
                             int partcnt) {
  /**
   * Parse JSON stats
   * These documents are already validated in the Event callback.
   */
  rapidjson::Document p;
  if (p.Parse<rapidjson::kParseValidateEncodingFlag>(prod_stats.c_str())
          .HasParseError())
    Test::Fail(tostr() << "Failed to parse producer stats JSON: "
                       << rapidjson::GetParseError_En(p.GetParseError())
                       << " at " << p.GetErrorOffset());

  rapidjson::Document c;
  if (c.Parse<rapidjson::kParseValidateEncodingFlag>(cons_stats.c_str())
          .HasParseError())
    Test::Fail(tostr() << "Failed to parse consumer stats JSON: "
                       << rapidjson::GetParseError_En(c.GetParseError())
                       << " at " << c.GetErrorOffset());

  assert(p.HasMember("name"));
  assert(c.HasMember("name"));
  assert(p.HasMember("type"));
  assert(c.HasMember("type"));

  Test::Say(tostr() << "Verifying stats from Producer " << p["name"].GetString()
                    << " and Consumer " << c["name"].GetString() << "\n");

  assert(!strcmp(p["type"].GetString(), "producer"));
  assert(!strcmp(c["type"].GetString(), "consumer"));

  int64_t exp_tot_txmsgs      = 0;
  int64_t exp_tot_txmsg_bytes = 0;
  int64_t exp_tot_rxmsgs      = 0;
  int64_t exp_tot_rxmsg_bytes = 0;

  for (int part = 0; part < partcnt; part++) {
    /*
     * Find partition stats.
     */

    /* Construct the partition path. */
    char path[256];
    rd_snprintf(path, sizeof(path), "/topics/%s/partitions/%d",
                exp_parts[part].topic.c_str(), exp_parts[part].part);
    Test::Say(tostr() << "Looking up partition " << exp_parts[part].part
                      << " with path " << path << "\n");

    /* Even though GetValueByPointer() takes a "char[]" it can only be used
     * with perfectly sized char buffers or string literals since it
     * does not respect NUL terminators.
     * So instead convert the path to a Pointer.*/
    rapidjson::Pointer jpath((const char *)path);

    rapidjson::Value *pp = rapidjson::GetValueByPointer(p, jpath);
    if (!pp)
      Test::Fail(tostr() << "Producer: could not find " << path << " in "
                         << prod_stats << "\n");

    rapidjson::Value *cp = rapidjson::GetValueByPointer(c, jpath);
    if (!pp)
      Test::Fail(tostr() << "Consumer: could not find " << path << " in "
                         << cons_stats << "\n");

    assert(pp->HasMember("partition"));
    assert(pp->HasMember("txmsgs"));
    assert(pp->HasMember("txbytes"));

    assert(cp->HasMember("partition"));
    assert(cp->HasMember("rxmsgs"));
    assert(cp->HasMember("rxbytes"));

    Test::Say(tostr() << "partition: " << (*pp)["partition"].GetInt() << "\n");

    int64_t txmsgs  = (*pp)["txmsgs"].GetInt();
    int64_t txbytes = (*pp)["txbytes"].GetInt();
    int64_t rxmsgs  = (*cp)["rxmsgs"].GetInt();
    int64_t rxbytes = (*cp)["rxbytes"].GetInt();

    exp_tot_txmsgs += txmsgs;
    exp_tot_txmsg_bytes += txbytes;
    exp_tot_rxmsgs += rxmsgs;
    exp_tot_rxmsg_bytes += rxbytes;

    Test::Say(tostr() << "Producer partition: " << (*pp)["partition"].GetInt()
                      << ": "
                      << "txmsgs: " << txmsgs << " vs "
                      << exp_parts[part].msgcnt << ", "
                      << "txbytes: " << txbytes << " vs "
                      << exp_parts[part].totsize << "\n");
    Test::Say(tostr() << "Consumer partition: " << (*cp)["partition"].GetInt()
                      << ": "
                      << "rxmsgs: " << rxmsgs << " vs "
                      << exp_parts[part].msgcnt << ", "
                      << "rxbytes: " << rxbytes << " vs "
                      << exp_parts[part].totsize << "\n");
  }

  /* Check top-level total stats */

  assert(p.HasMember("txmsgs"));
  assert(p.HasMember("txmsg_bytes"));
  assert(p.HasMember("rxmsgs"));
  assert(p.HasMember("rxmsg_bytes"));

  int64_t tot_txmsgs      = p["txmsgs"].GetInt();
  int64_t tot_txmsg_bytes = p["txmsg_bytes"].GetInt();
  int64_t tot_rxmsgs      = c["rxmsgs"].GetInt();
  int64_t tot_rxmsg_bytes = c["rxmsg_bytes"].GetInt();

  Test::Say(tostr() << "Producer total: "
                    << "txmsgs: " << tot_txmsgs << " vs " << exp_tot_txmsgs
                    << ", "
                    << "txbytes: " << tot_txmsg_bytes << " vs "
                    << exp_tot_txmsg_bytes << "\n");
  Test::Say(tostr() << "Consumer total: "
                    << "rxmsgs: " << tot_rxmsgs << " vs " << exp_tot_rxmsgs
                    << ", "
                    << "rxbytes: " << tot_rxmsg_bytes << " vs "
                    << exp_tot_rxmsg_bytes << "\n");
}

/**
 * @brief Verify stats JSON structure and individual metric fields.
 *
 * To capture as much verifiable data as possible we run a full
 * producer - consumer end to end test and verify that counters
 * and states are emitted accordingly.
 *
 * Requires RapidJSON (for parsing the stats).
 */
static void test_stats() {
  std::string errstr;
  RdKafka::Conf *conf;
  myEventCb producer_event(stats_schema_path);
  myEventCb consumer_event(stats_schema_path);

  std::string topic = Test::mk_topic_name("0053_stats", 1);

  const int partcnt = 2;
  int msgcnt        = (test_quick ? 10 : 100) * partcnt;
  const int msgsize = 6 * 1024;

  /*
   * Common config for producer and consumer
   */
  Test::conf_init(&conf, NULL, 60);
  if (conf->set("statistics.interval.ms", "1000", errstr) !=
      RdKafka::Conf::CONF_OK)
    Test::Fail(errstr);


  /*
   * Create Producer
   */
  if (conf->set("event_cb", &producer_event, errstr) != RdKafka::Conf::CONF_OK)
    Test::Fail(errstr);

  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create Producer: " + errstr);


  /*
   * Create Consumer
   */
  conf->set("group.id", topic, errstr);
  conf->set("auto.offset.reset", "earliest", errstr);
  conf->set("enable.partition.eof", "false", errstr);
  if (conf->set("event_cb", &consumer_event, errstr) != RdKafka::Conf::CONF_OK)
    Test::Fail(errstr);

  RdKafka::KafkaConsumer *c = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!c)
    Test::Fail("Failed to create KafkaConsumer: " + errstr);
  delete conf;

  /*
   * Set up consumer assignment (but assign after producing
   * since there will be no topics now) and expected partitions
   * for later verification.
   */
  std::vector<RdKafka::TopicPartition *> toppars;
  struct exp_part_stats exp_parts[partcnt] = {};

  for (int32_t part = 0; part < (int32_t)partcnt; part++) {
    toppars.push_back(RdKafka::TopicPartition::create(
        topic, part, RdKafka::Topic::OFFSET_BEGINNING));
    exp_parts[part].topic   = topic;
    exp_parts[part].part    = part;
    exp_parts[part].msgcnt  = msgcnt / partcnt;
    exp_parts[part].msgsize = msgsize;
    exp_parts[part].totsize = 0;
  }

  /*
   * Produce messages
   */
  uint64_t testid = test_id_generate();

  char key[256];
  char *buf = (char *)malloc(msgsize);

  for (int32_t part = 0; part < (int32_t)partcnt; part++) {
    for (int i = 0; i < msgcnt / partcnt; i++) {
      test_prepare_msg(testid, part, i, buf, msgsize, key, sizeof(key));
      RdKafka::ErrorCode err =
          p->produce(topic, part, RdKafka::Producer::RK_MSG_COPY, buf, msgsize,
                     key, sizeof(key), -1, NULL);
      if (err)
        Test::Fail("Produce failed: " + RdKafka::err2str(err));
      exp_parts[part].totsize += msgsize + sizeof(key);
      p->poll(0);
    }
  }

  free(buf);

  Test::Say("Waiting for final message delivery\n");
  /* Wait for delivery */
  p->flush(15 * 1000);

  /*
   * Start consuming partitions
   */
  c->assign(toppars);
  RdKafka::TopicPartition::destroy(toppars);

  /*
   * Consume the messages
   */
  int recvcnt = 0;
  Test::Say(tostr() << "Consuming " << msgcnt << " messages\n");
  while (recvcnt < msgcnt) {
    RdKafka::Message *msg = c->consume(-1);
    if (msg->err())
      Test::Fail("Consume failed: " + msg->errstr());

    int msgid;
    TestMessageVerify(testid, -1, &msgid, msg);
    recvcnt++;
    delete msg;
  }

  /*
   * Producer:
   * Wait for one last stats emit when all messages have been delivered.
   */
  int prev_cnt = producer_event.stats_cnt;
  while (prev_cnt == producer_event.stats_cnt) {
    Test::Say("Waiting for final producer stats event\n");
    p->poll(100);
  }

  /*
   * Consumer:
   * Wait for a one last stats emit when all messages have been received,
   * since previous stats may have been enqueued but not served we
   * skip the first 2.
   */
  prev_cnt = consumer_event.stats_cnt;
  while (prev_cnt + 2 >= consumer_event.stats_cnt) {
    Test::Say(tostr() << "Waiting for final consumer stats event: "
                      << consumer_event.stats_cnt << "\n");
    c->poll(100);
  }


  verify_e2e_stats(producer_event.last, consumer_event.last, exp_parts,
                   partcnt);


  c->close();

  delete p;
  delete c;
}
#endif

extern "C" {
int main_0053_stats_timing(int argc, char **argv) {
  test_stats_timing();
  return 0;
}

int main_0053_stats(int argc, char **argv) {
#if WITH_RAPIDJSON
  test_stats();
#else
  Test::Skip("RapidJSON >=1.1.0 not available\n");
#endif
  return 0;
}
}
