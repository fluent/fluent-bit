/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2016, Magnus Edenhill
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
#include <cstring>
#include <cstdlib>
#include "testcpp.h"

/**
 * Verify consumer_lag
 */

static std::string topic;

class StatsCb : public RdKafka::EventCb {
 public:
  int64_t calc_lag; //calculated lag
  int lag_valid;  // number of times lag has been valid

  StatsCb() {
    calc_lag = -1;
    lag_valid = 0;
  }

  /**
   * @brief Event callback
   */
  void event_cb (RdKafka::Event &event) {
    if (event.type() == RdKafka::Event::EVENT_LOG) {
      Test::Say(tostr() << "LOG-" << event.severity() << "-" << event.fac() <<
                ": " << event.str() << "\n");
      return;
    } else if (event.type() != RdKafka::Event::EVENT_STATS) {
      Test::Say(tostr() << "Dropping event " << event.type() << "\n");
      return;
    }

    int64_t consumer_lag = parse_json(event.str().c_str());

    Test::Say(3, tostr() << "Stats: consumer_lag is " << consumer_lag << "\n");
    if (consumer_lag == -1) {
      Test::Say(2, "Skipping old stats with invalid consumer_lag\n");
      return; /* Old stats generated before first message consumed */
    } else if (consumer_lag != calc_lag)
      Test::Fail(tostr() << "Stats consumer_lag " << consumer_lag << ", expected " << calc_lag << "\n");
    else
      lag_valid++;
  }


  /**
   * @brief Naiive JSON parsing, find the consumer_lag for partition 0
   * and return it.
   */
  static int64_t parse_json (const char *json_doc) {
    const std::string match_topic(std::string("\"") + topic + "\":");
    const char *search[] = { "\"topics\":",
                             match_topic.c_str(),
                             "\"partitions\":",
                             "\"0\":",
                             "\"consumer_lag\":",
                             NULL };
    const char *remain = json_doc;

    for (const char **sp = search ; *sp ; sp++) {
      const char *t = strstr(remain, *sp);
      if (!t)
        Test::Fail(tostr() << "Couldnt find " << *sp <<
                   " in remaining stats output:\n" << remain <<
                   "\n====================\n" << json_doc << "\n");
      remain = t + strlen(*sp);
    }

    while (*remain == ' ')
      remain++;

    if (!*remain)
      Test::Fail("Nothing following consumer_lag");

    int64_t lag = strtoull(remain, NULL, 0);
    if (lag == -1) {
      Test::Say(tostr() << "Consumer lag " << lag << " is invalid, stats:\n");
      Test::Say(3, tostr() << json_doc << "\n");
    }
    return lag;
  }
};


/**
 * @brief Produce \p msgcnt in a transaction that is aborted.
 */
static void produce_aborted_txns (const std::string &topic,
                                  int32_t partition, int msgcnt) {
  RdKafka::Producer *p;
  RdKafka::Conf *conf;
  RdKafka::Error *error;

  Test::Say(tostr() << "Producing " << msgcnt << " transactional messages " <<
            "which will be aborted\n");
  Test::conf_init(&conf, NULL, 0);

  Test::conf_set(conf, "transactional.id", "txn_id_" + topic);

  std::string errstr;
  p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create Producer:  " + errstr);
  delete conf;

  error = p->init_transactions(-1);
  if (error)
    Test::Fail("init_transactions() failed: " + error->str());

  error = p->begin_transaction();
  if (error)
    Test::Fail("begin_transaction() failed: " + error->str());

  for (int i = 0 ; i < msgcnt ; i++) {
    RdKafka::ErrorCode err;

    err = p->produce(topic, partition, RdKafka::Producer::RK_MSG_COPY,
                     &i, sizeof(i),
                     NULL, 0,
                     0, NULL);
    if (err)
      Test::Fail("produce() failed: " + RdKafka::err2str(err));
  }

  /* Flush is typically not needed for transactions since
   * commit_transaction() will do it automatically, but in the case of
   * abort_transaction() nothing might have been sent to the broker yet,
   * so call flush() here so we know the messages are sent and the
   * partitions are added to the transaction, so that a control(abort)
   * message is written to the partition. */
  p->flush(-1);

  error = p->abort_transaction(-1);
  if (error)
    Test::Fail("abort_transaction() failed: " + error->str());

  delete p;
}


static void do_test_consumer_lag (bool with_txns) {
  int msgcnt = test_quick ? 5 : 10;
  int txn_msgcnt = 3;
  int addcnt = 0;
  std::string errstr;
  RdKafka::ErrorCode err;

  Test::Say(tostr() << _C_MAG << "[ Test consumer lag " <<
            (with_txns ? "with":"without") << " transactions ]\n");

  topic = Test::mk_topic_name("0061-consumer_lag", 1);

  test_produce_msgs_easy(topic.c_str(), 0, 0, msgcnt);

  if (with_txns) {
    /* After the standard messages have been produced,
     * produce some transactional messages that are aborted to advance
     * the end offset with control messages. */
    produce_aborted_txns(topic, 0, txn_msgcnt);
    addcnt = txn_msgcnt + 1 /* ctrl msg */;
  }

  /*
   * Create consumer
   */

  /* Create consumer */
  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 40);
  StatsCb stats;
  if (conf->set("event_cb", &stats, errstr) != RdKafka::Conf::CONF_OK)
    Test::Fail("set event_cb failed: " + errstr);
  Test::conf_set(conf, "group.id", topic);
  Test::conf_set(conf, "enable.auto.commit", "false");
  Test::conf_set(conf, "auto.offset.reset", "earliest");
  Test::conf_set(conf, "statistics.interval.ms", "100");

  RdKafka::KafkaConsumer *c = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!c)
    Test::Fail("Failed to create KafkaConsumer: " + errstr);
  delete conf;

  /* Assign partitions */
  std::vector<RdKafka::TopicPartition*> parts;
  parts.push_back(RdKafka::TopicPartition::create(topic, 0));
  if ((err = c->assign(parts)))
    Test::Fail("assign failed: " + RdKafka::err2str(err));
  RdKafka::TopicPartition::destroy(parts);

  /* Start consuming */
  Test::Say("Consuming topic " + topic + "\n");
  int cnt = 0;
  while (cnt < msgcnt + addcnt) {
    RdKafka::Message *msg = c->consume(1000);

    switch (msg->err())
      {
      case RdKafka::ERR__TIMED_OUT:
        if (with_txns && cnt >= msgcnt && stats.calc_lag == 0)
          addcnt = 0; /* done */
        break;
      case RdKafka::ERR__PARTITION_EOF:
        Test::Fail(tostr() << "Unexpected PARTITION_EOF (not enbaled) after "
                   << cnt << "/" << msgcnt << " messages: " << msg->errstr());
        break;

      case RdKafka::ERR_NO_ERROR:
        /* Proper message. Update calculated lag for later
         * checking in stats callback */
        if (msg->offset()+1 >= msgcnt && with_txns)
          stats.calc_lag = 0;
        else
          stats.calc_lag = (msgcnt+addcnt) - (msg->offset()+1);
        cnt++;
        Test::Say(2, tostr() << "Received message #" << cnt << "/" << msgcnt <<
                  " at offset " << msg->offset() << " (calc lag " << stats.calc_lag << ")\n");
        /* Slow down message "processing" to make sure we get
         * at least one stats callback per message. */
        if (cnt < msgcnt)
          rd_sleep(1);
        break;

      default:
        Test::Fail("Consume error: " + msg->errstr());
        break;
      }

    delete msg;
  }
  Test::Say(tostr() << "Done, lag was valid " <<
            stats.lag_valid << " times\n");
  if (stats.lag_valid == 0)
    Test::Fail("No valid consumer_lag in statistics seen");

  c->close();
  delete c;
}

extern "C" {
  int main_0061_consumer_lag (int argc, char **argv) {
    do_test_consumer_lag(false/*no txns*/);
    if (test_broker_version >= TEST_BRKVER(0,11,0,0))
      do_test_consumer_lag(true/*txns*/);
    return 0;
  }
}
