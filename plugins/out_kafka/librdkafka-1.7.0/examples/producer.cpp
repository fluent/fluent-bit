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

/**
 * Apache Kafka producer
 * using the Kafka driver from librdkafka
 * (https://github.com/edenhill/librdkafka)
 */

#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <csignal>
#include <cstring>

#if _AIX
#include <unistd.h>
#endif

/*
 * Typical include path in a real application would be
 * #include <librdkafka/rdkafkacpp.h>
 */
#include "rdkafkacpp.h"


static volatile sig_atomic_t run = 1;

static void sigterm (int sig) {
  run = 0;
}


class ExampleDeliveryReportCb : public RdKafka::DeliveryReportCb {
public:
  void dr_cb (RdKafka::Message &message) {
    /* If message.err() is non-zero the message delivery failed permanently
     * for the message. */
    if (message.err())
      std::cerr << "% Message delivery failed: " << message.errstr() << std::endl;
    else
      std::cerr << "% Message delivered to topic " << message.topic_name() <<
        " [" << message.partition() << "] at offset " <<
        message.offset() << std::endl;
  }
};

int main (int argc, char **argv) {

  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <brokers> <topic>\n";
    exit(1);
  }

  std::string brokers = argv[1];
  std::string topic = argv[2];

  /*
   * Create configuration object
   */
  RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);

  std::string errstr;

  /* Set bootstrap broker(s) as a comma-separated list of
   * host or host:port (default port 9092).
   * librdkafka will use the bootstrap brokers to acquire the full
   * set of brokers from the cluster. */
  if (conf->set("bootstrap.servers", brokers, errstr) !=
      RdKafka::Conf::CONF_OK) {
    std::cerr << errstr << std::endl;
    exit(1);
  }

  signal(SIGINT, sigterm);
  signal(SIGTERM, sigterm);

  /* Set the delivery report callback.
   * This callback will be called once per message to inform
   * the application if delivery succeeded or failed.
   * See dr_msg_cb() above.
   * The callback is only triggered from ::poll() and ::flush().
   *
   * IMPORTANT:
   * Make sure the DeliveryReport instance outlives the Producer object,
   * either by putting it on the heap or as in this case as a stack variable
   * that will NOT go out of scope for the duration of the Producer object.
   */
  ExampleDeliveryReportCb ex_dr_cb;

  if (conf->set("dr_cb", &ex_dr_cb, errstr) != RdKafka::Conf::CONF_OK) {
    std::cerr << errstr << std::endl;
    exit(1);
  }

  /*
   * Create producer instance.
   */
  RdKafka::Producer *producer = RdKafka::Producer::create(conf, errstr);
  if (!producer) {
    std::cerr << "Failed to create producer: " << errstr << std::endl;
    exit(1);
  }

  delete conf;

  /*
   * Read messages from stdin and produce to broker.
   */
  std::cout << "% Type message value and hit enter " <<
    "to produce message." << std::endl;

  for (std::string line; run && std::getline(std::cin, line);) {
    if (line.empty()) {
      producer->poll(0);
      continue;
    }

    /*
     * Send/Produce message.
     * This is an asynchronous call, on success it will only
     * enqueue the message on the internal producer queue.
     * The actual delivery attempts to the broker are handled
     * by background threads.
     * The previously registered delivery report callback
     * is used to signal back to the application when the message
     * has been delivered (or failed permanently after retries).
     */
  retry:
    RdKafka::ErrorCode err =
      producer->produce(
                        /* Topic name */
                        topic,
                        /* Any Partition: the builtin partitioner will be
                         * used to assign the message to a topic based
                         * on the message key, or random partition if
                         * the key is not set. */
                        RdKafka::Topic::PARTITION_UA,
                        /* Make a copy of the value */
                        RdKafka::Producer::RK_MSG_COPY /* Copy payload */,
                        /* Value */
                        const_cast<char *>(line.c_str()), line.size(),
                        /* Key */
                        NULL, 0,
                        /* Timestamp (defaults to current time) */
                        0,
                        /* Message headers, if any */
                        NULL,
                        /* Per-message opaque value passed to
                         * delivery report */
                        NULL);

    if (err != RdKafka::ERR_NO_ERROR) {
      std::cerr << "% Failed to produce to topic " << topic << ": " <<
        RdKafka::err2str(err) << std::endl;

      if (err == RdKafka::ERR__QUEUE_FULL) {
        /* If the internal queue is full, wait for
         * messages to be delivered and then retry.
         * The internal queue represents both
         * messages to be sent and messages that have
         * been sent or failed, awaiting their
         * delivery report callback to be called.
         *
         * The internal queue is limited by the
         * configuration property
         * queue.buffering.max.messages */
        producer->poll(1000/*block for max 1000ms*/);
        goto retry;
      }

    } else {
      std::cerr << "% Enqueued message (" << line.size() << " bytes) " <<
        "for topic " << topic << std::endl;
    }

    /* A producer application should continually serve
     * the delivery report queue by calling poll()
     * at frequent intervals.
     * Either put the poll call in your main loop, or in a
     * dedicated thread, or call it after every produce() call.
     * Just make sure that poll() is still called
     * during periods where you are not producing any messages
     * to make sure previously produced messages have their
     * delivery report callback served (and any other callbacks
     * you register). */
    producer->poll(0);
  }

  /* Wait for final messages to be delivered or fail.
   * flush() is an abstraction over poll() which
   * waits for all messages to be delivered. */
  std::cerr << "% Flushing final messages..." << std::endl;
  producer->flush(10*1000 /* wait for max 10 seconds */);

  if (producer->outq_len() > 0)
    std::cerr << "% " << producer->outq_len() <<
              " message(s) were not delivered" << std::endl;

  delete producer;

  return 0;
}
