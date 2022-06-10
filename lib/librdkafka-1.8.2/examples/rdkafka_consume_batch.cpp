/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2018, Magnus Edenhill
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
 * Apache Kafka consumer & producer example programs
 * using the Kafka driver from librdkafka
 * (https://github.com/edenhill/librdkafka)
 *
 * This example shows how to read batches of messages.
 * Note that messages are fetched from the broker in batches regardless
 * of how the application polls messages from librdkafka, this example
 * merely shows how to accumulate a set of messages in the application.
 */

#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <csignal>
#include <cstring>

#ifndef _WIN32
#include <sys/time.h>
#endif

#ifdef _WIN32
#include "../win32/wingetopt.h"
#include <atltime.h>
#elif _AIX
#include <unistd.h>
#else
#include <getopt.h>
#include <unistd.h>
#endif

/*
 * Typically include path in a real application would be
 * #include <librdkafka/rdkafkacpp.h>
 */
#include "rdkafkacpp.h"



static volatile sig_atomic_t run = 1;

static void sigterm (int sig) {
  run = 0;
}



/**
 * @returns the current wall-clock time in milliseconds
 */
static int64_t now () {
#ifndef _WIN32
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return ((int64_t)tv.tv_sec * 1000) + (tv.tv_usec / 1000);
#else
#error "now() not implemented for Windows, please submit a PR"
#endif
}



/**
 * @brief Accumulate a batch of \p batch_size messages, but wait
 *        no longer than \p batch_tmout milliseconds.
 */
static std::vector<RdKafka::Message *>
consume_batch (RdKafka::KafkaConsumer *consumer, size_t batch_size, int batch_tmout) {

  std::vector<RdKafka::Message *> msgs;
  msgs.reserve(batch_size);

  int64_t end = now() + batch_tmout;
  int remaining_timeout = batch_tmout;

  while (msgs.size() < batch_size) {
    RdKafka::Message *msg = consumer->consume(remaining_timeout);

    switch (msg->err()) {
    case RdKafka::ERR__TIMED_OUT:
      delete msg;
      return msgs;

    case RdKafka::ERR_NO_ERROR:
      msgs.push_back(msg);
      break;

    default:
      std::cerr << "%% Consumer error: " << msg->errstr() << std::endl;
      run = 0;
      delete msg;
      return msgs;
    }

    remaining_timeout = end - now();
    if (remaining_timeout < 0)
      break;
  }

  return msgs;
}


int main (int argc, char **argv) {
  std::string errstr;
  std::string topic_str;
  std::vector<std::string> topics;
  int batch_size = 100;
  int batch_tmout = 1000;

  /* Create configuration objects */
  RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);

  if (conf->set("enable.partition.eof", "false", errstr) != RdKafka::Conf::CONF_OK) {
    std::cerr << errstr << std::endl;
    exit(1);
  }

  /* Read command line arguments */
  int opt;
  while ((opt = getopt(argc, argv, "g:B:T:b:X:")) != -1) {
    switch (opt) {
    case 'g':
      if (conf->set("group.id",  optarg, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
      }
      break;

    case 'B':
      batch_size = atoi(optarg);
      break;

    case 'T':
      batch_tmout = atoi(optarg);
      break;

    case 'b':
      if (conf->set("bootstrap.servers", optarg, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
      }
      break;

    case 'X':
      {
        char *name, *val;

        name = optarg;
        if (!(val = strchr(name, '='))) {
          std::cerr << "%% Expected -X property=value, not " <<
              name << std::endl;
          exit(1);
        }

        *val = '\0';
        val++;

        if (conf->set(name, val, errstr) != RdKafka::Conf::CONF_OK) {
          std::cerr << errstr << std::endl;
          exit(1);
        }
      }
      break;

    default:
      goto usage;
    }
  }

  /* Topics to consume */
  for (; optind < argc ; optind++)
    topics.push_back(std::string(argv[optind]));

  if (topics.empty() || optind != argc) {
  usage:
    fprintf(stderr,
            "Usage: %s -g <group-id> -B <batch-size> [options] topic1 topic2..\n"
            "\n"
            "librdkafka version %s (0x%08x)\n"
            "\n"
            " Options:\n"
            "  -g <group-id>    Consumer group id\n"
            "  -B <batch-size>  How many messages to batch (default: 100).\n"
            "  -T <batch-tmout> How long to wait for batch-size to accumulate in milliseconds. (default 1000 ms)\n"
            "  -b <brokers>    Broker address (localhost:9092)\n"
            "  -X <prop=name>  Set arbitrary librdkafka configuration property\n"
            "\n",
            argv[0],
            RdKafka::version_str().c_str(), RdKafka::version());
        exit(1);
  }


  signal(SIGINT, sigterm);
  signal(SIGTERM, sigterm);

  /* Create consumer */
  RdKafka::KafkaConsumer *consumer = RdKafka::KafkaConsumer::create(conf, errstr);
  if (!consumer) {
    std::cerr << "Failed to create consumer: " << errstr << std::endl;
    exit(1);
  }

  delete conf;

  /* Subscribe to topics */
  RdKafka::ErrorCode err = consumer->subscribe(topics);
  if (err) {
    std::cerr << "Failed to subscribe to " << topics.size() << " topics: "
              << RdKafka::err2str(err) << std::endl;
    exit(1);
  }

  /* Consume messages in batches of \p batch_size */
  while (run) {
    auto msgs = consume_batch(consumer, batch_size, batch_tmout);
    std::cout << "Accumulated " << msgs.size() << " messages:" << std::endl;

    for (auto &msg : msgs) {
      std::cout << " Message in " << msg->topic_name() << " [" << msg->partition() << "] at offset " << msg->offset() << std::endl;
      delete msg;
    }
  }

  /* Close and destroy consumer */
  consumer->close();
  delete consumer;

  return 0;
}
