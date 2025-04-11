/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2014-2022, Magnus Edenhill
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
 * (https://github.com/confluentinc/librdkafka)
 */

#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <csignal>
#include <cstring>

#ifndef _WIN32
#include <sys/time.h>
#else
#include <windows.h> /* for GetLocalTime */
#endif

#ifdef _MSC_VER
#include "../win32/wingetopt.h"
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
static bool exit_eof             = false;
static int eof_cnt               = 0;
static int partition_cnt         = 0;
static int verbosity             = 1;
static long msg_cnt              = 0;
static int64_t msg_bytes         = 0;
static void sigterm(int sig) {
  run = 0;
}


/**
 * @brief format a string timestamp from the current time
 */
static void print_time() {
#ifndef _WIN32
  struct timeval tv;
  char buf[64];
  gettimeofday(&tv, NULL);
  strftime(buf, sizeof(buf) - 1, "%Y-%m-%d %H:%M:%S", localtime(&tv.tv_sec));
  fprintf(stderr, "%s.%03d: ", buf, (int)(tv.tv_usec / 1000));
#else
  SYSTEMTIME lt = {0};
  GetLocalTime(&lt);
  // %Y-%m-%d %H:%M:%S.xxx:
  fprintf(stderr, "%04d-%02d-%02d %02d:%02d:%02d.%03d: ", lt.wYear, lt.wMonth,
          lt.wDay, lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);
#endif
}
class ExampleEventCb : public RdKafka::EventCb {
 public:
  void event_cb(RdKafka::Event &event) {
    print_time();

    switch (event.type()) {
    case RdKafka::Event::EVENT_ERROR:
      if (event.fatal()) {
        std::cerr << "FATAL ";
        run = 0;
      }
      std::cerr << "ERROR (" << RdKafka::err2str(event.err())
                << "): " << event.str() << std::endl;
      break;

    case RdKafka::Event::EVENT_STATS:
      std::cerr << "\"STATS\": " << event.str() << std::endl;
      break;

    case RdKafka::Event::EVENT_LOG:
      fprintf(stderr, "LOG-%i-%s: %s\n", event.severity(), event.fac().c_str(),
              event.str().c_str());
      break;

    case RdKafka::Event::EVENT_THROTTLE:
      std::cerr << "THROTTLED: " << event.throttle_time() << "ms by "
                << event.broker_name() << " id " << (int)event.broker_id()
                << std::endl;
      break;

    default:
      std::cerr << "EVENT " << event.type() << " ("
                << RdKafka::err2str(event.err()) << "): " << event.str()
                << std::endl;
      break;
    }
  }
};


class ExampleRebalanceCb : public RdKafka::RebalanceCb {
 private:
  static void part_list_print(
      const std::vector<RdKafka::TopicPartition *> &partitions) {
    for (unsigned int i = 0; i < partitions.size(); i++)
      std::cerr << partitions[i]->topic() << "[" << partitions[i]->partition()
                << "], ";
    std::cerr << "\n";
  }

 public:
  void rebalance_cb(RdKafka::KafkaConsumer *consumer,
                    RdKafka::ErrorCode err,
                    std::vector<RdKafka::TopicPartition *> &partitions) {
    std::cerr << "RebalanceCb: " << RdKafka::err2str(err) << ": ";

    part_list_print(partitions);

    RdKafka::Error *error      = NULL;
    RdKafka::ErrorCode ret_err = RdKafka::ERR_NO_ERROR;

    if (err == RdKafka::ERR__ASSIGN_PARTITIONS) {
      if (consumer->rebalance_protocol() == "COOPERATIVE")
        error = consumer->incremental_assign(partitions);
      else
        ret_err = consumer->assign(partitions);
      partition_cnt += (int)partitions.size();
    } else {
      if (consumer->rebalance_protocol() == "COOPERATIVE") {
        error = consumer->incremental_unassign(partitions);
        partition_cnt -= (int)partitions.size();
      } else {
        ret_err       = consumer->unassign();
        partition_cnt = 0;
      }
    }
    eof_cnt = 0; /* FIXME: Won't work with COOPERATIVE */

    if (error) {
      std::cerr << "incremental assign failed: " << error->str() << "\n";
      delete error;
    } else if (ret_err)
      std::cerr << "assign failed: " << RdKafka::err2str(ret_err) << "\n";
  }
};


void msg_consume(RdKafka::Message *message, void *opaque) {
  switch (message->err()) {
  case RdKafka::ERR__TIMED_OUT:
    break;

  case RdKafka::ERR_NO_ERROR:
    /* Real message */
    msg_cnt++;
    msg_bytes += message->len();
    if (verbosity >= 3)
      std::cerr << "Read msg at offset " << message->offset() << std::endl;
    RdKafka::MessageTimestamp ts;
    ts = message->timestamp();
    if (verbosity >= 2 &&
        ts.type != RdKafka::MessageTimestamp::MSG_TIMESTAMP_NOT_AVAILABLE) {
      std::string tsname = "?";
      if (ts.type == RdKafka::MessageTimestamp::MSG_TIMESTAMP_CREATE_TIME)
        tsname = "create time";
      else if (ts.type ==
               RdKafka::MessageTimestamp::MSG_TIMESTAMP_LOG_APPEND_TIME)
        tsname = "log append time";
      std::cout << "Timestamp: " << tsname << " " << ts.timestamp << std::endl;
    }
    if (verbosity >= 2 && message->key()) {
      std::cout << "Key: " << *message->key() << std::endl;
    }
    if (verbosity >= 1) {
      printf("%.*s\n", static_cast<int>(message->len()),
             static_cast<const char *>(message->payload()));
    }
    break;

  case RdKafka::ERR__PARTITION_EOF:
    /* Last message */
    if (exit_eof && ++eof_cnt == partition_cnt) {
      std::cerr << "%% EOF reached for all " << partition_cnt << " partition(s)"
                << std::endl;
      run = 0;
    }
    break;

  case RdKafka::ERR__UNKNOWN_TOPIC:
  case RdKafka::ERR__UNKNOWN_PARTITION:
    std::cerr << "Consume failed: " << message->errstr() << std::endl;
    run = 0;
    break;

  default:
    /* Errors */
    std::cerr << "Consume failed: " << message->errstr() << std::endl;
    run = 0;
  }
}

int main(int argc, char **argv) {
  std::string brokers = "localhost";
  std::string errstr;
  std::string topic_str;
  std::string mode;
  std::string debug;
  std::vector<std::string> topics;
  bool do_conf_dump = false;
  int opt;

  /*
   * Create configuration objects
   */
  RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);

  ExampleRebalanceCb ex_rebalance_cb;
  conf->set("rebalance_cb", &ex_rebalance_cb, errstr);

  conf->set("enable.partition.eof", "true", errstr);

  while ((opt = getopt(argc, argv, "g:b:z:qd:eX:AM:qv")) != -1) {
    switch (opt) {
    case 'g':
      if (conf->set("group.id", optarg, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
      }
      break;
    case 'b':
      brokers = optarg;
      break;
    case 'z':
      if (conf->set("compression.codec", optarg, errstr) !=
          RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
      }
      break;
    case 'e':
      exit_eof = true;
      break;
    case 'd':
      debug = optarg;
      break;
    case 'M':
      if (conf->set("statistics.interval.ms", optarg, errstr) !=
          RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
      }
      break;
    case 'X': {
      char *name, *val;

      if (!strcmp(optarg, "dump")) {
        do_conf_dump = true;
        continue;
      }

      name = optarg;
      if (!(val = strchr(name, '='))) {
        std::cerr << "%% Expected -X property=value, not " << name << std::endl;
        exit(1);
      }

      *val = '\0';
      val++;

      RdKafka::Conf::ConfResult res = conf->set(name, val, errstr);
      if (res != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
      }
    } break;

    case 'q':
      verbosity--;
      break;

    case 'v':
      verbosity++;
      break;

    default:
      goto usage;
    }
  }

  for (; optind < argc; optind++)
    topics.push_back(std::string(argv[optind]));

  if (topics.empty() || optind != argc) {
  usage:
    fprintf(stderr,
            "Usage: %s -g <group-id> [options] topic1 topic2..\n"
            "\n"
            "librdkafka version %s (0x%08x)\n"
            "\n"
            " Options:\n"
            "  -g <group-id>   Consumer group id\n"
            "  -b <brokers>    Broker address (localhost:9092)\n"
            "  -z <codec>      Enable compression:\n"
            "                  none|gzip|snappy\n"
            "  -e              Exit consumer when last message\n"
            "                  in partition has been received.\n"
            "  -d [facs..]     Enable debugging contexts:\n"
            "                  %s\n"
            "  -M <intervalms> Enable statistics\n"
            "  -X <prop=name>  Set arbitrary librdkafka "
            "configuration property\n"
            "                  Use '-X list' to see the full list\n"
            "                  of supported properties.\n"
            "  -q              Quiet / Decrease verbosity\n"
            "  -v              Increase verbosity\n"
            "\n"
            "\n",
            argv[0], RdKafka::version_str().c_str(), RdKafka::version(),
            RdKafka::get_debug_contexts().c_str());
    exit(1);
  }

  if (exit_eof) {
    std::string strategy;
    if (conf->get("partition.assignment.strategy", strategy) ==
            RdKafka::Conf::CONF_OK &&
        strategy == "cooperative-sticky") {
      std::cerr
          << "Error: this example has not been modified to "
          << "support -e (exit on EOF) when the partition.assignment.strategy "
          << "is set to " << strategy << ": remove -e from the command line\n";
      exit(1);
    }
  }

  /*
   * Set configuration properties
   */
  conf->set("metadata.broker.list", brokers, errstr);

  if (!debug.empty()) {
    if (conf->set("debug", debug, errstr) != RdKafka::Conf::CONF_OK) {
      std::cerr << errstr << std::endl;
      exit(1);
    }
  }

  ExampleEventCb ex_event_cb;
  conf->set("event_cb", &ex_event_cb, errstr);

  if (do_conf_dump) {
    std::list<std::string> *dump;
    dump = conf->dump();
    std::cout << "# Global config" << std::endl;

    for (std::list<std::string>::iterator it = dump->begin();
         it != dump->end();) {
      std::cout << *it << " = ";
      it++;
      std::cout << *it << std::endl;
      it++;
    }
    std::cout << std::endl;

    exit(0);
  }

  signal(SIGINT, sigterm);
  signal(SIGTERM, sigterm);


  /*
   * Consumer mode
   */

  /*
   * Create consumer using accumulated global configuration.
   */
  RdKafka::KafkaConsumer *consumer =
      RdKafka::KafkaConsumer::create(conf, errstr);
  if (!consumer) {
    std::cerr << "Failed to create consumer: " << errstr << std::endl;
    exit(1);
  }

  delete conf;

  std::cout << "% Created consumer " << consumer->name() << std::endl;


  /*
   * Subscribe to topics
   */
  RdKafka::ErrorCode err = consumer->subscribe(topics);
  if (err) {
    std::cerr << "Failed to subscribe to " << topics.size()
              << " topics: " << RdKafka::err2str(err) << std::endl;
    exit(1);
  }

  /*
   * Consume messages
   */
  while (run) {
    RdKafka::Message *msg = consumer->consume(1000);
    msg_consume(msg, NULL);
    delete msg;
  }

#ifndef _WIN32
  alarm(10);
#endif

  /*
   * Stop consumer
   */
  consumer->close();
  delete consumer;

  std::cerr << "% Consumed " << msg_cnt << " messages (" << msg_bytes
            << " bytes)" << std::endl;

  /*
   * Wait for RdKafka to decommission.
   * This is not strictly needed (with check outq_len() above), but
   * allows RdKafka to clean up all its resources before the application
   * exits so that memory profilers such as valgrind wont complain about
   * memory leaks.
   */
  RdKafka::wait_destroyed(5000);

  return 0;
}
