/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2021, Magnus Edenhill
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
 * OpenSSL engine integration example. This example fetches metadata
 * over SSL connection with broker, established using OpenSSL engine.
 */

#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <csignal>
#include <cstring>

#ifdef _WIN32
#include "../win32/wingetopt.h"
#elif _AIX
#include <unistd.h>
#else
#include <getopt.h>
#endif

/*
 * Typically include path in a real application would be
 * #include <librdkafka/rdkafkacpp.h>
 */
#include "rdkafkacpp.h"

static void metadata_print(const RdKafka::Metadata *metadata) {
  std::cout << "Number of topics: " << metadata->topics()->size() << std::endl;

  /* Iterate topics */
  RdKafka::Metadata::TopicMetadataIterator it;
  for (it = metadata->topics()->begin(); it != metadata->topics()->end(); ++it)
    std::cout << "  " << (*it)->topic() << " has "
              << (*it)->partitions()->size() << " partitions." << std::endl;
}


class PrintingSSLVerifyCb : public RdKafka::SslCertificateVerifyCb {
  /* This SSL cert verification callback simply prints the incoming
   * parameters. It provides no validation, everything is ok. */
 public:
  bool ssl_cert_verify_cb(const std::string &broker_name,
                          int32_t broker_id,
                          int *x509_error,
                          int depth,
                          const char *buf,
                          size_t size,
                          std::string &errstr) {
    std::cout << "ssl_cert_verify_cb :"
              << ": broker_name=" << broker_name << ", broker_id=" << broker_id
              << ", x509_error=" << *x509_error << ", depth=" << depth
              << ", buf size=" << size << std::endl;

    return true;
  }
};


int main(int argc, char **argv) {
  std::string brokers;
  std::string errstr;
  std::string engine_path;
  std::string ca_location;

  /*
   * Create configuration objects
   */
  RdKafka::Conf *conf = RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL);
  std::string engine_id;
  std::string engine_callback_data;
  int opt;

  if (conf->set("security.protocol", "ssl", errstr) != RdKafka::Conf::CONF_OK) {
    std::cerr << errstr << std::endl;
    exit(1);
  }

  while ((opt = getopt(argc, argv, "b:p:c:t:d:i:e:X:")) != -1) {
    switch (opt) {
    case 'b':
      brokers = optarg;
      break;
    case 'p':
      engine_path = optarg;
      break;
    case 'c':
      ca_location = optarg;
      break;
    case 'i':
      engine_id = optarg;
      break;
    case 'e':
      engine_callback_data = optarg;
      break;
    case 'd':
      if (conf->set("debug", optarg, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
      }
      break;
    case 'X': {
      char *name, *val;

      name = optarg;
      if (!(val = strchr(name, '='))) {
        std::cerr << "%% Expected -X property=value, not " << name << std::endl;
        exit(1);
      }

      *val = '\0';
      val++;

      if (conf->set(name, val, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        exit(1);
      }
    } break;

    default:
      goto usage;
    }
  }

  if (brokers.empty() || engine_path.empty() || optind != argc) {
  usage:
    std::string features;
    conf->get("builtin.features", features);
    fprintf(stderr,
            "Usage: %s [options] -b <brokers> -p <engine-path> \n"
            "\n"
            "OpenSSL engine integration example. This example fetches\n"
            "metadata over SSL connection with broker, established using\n"
            "OpenSSL engine.\n"
            "\n"
            "librdkafka version %s (0x%08x, builtin.features \"%s\")\n"
            "\n"
            " Options:\n"
            "  -b <brokers>              Broker address\n"
            "  -p <engine-path>          Path to OpenSSL engine\n"
            "  -i <engine-id>            OpenSSL engine id\n"
            "  -e <engine-callback-data> OpenSSL engine callback_data\n"
            "  -c <ca-cert-location>     File path to ca cert\n"
            "  -d [facs..]               Enable debugging contexts: %s\n"
            "  -X <prop=name>            Set arbitrary librdkafka configuration"
            " property\n"
            "\n",
            argv[0], RdKafka::version_str().c_str(), RdKafka::version(),
            features.c_str(), RdKafka::get_debug_contexts().c_str());
    exit(1);
  }

  if (conf->set("bootstrap.servers", brokers, errstr) !=
      RdKafka::Conf::CONF_OK) {
    std::cerr << errstr << std::endl;
    exit(1);
  }

  if (conf->set("ssl.engine.location", engine_path, errstr) !=
      RdKafka::Conf::CONF_OK) {
    std::cerr << errstr << std::endl;
    exit(1);
  }

  if (ca_location.length() > 0 && conf->set("ssl.ca.location", ca_location,
                                            errstr) != RdKafka::Conf::CONF_OK) {
    std::cerr << errstr << std::endl;
    exit(1);
  }

  if (engine_id.length() > 0 &&
      conf->set("ssl.engine.id", engine_id, errstr) != RdKafka::Conf::CONF_OK) {
    std::cerr << errstr << std::endl;
    exit(1);
  }

  /* engine_callback_data needs to be persistent
   * and outlive the lifetime of the Kafka client handle. */
  if (engine_callback_data.length() > 0 &&
      conf->set_engine_callback_data((void *)engine_callback_data.c_str(),
                                     errstr) != RdKafka::Conf::CONF_OK) {
    std::cerr << errstr << std::endl;
    exit(1);
  }

  /* We use the Certificiate verification callback to print the
   * certificate name being used. */
  PrintingSSLVerifyCb ssl_verify_cb;

  if (conf->set("ssl_cert_verify_cb", &ssl_verify_cb, errstr) !=
      RdKafka::Conf::CONF_OK) {
    std::cerr << errstr << std::endl;
    exit(1);
  }

  /*
   * Create producer using accumulated global configuration.
   */
  RdKafka::Producer *producer = RdKafka::Producer::create(conf, errstr);
  if (!producer) {
    std::cerr << "Failed to create producer: " << errstr << std::endl;
    exit(1);
  }

  std::cout << "% Created producer " << producer->name() << std::endl;

  class RdKafka::Metadata *metadata;

  /* Fetch metadata */
  RdKafka::ErrorCode err = producer->metadata(true, NULL, &metadata, 5000);
  if (err != RdKafka::ERR_NO_ERROR)
    std::cerr << "%% Failed to acquire metadata: " << RdKafka::err2str(err)
              << std::endl;

  metadata_print(metadata);

  delete metadata;
  delete producer;
  delete conf;

  return 0;
}
