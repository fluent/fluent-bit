librdkafka - the Apache Kafka C/C++ client library
==================================================

Copyright (c) 2012-2019, [Magnus Edenhill](http://www.edenhill.se/).

[https://github.com/edenhill/librdkafka](https://github.com/edenhill/librdkafka)

**librdkafka** is a C library implementation of the
[Apache Kafka](https://kafka.apache.org/) protocol, providing Producer, Consumer
and Admin clients. It was designed with message delivery reliability
and high performance in mind, current figures exceed 1 million msgs/second for
the producer and 3 million msgs/second for the consumer.

**librdkafka** is licensed under the 2-clause BSD license.

# Features #
  * High-level producer
  * High-level balanced KafkaConsumer (requires broker >= 0.9)
  * Simple (legacy) consumer
  * Admin client
  * Compression: snappy, gzip, lz4, zstd
  * [SSL](https://github.com/edenhill/librdkafka/wiki/Using-SSL-with-librdkafka) support
  * [SASL](https://github.com/edenhill/librdkafka/wiki/Using-SASL-with-librdkafka) (GSSAPI/Kerberos/SSPI, PLAIN, SCRAM, OAUTHBEARER) support
  * Full list of [supported KIPs](INTRODUCTION.md#supported-kips)
  * Broker version support: >=0.8 (see [Broker version compatibility](INTRODUCTION.md#broker-version-compatibility))
  * Guaranteed API stability for C & C++ APIs (ABI safety guaranteed for C)
  * [Statistics](STATISTICS.md) metrics
  * Debian package: librdkafka1 and librdkafka-dev in Debian and Ubuntu
  * RPM package: librdkafka and librdkafka-devel
  * Gentoo package: dev-libs/librdkafka
  * Portable: runs on Linux, OSX, Win32, Solaris, FreeBSD, AIX, ...

# Documentation

 * Public API in [C header](src/rdkafka.h) and [C++ header](src-cpp/rdkafkacpp.h).
 * Introduction and manual in [INTRODUCTION.md](https://github.com/edenhill/librdkafka/blob/master/INTRODUCTION.md).
 * Configuration properties in
[CONFIGURATION.md](https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md).
 * Statistics metrics in [STATISTICS.md](https://github.com/edenhill/librdkafka/blob/master/STATISTICS.md).
 * [Frequently asked questions](https://github.com/edenhill/librdkafka/wiki).

**NOTE**: The `master` branch is actively developed, use latest [release](https://github.com/edenhill/librdkafka/releases) for production use.


# Installation

## Installing prebuilt packages

On Mac OSX, install librdkafka with homebrew:

```bash
$ brew install librdkafka
```

On Debian and Ubuntu, install librdkafka from the Confluent APT repositories,
see instructions [here](https://docs.confluent.io/current/installation/installing_cp/deb-ubuntu.html#get-the-software) and then install librdkafka:

 ```bash
 $ apt install librdkafka-dev
 ```

On RedHat, CentOS, Fedora, install librdkafka from the Confluent YUM repositories,
instructions [here](https://docs.confluent.io/current/installation/installing_cp/rhel-centos.html#get-the-software) and then install librdkafka:

```bash
$ yum install librdkafka-devel
```

On Windows, reference [librdkafka.redist](https://www.nuget.org/packages/librdkafka.redist/) NuGet package in your Visual Studio project.


For other platforms, follow the source building instructions below.


## Build from source

### Requirements
	The GNU toolchain
	GNU make
   	pthreads
	zlib-dev (optional, for gzip compression support)
	libssl-dev (optional, for SSL and SASL SCRAM support)
	libsasl2-dev (optional, for SASL GSSAPI support)
	libzstd-dev (optional, for ZStd compression support)

**NOTE**: Static linking of ZStd (requires zstd >= 1.2.1) in the producer
          enables encoding the original size in the compression frame header,
          which will speed up the consumer.
          Use `STATIC_LIB_zstd=/path/to/libzstd.a ./configure --enable-static`
          to enable static ZStd linking.
          MacOSX example:
          `STATIC_LIB_zstd=$(brew ls -v zstd | grep libzstd.a$) ./configure --enable-static`


### Building

      ./configure
      # Or, to automatically install dependencies using the system's package manager:
      # ./configure --install-deps
      # Or, build dependencies from source:
      # ./configure --install-deps --source-deps-only

      make
      sudo make install


**NOTE**: See [README.win32](README.win32) for instructions how to build
          on Windows with Microsoft Visual Studio.

**NOTE**: See [CMake instructions](packaging/cmake/README.md) for experimental
          CMake build (unsupported).


## Usage in code

1. Refer to the [examples directory](examples/) for code using:

* Producers: basic producers, idempotent producers
* Consumers: basic consumers, reading batches of messages
* Performance tester

2. Refer to the [examples GitHub repo](https://github.com/confluentinc/examples/tree/master/clients/cloud/c) for code connecting to a cloud streaming data service based on Apache Kafka

3. Link your program with `-lrdkafka` (C) or `-lrdkafka++` (C++).


## Commercial support

Commercial support is available from [Confluent Inc](https://www.confluent.io/)


## Community support

**Only the [last official release](https://github.com/edenhill/librdkafka/releases) is supported for community members.**

File bug reports, feature requests and questions using
[GitHub Issues](https://github.com/edenhill/librdkafka/issues)

Questions and discussions are also welcome on the [Confluent Community slack](https://launchpass.com/confluentcommunity) #clients channel, or irc.freenode.org #apache-kafka channel.


# Language bindings #

  * C#/.NET: [confluent-kafka-dotnet](https://github.com/confluentinc/confluent-kafka-dotnet) (based on [rdkafka-dotnet](https://github.com/ah-/rdkafka-dotnet))
  * C++: [cppkafka](https://github.com/mfontanini/cppkafka)
  * Common Lisp: [cl-rdkafka](https://github.com/SahilKang/cl-rdkafka)
  * D (C-like): [librdkafka](https://github.com/DlangApache/librdkafka/)
  * D (C++-like): [librdkafkad](https://github.com/tamediadigital/librdkafka-d)
  * Erlang: [erlkaf](https://github.com/silviucpp/erlkaf)
  * Go: [confluent-kafka-go](https://github.com/confluentinc/confluent-kafka-go)
  * Haskell (kafka, conduit, avro, schema registry): [hw-kafka](https://github.com/haskell-works/hw-kafka)
  * Lua: [luardkafka](https://github.com/mistsv/luardkafka)
  * Node.js: [node-rdkafka](https://github.com/Blizzard/node-rdkafka)
  * OCaml: [ocaml-kafka](https://github.com/didier-wenzek/ocaml-kafka)
  * Perl: [Net::Kafka](https://github.com/bookingcom/perl-Net-Kafka)
  * PHP: [phpkafka](https://github.com/EVODelavega/phpkafka)
  * PHP: [php-rdkafka](https://github.com/arnaud-lb/php-rdkafka)
  * Python: [confluent-kafka-python](https://github.com/confluentinc/confluent-kafka-python)
  * Python: [PyKafka](https://github.com/Parsely/pykafka)
  * Ruby: [Hermann](https://github.com/reiseburo/hermann)
  * Ruby: [rdkafka-ruby](https://github.com/appsignal/rdkafka-ruby)
  * Rust: [rust-rdkafka](https://github.com/fede1024/rust-rdkafka)
  * Tcl: [KafkaTcl](https://github.com/flightaware/kafkatcl)
  * Swift: [Perfect-Kafka](https://github.com/PerfectlySoft/Perfect-Kafka)

# Users of librdkafka #

  * [kafkacat](https://github.com/edenhill/kafkacat) - Apache Kafka swiss army knife
  * [Wikimedia's varnishkafka](https://github.com/wikimedia/varnishkafka) - Varnish cache web log producer
  * [Wikimedia's kafkatee](https://github.com/wikimedia/analytics-kafkatee) - Kafka multi consumer with filtering and fanout
  * [rsyslog](https://www.rsyslog.com)
  * [syslog-ng](https://www.syslog-ng.com)
  * [collectd](https://collectd.org)
  * [logkafka](https://github.com/Qihoo360/logkafka) - Collect logs and send to Kafka
  * [redBorder](https://redborder.com)
  * [Headweb](http://www.headweb.com/)
  * [Produban's log2kafka](https://github.com/Produban/log2kafka) - Web log producer
  * [fuse_kafka](https://github.com/yazgoo/fuse_kafka) - FUSE file system layer
  * [node-kafkacat](https://github.com/Rafflecopter/node-kafkacat)
  * [OVH](https://ovh.com) - [AntiDDOS](https://www.slideshare.net/hugfrance/hugfr-6-oct2014ovhantiddos)
  * [otto.de](https://www.otto.de)'s [trackdrd](https://github.com/otto-de/trackrdrd) - Varnish log reader
  * [Microwish](https://github.com/microwish) has a range of Kafka utilites for log aggregation, HDFS integration, etc.
  * [aidp](https://github.com/weiboad/aidp) - kafka consumer embedded Lua scripting language in data process framework
  * [Yandex ClickHouse](https://github.com/yandex/ClickHouse)
  * [NXLog](https://nxlog.co/) - Enterprise logging system, Kafka input/output plugin.
  * large unnamed financial institutions
  * and many more..
  * *Let [me](mailto:rdkafka@edenhill.se) know if you are using librdkafka*
