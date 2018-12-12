librdkafka - the Apache Kafka C/C++ client library
==================================================

Copyright (c) 2012-2018, [Magnus Edenhill](http://www.edenhill.se/).

[https://github.com/edenhill/librdkafka](https://github.com/edenhill/librdkafka)

[![Gitter chat](https://badges.gitter.im/edenhill/librdkafka.png)](https://gitter.im/edenhill/librdkafka) [![Build status](https://doozer.io/badge/edenhill/librdkafka/buildstatus/master)](https://doozer.io/user/edenhill/librdkafka)


**librdkafka** is a C library implementation of the
[Apache Kafka](http://kafka.apache.org/) protocol, containing both
Producer and Consumer support. It was designed with message delivery reliability
and high performance in mind, current figures exceed 1 million msgs/second for
the producer and 3 million msgs/second for the consumer.

**librdkafka** is licensed under the 2-clause BSD license.

For an introduction to the performance and usage of librdkafka, see
[INTRODUCTION.md](https://github.com/edenhill/librdkafka/blob/master/INTRODUCTION.md)

See the [wiki](https://github.com/edenhill/librdkafka/wiki) for a FAQ.

**NOTE**: The `master` branch is actively developed, use latest release for production use.


# Overview #
  * High-level producer
  * High-level balanced KafkaConsumer (requires broker >= 0.9)
  * Simple (legacy) consumer
  * Compression: snappy, gzip, lz4
  * [SSL](https://github.com/edenhill/librdkafka/wiki/Using-SSL-with-librdkafka) support
  * [SASL](https://github.com/edenhill/librdkafka/wiki/Using-SASL-with-librdkafka) (GSSAPI/Kerberos/SSPI, PLAIN, SCRAM) support
  * Broker version support: >=0.8 (see [Broker version compatibility](https://github.com/edenhill/librdkafka/wiki/Broker-version-compatibility))
  * Stable C & C++ APIs (ABI safety guaranteed for C)
  * [Statistics](https://github.com/edenhill/librdkafka/blob/master/STATISTICS.md) metrics
  * Debian package: librdkafka1 and librdkafka-dev in Debian and Ubuntu
  * RPM package: librdkafka and librdkafka-devel
  * Gentoo package: dev-libs/librdkafka
  * Portable: runs on Linux, OSX, Win32, Solaris, FreeBSD, AIX, ...


# Language bindings #

  * C#/.NET: [confluent-kafka-dotnet](https://github.com/confluentinc/confluent-kafka-dotnet) (based on [rdkafka-dotnet](https://github.com/ah-/rdkafka-dotnet))
  * C++: [cppkafka](https://github.com/mfontanini/cppkafka)
  * D (C-like): [librdkafka](https://github.com/DlangApache/librdkafka/)
  * D (C++-like): [librdkafkad](https://github.com/tamediadigital/librdkafka-d)
  * Erlang: [erlkaf](https://github.com/silviucpp/erlkaf)
  * Go: [confluent-kafka-go](https://github.com/confluentinc/confluent-kafka-go)
  * Haskell (kafka, conduit, avro, schema registry): [hw-kafka](https://github.com/haskell-works/hw-kafka)
  * Haskell: [haskakafka](https://github.com/cosbynator/haskakafka)
  * Haskell: [haskell-kafka](https://github.com/yanatan16/haskell-kafka)
  * Lua: [luardkafka](https://github.com/mistsv/luardkafka)
  * Node.js: [node-rdkafka](https://github.com/Blizzard/node-rdkafka)
  * Node.js: [node-kafka](https://github.com/sutoiku/node-kafka)
  * Node.js: [kafka-native](https://github.com/jut-io/node-kafka-native)
  * OCaml: [ocaml-kafka](https://github.com/didier-wenzek/ocaml-kafka)
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
  * [rsyslog](http://www.rsyslog.com)
  * [syslog-ng](http://syslog-ng.org)
  * [collectd](http://collectd.org)
  * [logkafka](https://github.com/Qihoo360/logkafka) - Collect logs and send to Kafka
  * [redBorder](http://www.redborder.net)
  * [Headweb](http://www.headweb.com/)
  * [Produban's log2kafka](https://github.com/Produban/log2kafka) - Web log producer
  * [fuse_kafka](https://github.com/yazgoo/fuse_kafka) - FUSE file system layer
  * [node-kafkacat](https://github.com/Rafflecopter/node-kafkacat)
  * [OVH](http://ovh.com) - [AntiDDOS](http://www.slideshare.net/hugfrance/hugfr-6-oct2014ovhantiddos)
  * [otto.de](http://otto.de)'s [trackdrd](https://github.com/otto-de/trackrdrd) - Varnish log reader
  * [Microwish](https://github.com/microwish) has a range of Kafka utilites for log aggregation, HDFS integration, etc.
  * [aidp](https://github.com/weiboad/aidp) - kafka consumer embedded Lua scripting language in data process framework
  * [Yandex ClickHouse](https://github.com/yandex/ClickHouse)
  * [NXLog](http://nxlog.co/) - Enterprise logging system, Kafka input/output plugin.
  * large unnamed financial institutions
  * and many more..
  * *Let [me](mailto:rdkafka@edenhill.se) know if you are using librdkafka*



# Usage

## Requirements
	The GNU toolchain
	GNU make
   	pthreads
	zlib-dev (optional, for gzip compression support)
	libssl-dev (optional, for SSL and SASL SCRAM support)
	libsasl2-dev (optional, for SASL GSSAPI support)

## Instructions

### Building

      ./configure
      make
      sudo make install


**NOTE**: See [README.win32](README.win32) for instructions how to build
          on Windows with Microsoft Visual Studio.

**NOTE**: See [CMake instructions](packaging/cmake/README.md) for experimental
          CMake build (unsupported).


### Usage in code

See [examples/rdkafka_example.c](https://github.com/edenhill/librdkafka/blob/master/examples/rdkafka_example.c) for an example producer and consumer.

Link your program with `-lrdkafka -lz -lpthread -lrt`.


## Documentation

The public APIs are documented in their respective header files:
 * The **C** API is documented in [src/rdkafka.h](src/rdkafka.h)
 * The **C++** API is documented in [src-cpp/rdkafkacpp.h](src-cpp/rdkafkacpp.h)

To generate Doxygen documents for the API, type:

    make docs


Configuration properties are documented in
[CONFIGURATION.md](https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md)

For a librdkafka introduction, see
[INTRODUCTION.md](https://github.com/edenhill/librdkafka/blob/master/INTRODUCTION.md)


## Examples

See the `examples/`sub-directory.


## Tests

See the `tests/`sub-directory.


## Support

File bug reports, feature requests and questions using
[GitHub Issues](https://github.com/edenhill/librdkafka/issues)


Questions and discussions are also welcome on irc.freenode.org, #apache-kafka,
nickname Snaps.


### Commercial support

Commercial support is available from [Edenhill services](http://www.edenhill.se)
