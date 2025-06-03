# ![logo](fluentbit_logo.png)

### CI Status

| CI Workflow       | Status             |
|-------------------|--------------------|
| Unit Tests (master) | [![CI/Unit Tests](https://github.com/fluent/fluent-bit/actions/workflows/unit-tests.yaml/badge.svg?branch=master)](https://github.com/fluent/fluent-bit/actions/workflows/unit-tests.yaml) |
| Integration Tests (master) | [![CI/Integration Tests](https://github.com/fluent/fluent-bit/actions/workflows/master-integration-test.yaml/badge.svg)](https://github.com/fluent/fluent-bit/actions/workflows/master-integration-test.yaml)|
| Arm builds         | <a href="https://actuated.dev/"><img alt="Arm CI sponsored by Actuated" src="https://docs.actuated.dev/images/actuated-badge.png" width="120px"></img></a> |
| Latest release |  [![CI/Build](https://github.com/fluent/fluent-bit/actions/workflows/staging-release.yaml/badge.svg)](https://github.com/fluent/fluent-bit/actions/workflows/staging-release.yaml)|

## About

![](documentation/fluentbit_ecosystem.png)

[Fluent Bit](http://fluentbit.io) is a fast Log, Metrics and Traces Processor and Forwarder for Linux, Windows, Embedded Linux, MacOS and BSD family operating systems. It's part of the Graduated [Fluentd](http://fluentd.org) Ecosystem and a [CNCF](https://cncf.io) sub-project.

Fluent Bit allows to collect different signal types such as logs, metrics and traces from different sources, process them and deliver them to different backends such as [Fluentd](http://fluentd.org), Elasticsearch, Splunk, DataDog, Kafka, New Relic, Azure services, AWS services, Google services, NATS, InfluxDB or any custom HTTP end-point.

Fluent Bit comes with full SQL [Stream Processing](https://docs.fluentbit.io/manual/stream-processing/introduction) capabilities: data manipulation and analytics using SQL queries.

Fluent Bit runs on x86_64, x86, arm32v7, and arm64v8 architectures.

## Features

- High Performance at low CPU and Memory footprint
- Data Parsing
  - Convert your unstructured messages using our parsers: [JSON](https://docs.fluentbit.io/manual/pipeline/parsers/json), [Regex](https://docs.fluentbit.io/manual/pipeline/parsers/regular-expression), [LTSV](https://docs.fluentbit.io/manual/pipeline/parsers/ltsv) and [Logfmt](https://docs.fluentbit.io/manual/pipeline/parsers/logfmt)
- Reliability and Data Integrity
  - [Backpressure](https://docs.fluentbit.io/manual/administration/backpressure) Handling
  - [Data Buffering](https://docs.fluentbit.io/manual/administration/buffering-and-storage) in memory and file system
- Networking
  - Security: built-in TLS/SSL support
  - Asynchronous I/O
- Pluggable Architecture and [Extensibility](https://docs.fluentbit.io/manual/development): Inputs, Filters and Outputs
  - More than 70 built-in plugins available
  - Extensibility
    - Write any input, filter or output plugin in C language
    - Write [Filters in Lua](https://docs.fluentbit.io/manual/filter/lua) or [Output plugins in Golang](https://docs.fluentbit.io/manual/development/golang-output-plugins)
- [Monitoring](https://docs.fluentbit.io/manual/administration/monitoring): expose internal metrics, including Fluent Bit process CPU and memory usage, over HTTP in JSON and [Prometheus](https://prometheus.io/) format
- [Stream Processing](https://docs.fluentbit.io/manual/stream-processing/introduction): Perform data selection and transformation using simple SQL queries
  - Create new streams of data using query results
  - Aggregation Windows
  - Data analysis and prediction: Timeseries forecasting
- Portable: runs on Linux, MacOS, Windows and BSD systems

## Fluent Bit in Production

Fluent Bit is a widely adopted solution in production environments. As of 2024, Fluent Bit has surpassed 15 billion downloads and continues to be deployed over 10 million times daily. Below is a preview of some of the organizations that rely heavily on Fluent Bit in their production systems:

> If your company uses Fluent Bit and is not listed, feel free to open a GitHub issue and we will add the logo.

![users](documentation/fluentbit_users.png)

## [Documentation](https://docs.fluentbit.io)

Our official project documentation for [installation](https://docs.fluentbit.io/manual/installation), [configuration](https://docs.fluentbit.io/manual/administration/configuring-fluent-bit), deployment and development topics is located here:

- [https://docs.fluentbit.io](https://fluentbit.io)

### Quick Start

#### Build from Scratch

If you aim to build Fluent Bit from sources, you can go ahead and start with the following commands.

```bash
cd build
cmake ..
make
bin/fluent-bit -i cpu -o stdout -f 1
```

If you are interested into more details, please refer to the [Build & Install](https://docs.fluentbit.io/manual/installation/sources/build-and-install) section.

#### Requirements

- CMake >= 3.0
- Flex
- Bison
- YAML library/headers
- OpenSSL library/headers

#### Linux Packages

We provide packages for most common Linux distributions:

- [Debian](https://docs.fluentbit.io/manual/installation/linux/debian)
- [Raspbian](https://docs.fluentbit.io/manual/installation/linux/raspbian-raspberry-pi)
- [Ubuntu](https://docs.fluentbit.io/manual/installation/linux/ubuntu)
- [CentOS](https://docs.fluentbit.io/manual/installation/linux/redhat-centos)

#### Linux / Docker Container Images

Our Linux containers images are the most common deployment model, thousands of
new installation happen every day, learn more about the available images and
tags [here](https://docs.fluentbit.io/manual/installation/docker).

#### Windows Packages

Fluent Bit is fully supported on Windows environments, get started with [these instructions](https://docs.fluentbit.io/manual/installation/windows).

#### Running on s390x

Fluent Bit runs on Linux on IBM Z(s390x), but the WASM filter plugin is not. For the LUA filter plugin, it runs when `libluajit` is installed on the system and fluent bit is built with `FLB_LUAJIT` and `FLB_PREFER_SYSTEM_LIB_LUAJIT` on.

### Plugins: Inputs, Filters and Outputs

[Fluent Bit](http://fluentbit.io) is based in a pluggable architecture where different plugins plays a major role in the data pipeline:

#### Input Plugins

| name | title | description |
| :--- | :--- | :--- |
| [collectd](https://docs.fluentbit.io/manual/pipeline/inputs/collectd) | Collectd | Listen for UDP packets from Collectd. |
| [cpu](https://docs.fluentbit.io/manual/pipeline/inputs/cpu-metrics) | CPU Usage | measure total CPU usage of the system. |
| [disk](https://docs.fluentbit.io/manual/pipeline/inputs/disk-io-metrics) | Disk Usage | measure Disk I/Os. |
| [dummy](https://docs.fluentbit.io/manual/pipeline/inputs/dummy) | Dummy | generate dummy event. |
| [exec](https://docs.fluentbit.io/manual/pipeline/inputs/exec) | Exec | executes external program and collects event logs. |
| [forward](https://docs.fluentbit.io/manual/pipeline/inputs/forward) | Forward | Fluentd forward protocol. |
| [head](https://docs.fluentbit.io/manual/pipeline/inputs/head) | Head | read first part of files. |
| [health](https://docs.fluentbit.io/manual/pipeline/inputs/health) | Health | Check health of TCP services. |
| [kmsg](https://docs.fluentbit.io/manual/pipeline/inputs/kernel-logs) | Kernel Log Buffer | read the Linux Kernel log buffer messages. |
| [mem](https://docs.fluentbit.io/manual/pipeline/inputs/memory-metrics) | Memory Usage | measure the total amount of memory used on the system. |
| [mqtt](https://docs.fluentbit.io/manual/pipeline/inputs/mqtt) | MQTT | start a MQTT server and receive publish messages. |
| [netif](https://docs.fluentbit.io/manual/pipeline/inputs/network-io-metrics) | Network Traffic | measure network traffic. |
| [proc](https://docs.fluentbit.io/manual/pipeline/inputs/process) | Process | Check health of Process. |
| [random](https://docs.fluentbit.io/manual/pipeline/inputs/random) | Random | Generate Random samples. |
| [serial](https://docs.fluentbit.io/manual/pipeline/inputs/serial-interface) | Serial Interface | read data information from the serial interface. |
| [stdin](https://docs.fluentbit.io/manual/pipeline/inputs/standard-input) | Standard Input | read data from the standard input. |
| [syslog](https://docs.fluentbit.io/manual/pipeline/inputs/syslog) | Syslog | read syslog messages from a Unix socket. |
| [systemd](https://docs.fluentbit.io/manual/pipeline/inputs/systemd) | Systemd | read logs from Systemd/Journald. |
| [tail](https://docs.fluentbit.io/manual/pipeline/inputs/tail) | Tail | Tail log files. |
| [tcp](https://docs.fluentbit.io/manual/pipeline/inputs/tcp) | TCP | Listen for JSON messages over TCP. |
| [thermal](https://docs.fluentbit.io/manual/pipeline/inputs/thermal) | Thermal | measure system temperature(s). |

#### Filter Plugins

| name | title | description |
| :--- | :--- | :--- |
| [aws](https://docs.fluentbit.io/manual/pipeline/filters/aws-metadata) | AWS Metadata | Enrich logs with AWS Metadata. |
| [expect](https://docs.fluentbit.io/manual/pipeline/filters/expect) | Expect | Validate records match certain criteria in structure. |
| [grep](https://docs.fluentbit.io/manual/pipeline/filters/grep) | Grep | Match or exclude specific records by patterns. |
| [kubernetes](https://docs.fluentbit.io/manual/pipeline/filters/kubernetes) | Kubernetes | Enrich logs with Kubernetes Metadata. |
| [lua](https://docs.fluentbit.io/manual/pipeline/filters/lua) | Lua | Filter records using Lua Scripts. |
| [parser](https://docs.fluentbit.io/manual/pipeline/filters/parser) | Parser | Parse record. |
| [record\_modifier](https://docs.fluentbit.io/manual/pipeline/filters/record-modifier) | Record Modifier | Modify record. |
| [rewrite\_tag](https://docs.fluentbit.io/manual/pipeline/filters/rewrite-tag) | Rewrite Tag | Re-emit records under new tag. |
| [stdout](https://docs.fluentbit.io/manual/pipeline/filters/standard-output) | Stdout | Print records to the standard output interface. |
| [throttle](https://docs.fluentbit.io/manual/pipeline/filters/throttle) | Throttle | Apply rate limit to event flow. |
| [nest](https://docs.fluentbit.io/manual/pipeline/filters/nest) | Nest | Nest records under a specified key |
| [modify](https://docs.fluentbit.io/manual/pipeline/filters/modify) | Modify | Modifications to record. |

#### Output Plugins

| name | title | description |
| :--- | :--- | :--- |
| [azure](https://docs.fluentbit.io/manual/pipeline/outputs/azure) | Azure Log Analytics | Ingest records into Azure Log Analytics |
| [bigquery](https://docs.fluentbit.io/manual/pipeline/outputs/bigquery) | BigQuery | Ingest records into Google BigQuery |
| [counter](https://docs.fluentbit.io/manual/pipeline/outputs/counter) | Count Records | Simple records counter. |
| [datadog](https://docs.fluentbit.io/manual/pipeline/outputs/datadog) | Datadog | Ingest logs into Datadog. |
| [es](https://docs.fluentbit.io/manual/pipeline/outputs/elasticsearch) | Elasticsearch | flush records to a Elasticsearch server. |
| [file](https://docs.fluentbit.io/manual/pipeline/outputs/file) | File | Flush records to a file. |
| [flowcounter](https://docs.fluentbit.io/manual/pipeline/outputs/flowcounter) | FlowCounter | Count records. |
| [forward](https://docs.fluentbit.io/manual/pipeline/outputs/forward) | Forward | Fluentd forward protocol. |
| [gelf](https://docs.fluentbit.io/manual/pipeline/outputs/gelf) | GELF | Flush records to Graylog |
| [http](https://docs.fluentbit.io/manual/pipeline/outputs/http) | HTTP | Flush records to an HTTP end point. |
| [influxdb](https://docs.fluentbit.io/manual/pipeline/outputs/influxdb) | InfluxDB | Flush records to InfluxDB time series database. |
| [kafka](https://docs.fluentbit.io/manual/pipeline/outputs/kafka) | Apache Kafka | Flush records to Apache Kafka |
| [kafka-rest](https://docs.fluentbit.io/manual/pipeline/outputs/kafka-rest-proxy) | Kafka REST Proxy | Flush records to a Kafka REST Proxy server. |
| [loki](https://docs.fluentbit.io/manual/pipeline/outputs/loki) | Loki | Flush records to Loki server. |
| [nats](https://docs.fluentbit.io/manual/pipeline/outputs/nats) | NATS | Flush records to a NATS server. |
| [null](https://docs.fluentbit.io/manual/pipeline/outputs/null) | NULL | Throw away events. |
| [s3](https://docs.fluentbit.io/manual/pipeline/outputs/s3) | S3 | Flush records to s3 |
| [stackdriver](https://docs.fluentbit.io/manual/pipeline/outputs/stackdriver) | Google Stackdriver Logging | Flush records to Google Stackdriver Logging service. |
| [stdout](https://docs.fluentbit.io/manual/pipeline/outputs/standard-output) | Standard Output | Flush records to the standard output. |
| [splunk](https://docs.fluentbit.io/manual/pipeline/outputs/splunk) | Splunk | Flush records to a Splunk Enterprise service |
| [tcp](https://docs.fluentbit.io/manual/pipeline/outputs/tcp-and-tls) | TCP & TLS | Flush records to a TCP server. |
| [td](https://docs.fluentbit.io/manual/pipeline/outputs/treasure-data) | [Treasure Data](http://www.treasuredata.com) | Flush records to the [Treasure Data](http://www.treasuredata.com) cloud service for analytics. |

## Contributing

[Fluent Bit](https://fluentbit.io) is an open project, several individuals and companies contribute in different forms like coding, documenting, testing, spreading the word at events within others. If you want to learn more about contributing opportunities please reach out to us through our [Community Channels](https://fluentbit.io/community/).

If you are interested in contributing to Fluent bit with bug fixes, new features or coding in general, please refer to the code [CONTRIBUTING](CONTRIBUTING.md) guidelines. You can also refer the Beginners Guide to contributing to Fluent Bit [here.](DEVELOPER_GUIDE.md)

## Community & Contact

Feel free to join us on our Slack channel, Mailing List or IRC:

- [Slack](http://slack.fluentd.org) (#fluent-bit channel)
- [Twitter](http://twitter.com/fluentbit)

## License

This program is under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Authors

[Fluent Bit](http://fluentbit.io) is sponsored and maintained by several companies in the Cloud Native community, including all the major cloud providers.

You can see a list of contributors [here](https://github.com/fluent/fluent-bit/graphs/contributors).

