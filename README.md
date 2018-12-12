![](fluentbit_logo.png)

[![Build Status](https://travis-ci.org/fluent/fluent-bit.svg?branch=master)](https://travis-ci.org/fluent/fluent-bit)

[Fluent Bit](http://fluentbit.io) is a Data Forwarder for Linux, Embedded Linux, OSX and BSD family operating systems. It's part of the [Fluentd](http://fluentd.org) Ecosystem.  Fluent Bit allows collection of information from different sources, buffering and dispatching them to different outputs such as [Fluentd](http://fluentd.org), Elasticsearch, Nats or any HTTP end-point within others. It's fully supported on x86_64, x86 and ARM architectures.

For more details about it capabilities and general features please visit the official documentation:

https://docs.fluentbit.io/

## Quick Start

```
$ cd build
$ cmake ..
$ make
$ bin/fluent-bit -i cpu -o stdout
```

## Features

[Fluent Bit](http://fluentbit.io) support the following features through plugins:

### Input plugins

| name               | option  | description  |
|--------------------|---------|---------------------------------------------------------------------------------|
| CPU                | cpu     | gather CPU usage between snapshots of one second. It support multiple cores     |
| Disk               | disk    | usage of block device |
| Dummy              | dummy   | generates dummy event |
| Exec               | exec    | executes external program and collects event logs |
| Forward            | forward | [Fluentd](http://fluentd.org) forward protocol |
| Memory             | mem     | usage of system memory |
| MQTT               | mqtt    | start a MQTT server and receive publish messages |
| Netif              | netif   | usage of network interface |
| Kernel Ring Buffer | kmsg    | read Linux Kernel messages, same behavior as the __dmesg__ command line program |
| Syslog             | syslog  | read messages from a syslog daemon |
| Systemd/Journald   | systemd | read messages from journald, part of the systemd suite |
| Serial Port        | serial  | read from serial port |
| Standard Input     | stdin   | read from the standard input |
| Head               | head    | read first part of files |
| Health             | health  | check health of TCP services|
| Process            | proc    | check health of Process |
| Random             | random  | generate random numbers |
| Tail               | tail    | tail log files |
| TCP                | tcp     | listen for raw JSON map messages over TCP |

### Filter Plugins

| name               | option     | description  |
|--------------------|------------|---------------------------------------------------------------------------------|
| Record Modifier    | record_modifier | Append/Remove key-value pair |
| Grep               | grep       | Match or exclude specific records by patterns |
| Nest               | nest       | Nest specific records by patterns |
| Kubernetes         | kubernetes | Enrich logs with Kubernetes Metadata |
| Stdout             | stdout     | Print records to the standard output interface |
| Parser             | parser     | Parse records |


### Output Plugins

| name               | option                  | description  |
|--------------------|-------------------------|---------------------------------------------------------------------------------|
| Counter            | counter | count records |
| Elasticsearch      | es | flush records to a Elasticsearch server |
| File               | file | flush records to a file |
| FlowCounter        | flowcounter| count records and its size |
| Forward            | forward  | flush records to a [Fluentd](http://fluentd.org) service. On the [Fluentd](http://fluentd.org) side, it requires an __in_forward__.|
| NATS               | nats | flush records to a NATS server |
| HTTP               | http | flush records to a HTTP end point |
| InfluxDB           | influxdb | flush records to InfluxDB time series database |
| Plot               | plot | generate a file for gnuplot |
| Standard Output    | stdout                  | prints the records to the standard output stream |
| Treasure Data      | td                      | flush records to [Treasure Data](http://treasuredata.com) service (cloud analytics)|

## Official Documentation

The official documentation of [Fluent Bit](http://fluentbit.io) can be found in the following site:

http://fluentbit.io/documentation/

## Contributing

In order to contribute to the project please refer to the [CONTRIBUTING](CONTRIBUTING.md) guidelines.

## Contact

Feel free to join us on our Slack channel, Mailing List or IRC:

 - Slack: http://slack.fluentd.org (#fluent-bit channel)
 - Mailing List: https://groups.google.com/forum/#!forum/fluent-bit
 - IRC: irc.freenode.net #fluent-bit
 - Twitter: http://twitter.com/fluentbit

## License

This program is under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Authors

[Fluent Bit](http://fluentbit.io) is made and sponsored by [Treasure Data](http://treasuredata.com) among
other [contributors](https://github.com/fluent/fluent-bit/graphs/contributors).
