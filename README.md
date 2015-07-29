# Fluent Bit

[Fluent Bit](http://fluentbit.io) is an events collector for Linux, Embedded Linux, OSX and BSD family operating systems. It's part of the [Fluentd](http://fluentd.org) project ecosystem, it allows to collects information from different sources, package and dispatch them to different outputs such as [Fluentd](http://fluentd.org). It have a strong focus on Embedded & IoT environments.

## Features

[Fluent Bit](http://fluentbit.io) support the following features through plugins:

### Input plugins

| name               | option  | description  |
|--------------------|---------|---------------------------------------------------------------------------------|
| CPU                | cpu     | gather CPU usage between snapshots of one second. It support multiple cores     |
| Memory             | mem     | usage of system memory |
| Kernel Ring Buffer | kmsg    | read Linux Kernel messages, same behavior as the __dmesg__ command line program |
| Serial Port        | serial  | read from serial port |
| Standard Input     | stdin   | read from the standard input |
| XBee               | xbee    | listen for incoming messages over a Xbee device |

### Output Plugins

| name               | option                  | description  |
|--------------------|-------------------------|---------------------------------------------------------------------------------|
| Fluentd            | fluentd://host:port     | flush content to a [Fluentd](http://fluentd.org) service. On the [Fluentd](http://fluentd.org) side, it requires an __in_forward__.|
| Standard Output    | stdout                  | prints the collected data to standard output stream |

## Documentation

The official documentation of [Fluent Bit](http://fluentbit.io) can be found in the following site:

http://fluentbit.io/documentation

Or you can browse directly on this repository [here](documentation/SUMMARY.md)

## Contributing

In order to contribute to the project please refer to the [CONTRIBUTING](CONTRIBUTING.md) guidelines.

## Contact

Feel free to join us on our Mailing List or IRC:

 - Mailing List: https://groups.google.com/forum/#!forum/fluent-bit
 - IRC: irc.freenode.net #fluent-bit

## License

This program is under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Authors

[Fluent Bit](http://fluentbit.io) is made and sponsored by [Treasure Data](http://treasuredata.com) among
other [contributors](https://github.com/fluent/fluent-bit/graphs/contributors).
