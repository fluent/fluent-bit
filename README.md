# Fluent Bit

> The project is under active development, so changes on the API and internal mechanism are expected.

[Fluent-Bit](http://fluentbit.io) is an events collector for Embedded Linux and is part of the [Fluentd](http://fluentd.org) project ecosystem. It allows to collects information from different sources, package and dispatch them to different outputs such as [Fluentd](http://fluentd.org).

The current project builds an executable called _fluent-bit_, a shared library _libfluent-bit.so_ and a static library _libfluent-bit.a_. Please refer to the build options described below for more details.

## Build

To build _Fluent-Bit_, you need __cmake__ and a C compiler such as __GCC__ or __Clang__. If you already have the requirements proceed with the following steps:

```bash
$ cd build/
$ cmake ..
$ make
```

When building _Fluent-Bit_, the following options are available when running __cmake__:

 option     | value type | description                                 | default
------------|------------|---------------------------------------------|---------
WITH_ALL    | bool       | Enable all features available               | off
WITH_XBEE   | bool       | Enable XBee support (input)                 | off
WITH_DEBUG  | bool       | Include debug symbols when building targets | off
WITHOUT_BIN | bool       | Do not build the fluent-bit executable      | off

In order to active one of these features, you need to set a boolean value. As an example if we would like to build _Fluent-Bit_ with _XBee_ support we should do:

```bash
$ cd build/
$ cmake -DWITH_XBEE=1 ..
$ make
```

Multiple features can be enabled with _cmake_, just not that the _WITH\_ALL_ option will activate and override any previous value for all of them.

## Using Fluent Bit

Once the tool have been compiled, a binary file called _Fluent-Bit_ will be found on the _bin/_ directory. The tool is designed with the same philosophy than [Fluentd](http://fluentd.org), it requires an _Input_ type (or many) from where the data will be collected and an _Output_ where it will be flushed.

### Input Plugins

| name               | option  | description  |
|--------------------|---------|---------------------------------------------------------------------------------|
| CPU                | cpu     | gather CPU usage between snapshots of one second. It support multiple cores     |
| Memory             | mem     | usage of system memory |
| Kernel Ring Buffer | kmsg    | read Linux Kernel messages, same behavior as the __dmesg__ command line program |
| XBee               | xbee | listen for incoming messages over a Xbee device |

### Output Plugins

| name               | option  | description  |
|--------------------|-------------------------|---------------------------------------------------------------------------------|
| Fluentd            | fluentd://host:port     | flush content to a [Fluentd](http://fluentd.org) service. On the [Fluentd](http://fluentd.org) side, it requires an __in_forward__.|
| TreasureData       | td                      | flush data collected to [TreasureData](http://treasuredata.com) service (cloud analytics platform) |
| STDOUT             | stdout                  | prints the collected data to standard output stream |

### Usage

### Flush CPU usage to a Fluentd service

```bash
$ fluent-bit -i cpu -o fluentd://localhost:12224
```

## Contributing

In order to contribute to the project please refer to the [CONTRIBUTING](CONTRIBUTING.md) guidelines.


## License

This program is under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Contact

irc.freenode.net #fluent-bit
