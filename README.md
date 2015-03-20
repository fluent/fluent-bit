# Fluent Bit

_Fluent-Bit_ is an events collector for Embedded Linux and is part of the [Fluentd](http://fluentd.org) project ecosystem. It allows to collects information from different sources, package them and dispatch to [Fluentd](http://fluentd.org) collector Instances.

## Build

To build _Fluent-Bit_, you need __cmake__ and a C compiler such as __GCC__ or __Clang__. If you already have the requirements proceed with the following steps:

```bash
$ cd build/
$ cmake ..
$ make
```
### XBee Support

As an optional feature that needs to be enabled at build time, _Fluent-Bit_ supports [Xbee devices](http://www.digi.com/products/wireless-wired-embedded-solutions/zigbee-rf-modules/zigbee-mesh-module/xbee-zb-module#overview) (ZigBee protocol). To make it available run _cmake_ with the following additional option:

```bash
$ cd build/
$ cmake -DFLB_XBEE=1 ..
$ make
```

## Using Fluent Bit

Once the tool have been compiled, a binary file called _Fluent-Bit_ will be found on the _bin/_ directory. The tool is designed with the same philosophy than [Fluentd](http://fluentd.org), it requires an _Input_ type (or many) from where the data will be collected and an _Output_ where it will be flushed.

### Input Plugins

| name               | option  | description  |
|--------------------|---------|---------------------------------------------------------------------------------|
| CPU                | cpu     | gather CPU usage between snapshots of one second. It support multiple cores     |
| Kernel Ring Buffer | kmsg    | read Linux Kernel messages, same behavior as the __dmesg__ command line program |
| XBee               | xbee | listen for incoming messages over a Xbee device |

### Output Plugins

| name               | option  | description  |
|--------------------|-------------------------|---------------------------------------------------------------------------------|
| Fluentd            | fluentd://host:port     | flush content to a [Fluentd](http://fluentd.org) service. On the [Fluentd](http://fluentd.org) side, it requires an __in_forward__.|

### Usage

### Flush CPU usage to a Fluentd service

```bash
$ Fluent-Bit -i cpu -o fluentd://localhost:12224
```

## License

This program is under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).
