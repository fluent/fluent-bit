# Fluent Bit

__Fluent-Bit__ is a [Fluentd](http://fluentd.org) collection tool designed for Embedded Linux that collects Kernel messages (Kernel Ring Buffer) and Hardware metrics such as CPU and Memory usage.

## Build

To build _fluent-bit_, you need __cmake__ and a C compiler such as __GCC__ or __Clang__. If you already have the requirements proceed with the following steps:

```bash
$ cd build/
$ cmake ..
$ make
```

## Using Fluent Bit

Once the tool have been compiled, a binary file called __fluent-bit__ will be found on the _bin/_ directory. The tool is designed with the same philosophy than [Fluentd](http://fluentd.org), it requires an _Input_ type (or many) from where the data will be collected and an _Output_ where it will be flushed.

### Input Plugins

| name               | option  | description  |
|--------------------|---------|---------------------------------------------------------------------------------|
| CPU                | cpu     | gather CPU usage between snapshots of one second. It support multiple cores     |
| Kernel Ring Buffer | kmsg    | read Linux Kernel messages, same behavior as the __dmesg__ command line program |

### Output Plugins

| name               | option  | description  |
|--------------------|-------------------------|---------------------------------------------------------------------------------|
| Fluentd            | fluentd://host:port     | flush content to a [Fluentd](http://fluentd.org) service. On the [Fluentd](http://fluentd.org) side, it requires an __in_forward__.|

### Usage

### Flush CPU usage to a Fluentd service

```bash
$ fluent-bit -i cpu -o fluentd://localhost:12224
```

## License

This program is under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).
