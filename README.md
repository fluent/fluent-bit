# Fluent Bit

__Fluent-Bit__ is a [Fluentd](http://fluentd.org) collection tool designed for Embedded Linux that collects Kernel messages (Kernel Ring Buffer) and Hardware metrics such as CPU and Memory usage.

## Build

To build _fluent-bit_, you need __cmake__ and a C compiler such as __GCC__ or __Clang__. If you already have the requirements proceed with the following steps:

```bash
$ cd build/
$ cmake ..
$ make
```

## Running

Once the tool have been compiled, a binary file called __fluent-bit__ will be found on the _bin/_ directory.

## License

This program is under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).
