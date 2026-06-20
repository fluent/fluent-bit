# CTraces

The [CTraces](https://github.com/calyptia/ctraces) project is a tiny library to create and maintain Traces contexts and provide utilities for data manipulation, including encoding/decoding for compatibility with OpenTelemetry and other formats.

This project is a core library for [Fluent Bit](https://fluentbit.io): agent and aggregator for Observability.

## Build

Clone the repository:

```shell
git clone https://github.com/calyptia/ctraces
```

Get into the project directory and retrieve submodules:

```shell
cd ctraces
git submodule update --init --recursive --remote
```

Compile:

```shell
cd build/
cmake -DCTR_DEV=on ../
make
```

> CTR_DEV flag enables debugging mode, examples and the unit tests

## Usage

In the [examples](examples/) directory, you will find a _simple_ example that describes how to use the API.

## License

This program is under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Authors

[Calyptia Team](https://www.calyptia.com)
