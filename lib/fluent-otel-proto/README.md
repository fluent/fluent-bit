# Fluent OTel (OpenTelemetry) Proto files

This projects builds a static library that provides C interfaces for OpenTelemetry proto files data model and also includes some helper utilities.

In the source, the `.proto` files are already included in their `C` version, so here you will find instructions for:

- build this as a static library
- regenerate C interfaces from .proto files

The project exposes the following build options:

## Build static library

To get start just clone this repository

```
git clone https://github.com/fluent/fluent-otel-proto
```

Join the build directory and compile:

```
cd fluent-otel-proto/build
cmake ../
```

By default an example test gets available:

```
examples/test-api

- opentelemetry proto 'common'  :     found
- opentelemetry proto 'resource':     found
- opentelemetry proto 'trace'   :     found
- opentelemetry proto 'logs'    :     found
- opentelemetry proto 'metrics' : not found (enable it with -DFLUENT_PROTO_METRICS)
```

> Yes, Metrics are disabled for now.

## Regenerate C files

To regenerate the C files inside this repo, you need to main dependencies or repositories:

- [fluent/protobuf-c](https://github.com/fluent/protobuf-c)
- [open-telemetry/opentelemetry-proto](https://github.com/open-telemetry/opentelemetry-proto)

### Download dependencies

#### 1. Protobuf-c

The repository [fluent/protobuf-c](https://github.com/fluent/protobuf-c) is a fork of the official protobuf-c that includes a small modification to support `options` feature from proto3. This feature is only required by the OpenTelemetry Metrics data model.

Download and install `protobuf-c` by  running the following commands:

```
git clone https://github.com/fluent/protobuf-c
cd protobuf-c
./autogen.sh
./configure --prefix=/opt/protobuf-c
make
sudo make install
```

#### 2. OpenTelemetry Proto

Download the main repository with the following command:

```
git clone https://github.com/open-telemetry/opentelemetry-proto
```

#### 3. Clone this repository

```bash
git clone https://github.com/fluent/fluent-otel-proto
```

#### 4. Regenerate C Files 

The CMake command will require the following variable definitions to succeed in the C files regeneration:

| Variable name           | Description                                                  |
| ----------------------- | ------------------------------------------------------------ |
| FLUENT_PROTO_REGENERATE | Enable the C source file regeneration. Disabled by default.  |
| PROTOBUF_C_SOURCE_DIR   | Absolute path of the directory containing the sources of `protobuf-c` downloaded in Step 1. __NOTE__: this is the source code path, not where the binaries were installed. |
| OTEL_PROTO_DIR          | Absolute path of the directory containing the sources of `opentelemetry-proto` downloaded in Step 2. |

In addition, the following build options are available if you desire to enable/disable certain feature:

| Build Option          | Description                                                  | Default |
| --------------------- | ------------------------------------------------------------ | ------- |
| FLUENT_PROTO_COMMON   | Include the regeneration of a C interface for `common.proto` file. | On      |
| FLUENT_PROTO_RESOURCE | Include the regeneration of a C interface for `resource.proto` file. | On      |
| FLUENT_PROTO_TRACE    | Include the regeneration of a C interfaces for `trace.proto` and `trace_service.proto` files. | On      |
| FLUENT_PROTO_LOGS     | Include the regeneration of a C interfaces for `logs.proto` and `logs_service.proto` files. | On      |
| FLUENT_PROTO_METRICS  | Include the regeneration of a C interfaces for `metrics.proto` and `metrics_service.proto` files. | Off     |

#### 5. Example

Get into this project source code directory:

```bash
cd fluent-otel-proto/build/
```

Run CMake:

```bash
cmake -DFLUENT_PROTO_REGENERATE=ON \
      -DPROTOBUF_C_SOURCE_DIR=/tmp/protobuf-c \
      -DOTEL_PROTO_DIR=/tmp/opentelemetry-proto \
      ../
```

now build by running `make` command.



