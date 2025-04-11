# CProfiles

The [CProfiles](https://github.com/fluent/cprofiles) provides a simple API to create and manage profiles for monitoring and observability purposes, the internal data structure is based on OpenTelemetry Profiles schema (v1/development):

- <https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/profiles/v1development/profiles.proto>

## Build

Clone the repository:

```shell
git clone https://github.com/fluent/cprofiles
```

Get into the project directory and retrieve submodules:

```shell
cd cprofiles/
git submodule update --init --recursive --remote
```

Compile:

```shell
cd build/
cmake -DCPROF_DEV=on ../
make
```

> CPROF_DEV flag enables debugging mode, examples and the unit tests

## Usage

For now you can try out the unit test that compiles when dev mode is enabled: `tests/cprof-test-profile`:

```text
--- profile debug
Profile Duration: 0 nanoseconds

Samples:
  Sample #1:
    Locations:
      [Empty String: No Function Name]
      Function: main
    Values:
      CPU time: 644 ns
      Memory usage: 1046 bytes
    Timestamps:
      Timestamp 0: 1730342869000000000 ns

  Sample #2:
    Locations:
      [Empty String: No Function Name]
      Function: foo
    Values:
      CPU time: 73 ns
      Memory usage: 1068 bytes
    Timestamps:
      Timestamp 0: 1730342869000000000 ns

  Sample #3:
    Locations:
      [Empty String: No Function Name]
      Function: bar
    Values:
      CPU time: 175 ns
      Memory usage: 849 bytes
    Timestamps:
      Timestamp 0: 1730342869000000000 ns

String Table:
  0: ''
  1: 'CPU time'
  2: 'ns'
  3: 'Memory usage'
  4: 'bytes'
  5: 'main'
  6: 'foo'
  7: 'bar'
```

## License

This program is under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Authors

Fluent Bit Authors
