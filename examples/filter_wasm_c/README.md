# Fluent Bit / filter_wasm_c

This source source tree provides an example of WASM filter program with WASI mode.

## Prerequisites

Tested on

* [WASI SDK](https://github.com/WebAssembly/wasi-sdk)

For Ubuntu, it's easy to install with:

```console
$ export WASI_VERSION=14
$ export WASI_VERSION_FULL=${WASI_VERSION}.0
$ wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_VERSION}/wasi-sdk-${WASI_VERSION_FULL}-linux.tar.gz
$ sudo mkdir -p /opt/wasi-sdk/
$ sudo tar xvf wasi-sdk-${WASI_VERSION_FULL}-linux.tar.gz --strip-components=1 -C /opt/wasi-sdk
```

## How to build

Execute _make_ as follows:

```console
$ make
/opt/wasi-sdk/bin/clang -O3 -nostdlib \
	-z stack-size=8192 -Wl,--initial-memory=65536 \
	-o c_filter.wasm c_filter.c \
	-Wl,--export=__heap_base -Wl,--export=__data_end -Wl,--export=c_filter \
	-Wl,--no-entry -Wl,--strip-all -Wl,--allow-undefined
```

Finally, under the same directory, `*.wasm` file will be created:

```console
$ ls *.wasm
c_filter.wasm
```

## How to confirm WASM filter integration

Create fluent-bit configuration file as follows:

```ini
[SERVICE]
    Flush        1
    Daemon       Off
    Log_Level    info
    HTTP_Server  Off
    HTTP_Listen  0.0.0.0
    HTTP_Port    2020

[INPUT]
    Name dummy
    Tag dummy.local

[FILTER]
    Name wasm
    match dummy.*
    WASM_Path c_filter.wasm
    Function_Name c_filter
    accessible_paths .,/path/to/fluent-bit

[OUTPUT]
    Name  stdout
    Match *

```
