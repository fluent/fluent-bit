# Fluent Bit / filter_rust_clib

This source source tree provides an example of WASM program with WASI mode mainly written in Rust.

## Prerequisites

* Rust
  * rustc 1.61.0 (fe5b13d68 2022-05-18)
* [rustup](https://rustup.rs/) (For preparing rust compiler and toolchains)
* [cbindgen](https://github.com/eqrion/cbindgen) (For preparing C headers to include exported Rust's c style function(s))
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

Add `wasm32-unknown-unknown` target for Rust toolchain:

```console
$ rustup target add wasm32-unknown-unknown
```

Install `cbindgen` command as follows:

```console
$ cargo install --force cbindgen
```

Then, execute _make build_ as follows:

```console
$ make build
```

Finally, `*.wasm` file will be created:

```console
$ ls *.wasm
rust_clib_filter.wasm
```

## How to confirm WASI integration

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
    Tag  dummy.local

[FILTER]
    Name   wasm
    match  dummy.*
    WASM_Path /path/to/rust_clib_filter.wasm
    Function_Name rust_clib_filter
    accessible_paths .,/path/to/fluent-bit

[OUTPUT]
    Name  stdout
    Match *
```
