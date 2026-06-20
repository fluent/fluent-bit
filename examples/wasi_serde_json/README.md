# Fluent Bit / wasi_serde_json

This source source tree provides an example of WASM program with WASI mode.

## Prerequisites

* Rust
  * rustc 1.61.0 (fe5b13d68 2022-05-18)
* [rustup](https://rustup.rs/) (For preparing rust compiler and toolchains)

## How to build

Add `wasm32-wasip1` target for Rust toolchain:

```console
$ rustup target add wasm32-wasip1
```

Then, execute _cargo build_ as follows:

```console
$ cargo build --target wasm32-wasip1 --release
```

Finally, under target/wasm32-wasip1/release directory, `*.wasm` file will be created:

```console
$ ls target/wasm32-wasip1/release/*.wasm
target/wasm32-wasip1/release/wasi_serde_json.wasm
```

## How to confirm WASI integration

Create parsers.conf as follows:

```ini
[PARSER]
    Name        wasi
    Format      json
    Time_Key    time
    Time_Format %Y-%m-%dT%H:%M:%S.%L %z
```

And Create fluent-bit configuration file as follows:

```ini
[SERVICE]
    Flush        1
    Daemon       Off
    Parsers_File parsers.conf
    Log_Level    info
    HTTP_Server  Off
    HTTP_Listen  0.0.0.0
    HTTP_Port    2020

[INPUT]
    Name exec_wasi
    Tag  exec.wasi.local
    WASI_Path /path/to/wasi_serde_json.wasm
    Parser wasi

[OUTPUT]
    Name  stdout
    Match *
```
