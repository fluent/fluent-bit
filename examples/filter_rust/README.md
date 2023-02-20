# Fluent Bit / filter_rust

This source source tree provides an example of WASM program with WASI mode mainly written in Rust.

## Prerequisites

* Rust
  * rustc 1.61.0 (fe5b13d68 2022-05-18)
* [rustup](https://rustup.rs/) (For preparing rust compiler and toolchains)

## How to build

Add `wasm32-unknown-unknown` target for Rust toolchain:

```console
$ rustup target add wasm32-unknown-unknown
```

Then, execute _cargo build_ as follows:

```console
$ cargo build --target wasm32-unknown-unknown --release
```

Finally, `*.wasm` file will be created:

```console
$ ls target/wasm32-unknown-unknown/release/*.wasm
target/wasm32-unknown-unknown/release/filter_rust.wasm
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
    Tag  dummy.local

[FILTER]
    Name   wasm
    match  dummy.*
    WASM_Path /path/to/filter_rust.wasm
    Function_Name rust_filter
    accessible_paths .,/path/to/fluent-bit

[OUTPUT]
    Name  stdout
    Match *
```
