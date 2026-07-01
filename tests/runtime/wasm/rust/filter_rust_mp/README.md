# Fluent Bit / filter_rust_mp

This source tree provides an test program of WASM program which uses msgpack format written in Rust.

## Prerequisites

* Rust
  * rustc 1.75.0 (82e1608df 2023-12-21)) or later
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
target/wasm32-unknown-unknown/release/filter_rust_mp.wasm
```

## How to put test data of WASM filter

Testcase of Wasm filters, which is written in Rust, on fluent-bit is put under `tests/runtime/data/wasm/msgpack` directory.

```console
$ cp target/wasm32-unknown-unknown/release/filter_rust_mp.wasm \
  /top/path/of/fluent-bit/tests/runtime/data/wasm/msgpack
```
