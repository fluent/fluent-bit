# Rust WASM filter: ABI v2 value-length return

[filter_v2.rs](filter_v2.rs) is a dependency-free `no_std` example. The exported
function has six `i32` arguments and one `i64` return value on wasm32:

```rust
#[no_mangle]
pub extern "C" fn filter_v2(
    _tag: *const u8,
    _tag_length: u32,
    _seconds: u32,
    _nanoseconds: u32,
    record: *const u8,
    record_length: u32,
) -> u64 {
    ((record_length as u64) << 32) | (record as u32 as u64)
}
```

The low 32 bits hold the value (offset in WASM linear memory), and the high
32 bits hold its byte length. Return zero to drop the record. Output does not
require a NUL terminator. No filter configuration is passed to the guest.

The input is borrowed for the call. Fluent Bit copies the result before
releasing it, so returning a slice of the input is valid. For transformed
output, use storage that stays alive until the next call. The binary example
uses a static array. Do not return `Vec::as_ptr()` from a local vector that is
dropped when the function returns, or leak a new allocation on every call.

## Build

Install the `wasm32-unknown-unknown` Rust target if it is not already available:

```sh
rustup target add wasm32-unknown-unknown
make v2
```

This invokes `rustc` with edition 2021, `--crate-type=cdylib`, and
`-C panic=abort`. The example supplies a panic handler that traps. No WASI
imports, Cargo dependencies, or allocator are required. When adapting this
source to Rust edition 2024, use `#[unsafe(no_mangle)]` for the exported names.

## Run

```ini
[SERVICE]
    Flush 1

[INPUT]
    Name dummy
    Tag  example

[FILTER]
    Name          wasm
    Match         *
    WASM_Path     filter_v2.wasm
    Function_Name filter_v2
    ABI_Version   2
    Event_Format  json

[OUTPUT]
    Name  stdout
    Match *
```

`filter_v2` passes the record body through. To demonstrate binary output,
select `Function_Name filter_binary_v2` and `Event_Format msgpack`; it returns
`{"n": 0, "s": "a\u0000b"}`. The `filter_drop_v2` export drops records.

Runtime tests use a compiled copy of this example at
`tests/runtime/data/wasm/filter_rust_v2.wasm`. From the repository root, rebuild
it with `make -C tests/runtime/wasm/rust v2`.

See [the full value-length specification](../../plugins/filter_wasm/README.md).
