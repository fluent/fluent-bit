# Zerobus FFI vendoring notes

This directory vendors the Zerobus Rust FFI source used by the Fluent Bit
`out_zerobus` plugin.

Upstream: https://github.com/databricks/zerobus-sdk
Version: `ffi/v1.3.0`

Only the Rust crates needed to build the C FFI are included:

- `LICENSE`
- `rust/Cargo.toml`
- `rust/Cargo.lock`
- `rust/LICENSE`
- `rust/NOTICE`
- `rust/README.md`
- `rust/ffi/`
- `rust/sdk/`

The upstream repository also contains language bindings, examples, tests, and
prebuilt archives under `go/lib/`; those are intentionally not vendored.

## Update

Run this from the Fluent Bit repository root:

```console
lib/update_zerobus_ffi.sh 1.3.0
```

The script downloads the Databricks Zerobus SDK release archive, copies only
the FFI build inputs listed above, narrows the Rust workspace to `sdk` and
`ffi`, and refreshes `Cargo.lock` for that narrowed workspace.

## Fluent Bit changes

The vendored `rust/Cargo.toml` workspace is narrowed to `sdk` and `ffi`.

The vendored `rust/ffi/build.rs` writes the cbindgen output to Cargo's
`OUT_DIR` instead of rewriting `rust/ffi/zerobus.h` during every build. The
checked-in `rust/ffi/zerobus.h` is the header used by the C plugin.

## Build behavior

Fluent Bit builds the bundled library with:

```console
cargo build --locked --release -p zerobus-ffi
```

Crates.io dependencies are not vendored in this repository. `Cargo.lock` is
checked in to keep dependency resolution stable. In the Ubuntu packaging image,
the package build runs from `CMD`, so Cargo registry configuration should be
provided when the container is run if a registry proxy is required.
