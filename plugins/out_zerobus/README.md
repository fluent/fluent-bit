# Zerobus Output Plugin

This plugin sends log records to Databricks via Zerobus streaming ingestion.

## Building Fluent Bit with Zerobus

The plugin is disabled by default (`FLB_OUT_ZEROBUS=OFF`). When enabled, Fluent
Bit builds the bundled Zerobus FFI Rust source from
`lib/zerobus-ffi-1.3.0/rust` with `cargo build --locked --release -p
zerobus-ffi`.

```bash
# Enable and build the bundled Zerobus FFI source
cmake -DFLB_OUT_ZEROBUS=ON ..

# Point to a custom prebuilt library directory
cmake -DFLB_OUT_ZEROBUS=ON -DZEROBUS_LIB_DIR=/path/to/lib ..

# Prefer a system-installed library when available
cmake -DFLB_OUT_ZEROBUS=ON -DFLB_PREFER_SYSTEM_LIB_ZEROBUS_FFI=ON ..

# Explicitly disable
cmake -DFLB_OUT_ZEROBUS=OFF ..
```

Building the bundled source requires Rust Cargo. Crates.io dependencies are not
vendored in the Fluent Bit tree; dependency resolution is pinned by the checked
in `Cargo.lock`. If a crate disappears from the configured registry or the
registry is unavailable, the bundled source build will fail. Environments that
need a registry mirror or cache should provide it through normal Cargo
configuration, such as `CARGO_HOME/config.toml`.

The distro packaging images run the package build from `CMD` when the container
is run. If a registry proxy is required, make the Cargo registry configuration
available at `docker run` time as well as during image builds.

The bundled source build is supported on Linux, macOS, and Windows when a Rust
toolchain is available. The plugin CMake target links the platform-specific
system libraries required by the Rust FFI for each supported target.

## Vendoring the Zerobus FFI Source

The vendored source comes from the Databricks Zerobus SDK release
`ffi/v1.3.0`:

https://github.com/databricks/zerobus-sdk

Only the Rust crates needed to build the C FFI are included under
`lib/zerobus-ffi-1.3.0`:

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

To refresh the vendored FFI source, run this from the Fluent Bit repository
root:

```bash
scripts/update_zerobus_ffi.sh 1.3.0
```

The script downloads the Databricks Zerobus SDK release archive, copies only the
FFI build inputs listed above, narrows the Rust workspace to `sdk` and `ffi`,
and refreshes `Cargo.lock` for that narrowed workspace.

The vendored `rust/ffi/build.rs` is patched to write cbindgen output to Cargo's
`OUT_DIR` instead of rewriting `rust/ffi/zerobus.h` during every build. The
checked-in `rust/ffi/zerobus.h` is the header used by the C plugin.

## Configuration

| Key           | Description                                  | Required | Default |
|---------------|----------------------------------------------|----------|---------|
| endpoint      | Zerobus gRPC endpoint URL                    | Yes      |         |
| workspace_url | Databricks workspace URL                     | Yes      |         |
| table_name    | Fully qualified table (catalog.schema.table) | Yes      |         |
| client_id     | OAuth2 client ID                             | Yes      |         |
| client_secret | OAuth2 client secret                         | Yes      |         |
| add_tag       | Add Fluent Bit tag as `_tag` field           | No       | true    |
| time_key      | Key name for the injected timestamp          | No       | \_time  |
| log_key       | Comma-separated list of keys to include      | No       | (all)   |
| raw_log_key   | Store full original record as JSON string    | No       |         |
