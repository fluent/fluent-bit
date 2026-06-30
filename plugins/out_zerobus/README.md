# Zerobus Output Plugin

This plugin sends log records to Databricks via Zerobus streaming ingestion.

## Building Fluent Bit with Zerobus

The plugin is disabled by default (`FLB_OUT_ZEROBUS=OFF`). When enabled, Fluent
Bit builds the bundled Zerobus FFI Rust source from
`lib/zerobus-ffi-1.3.0/rust` with `cargo build --locked`.

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
in `Cargo.lock`.

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
