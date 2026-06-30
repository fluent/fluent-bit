# Zerobus C FFI

C Foreign Function Interface bindings for the Zerobus Rust SDK.

## Building

```bash
# Build both static and dynamic libraries
cargo build -p zerobus-ffi --release

# Output:
# target/release/libzerobus_ffi.a    (static library)
# target/release/libzerobus_ffi.so   (Linux dynamic library)
# target/release/libzerobus_ffi.dylib (macOS dynamic library)
# target/release/zerobus_ffi.dll     (Windows dynamic library)
```

## Cross-compilation

```bash
# Linux ARM64
rustup target add aarch64-unknown-linux-gnu
cargo build -p zerobus-ffi --release --target aarch64-unknown-linux-gnu

# macOS ARM64 (Apple Silicon)
rustup target add aarch64-apple-darwin
cargo build -p zerobus-ffi --release --target aarch64-apple-darwin

# Windows
rustup target add x86_64-pc-windows-gnu
cargo build -p zerobus-ffi --release --target x86_64-pc-windows-gnu
```

## Usage

### Go (CGO with static library)

```go
/*
#cgo LDFLAGS: -L${SRCDIR}/lib -lzerobus_ffi -ldl -lpthread -lm
#include "zerobus.h"
*/
import "C"
```

### C# (P/Invoke with dynamic library)

```csharp
[DllImport("zerobus_ffi", CallingConvention = CallingConvention.Cdecl)]
private static extern IntPtr zerobus_sdk_new(string endpoint, string ucUrl, ref CResult result);
```

### C++

```cpp
#include "zerobus.h"

// Link with -lzerobus_ffi
```

### Dynamic protobuf from a Unity Catalog schema (pure C)

Build a protobuf descriptor and encode records straight from Unity Catalog
table metadata — no pre-generated `.proto` file and no second Rust crate:

```c
CResult r = {0};

/* init: fetch GET /api/2.1/unity-catalog/tables/{name} and pass its JSON body */
CZerobusProtoSchema *schema = zerobus_proto_schema_from_uc_json(uc_table_json, &r);
/* on error schema == NULL; read r.error_message then zerobus_free_error_message(r.error_message) */

uintptr_t dlen;
const uint8_t *desc = zerobus_proto_schema_descriptor_bytes(schema, &dlen);
CZerobusStream *stream = zerobus_sdk_create_stream(sdk, table_name, desc, dlen,
                                                   client_id, client_secret, &opts, &r);

/* per record, at flush time */
uint8_t *buf; uintptr_t len;
if (zerobus_proto_schema_encode_json(schema, record_json, &buf, &len, &r)) {
    /* collect buf/len into a batch, ingest via zerobus_stream_ingest_proto_records(...) */
    zerobus_free_proto_bytes(buf, len);
}

/* shutdown */
zerobus_proto_schema_free(schema);
```

Encoding contract: record object keys are matched to column names; unknown keys
are ignored (upstream records often carry extra non-column metadata). Records are
encoded through protobuf's JSON mapping, so a few column types need their JSON
value shaped accordingly:

| Unity Catalog type            | Proto type      | JSON value to supply                                             |
|-------------------------------|-----------------|------------------------------------------------------------------|
| `STRING`                      | `string`        | string                                                           |
| `INT`/`INTEGER`, `SHORT`/`SMALLINT` | `int32`   | number                                                           |
| `LONG`/`BIGINT`               | `int64`         | number **or string** — use a **string** above 2^53 (see below)   |
| `FLOAT`, `DOUBLE`             | `float`/`double`| number                                                           |
| `BOOLEAN`                     | `bool`          | boolean                                                          |
| `BINARY`                      | `bytes`         | **base64-encoded string** (not a JSON array of byte values)      |
| `DATE`                        | `int32`         | integer — days since the Unix epoch (not an ISO-8601 string)     |
| `TIMESTAMP`                   | `int64`         | integer — microseconds since the Unix epoch (not an ISO-8601 string) |
| `VARIANT`                     | `string`        | **JSON-encoded string** — a string whose contents are the variant's JSON (objects, arrays, or primitives) |
| `ARRAY<T>`                    | `repeated T`    | JSON array of `T` values                                         |
| `MAP<K,V>`                    | `map<K,V>`      | JSON object (`K` must be an integral, bool, or string type)      |
| `STRUCT<...>`                 | nested `message`| JSON object                                                      |

This table mirrors the supported set in the [Zerobus type-support
reference](https://docs.databricks.com/aws/en/ingestion/zerobus-limits#type-support).
Beyond that reference, the encoder additionally accepts `BYTE`/`TINYINT` (→
`int32`), `TIMESTAMP_NTZ` (→ `int64` micros, same wire shape as `TIMESTAMP`),
and `DECIMAL` (→ `string`, e.g. `"123.45"`, to preserve precision/scale).
Complex columns (`ARRAY`/`MAP`/`STRUCT`) require the column's `type_json` from
the Unity Catalog REST response to be present in the input.

Two precision pitfalls worth calling out:

- **64-bit integers above 2^53** (large `BIGINT` values, and `TIMESTAMP` micros
  past year 2255) lose precision when emitted as a JSON number by most encoders.
  Pass them as JSON **strings** (the canonical protobuf-JSON form for 64-bit
  ints), which round-trip exactly.
- **`DATE`/`TIMESTAMP*` unit mismatches** are silent: writing milliseconds where
  microseconds are expected shifts every row by 10³.

Top-level non-nullable scalar and struct columns become proto2 `required`
fields; a record missing one is rejected rather than encoded. Non-nullable
`ARRAY`/`MAP` columns map to `repeated`, which has no presence, so an omitted one
encodes as empty rather than being rejected; required fields nested inside a
`STRUCT` are likewise not presence-checked.

A handle may be shared by concurrent readers: worker threads may call
`zerobus_proto_schema_encode_json` and `zerobus_proto_schema_descriptor_bytes`
on the same handle concurrently. `zerobus_proto_schema_free` must be called
exactly once, after all in-flight calls on the handle have returned — it must
not race any other use of the handle.

## API Reference

See `zerobus.h` for the complete C API documentation.
