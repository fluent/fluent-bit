# Protobuf records to Parquet

This example keeps Protobuf type information through the logging pipeline:

1. The application serializes one Protobuf message with `toByteArray()`.
2. It sends that byte array as a MessagePack `bin` value in a Forward record.
3. The S3 output loads a `FileDescriptorSet` once at startup.
4. Before upload, Fluent Bit decodes the buffered messages into typed Arrow
   columns and writes one Parquet object using Zstandard compression.

The payload is never Base64-encoded and is never converted to JSON.

## Build requirements

Build Fluent Bit with Arrow, Parquet, and the Protobuf runtime:

```text
-DFLB_ARROW=On
-DFLB_PROTOBUF=On
```

`FLB_PROTOBUF_ENCODER` is not required for this path.

## Generate the descriptor

Generate a binary descriptor set containing the root file and all imports:

```sh
protoc \
  --proto_path=/path/to/protos \
  --include_imports \
  --descriptor_set_out=/etc/fluent-bit/wire-log.desc \
  /path/to/protos/wire_log.proto
```

Set `protobuf_message_type` to the message's fully-qualified Protobuf name.

## Forward record shape

The application must send a standard Forward record whose map contains a
MessagePack binary value:

```text
[
  "wire.logs",
  1700000000,
  {
    "wire_proto": <MessagePack bin containing WireLog.toByteArray()>
  }
]
```

Do not send Base64 or a MessagePack string. The output rejects missing,
duplicate, or non-binary `protobuf_data_key` values instead of silently
writing corrupt data.

See `fluent-bit.conf` in this directory for the matching configuration.

## Local buffering and schema evolution

Buffered data is stored as a sequence of MessagePack binary values, preserving
record boundaries across restarts. The local buffer directory is isolated by
the Protobuf message type and the framing version, so it cannot collide with
the existing JSON buffer for the same bucket.

Backward-compatible descriptor updates for the same message type reuse the
same buffer. Changing `protobuf_message_type` creates a different buffer
directory. Keep Protobuf field-number and wire-type changes backward
compatible so messages buffered by the previous deployment remain decodable.
