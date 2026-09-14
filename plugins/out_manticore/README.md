# Manticore Search output

The `manticore` output sends log records to Manticore Search's direct-to-disk
bulk import endpoint, `/bulk?bulk_import=<table>`, as newline-delimited JSON
over HTTP/1.1 chunked transfer encoding.

The plugin formats each Fluent Bit record as one Manticore operation:

```json
{"insert":{"table":"logs","id":42,"doc":{"message":"hello","status":200}}}
```

It converts records incrementally and buffers at most `stream_chunk_size` bytes
before writing an HTTP chunk. A record larger than that limit is sent as its own
chunk. The plugin never builds the complete NDJSON request body in memory.

## Requirements

The target table must exist before Fluent Bit sends data. Manticore's native
`/bulk` endpoint does not create tables automatically.

Each request is imported directly into one disk chunk and published at request
EOF. The `table` option is sent both in `bulk_import=<table>` and in every
operation. Empty NDJSON lines are never generated. In the default mode, every
Fluent Bit flush is one request and therefore one disk chunk. The plugin closes
the HTTP connection after each request to release Manticore's bulk import
reservation and unblock ordinary writes. For this reason, `net.keepalive` is
disabled for this output.

Every record must contain a stable, non-zero numeric ID in `id_key`. Decimal
strings are accepted and normalized to JSON numbers. Missing, zero, negative,
non-decimal, overflowing, or duplicate IDs are rejected during preflight before
the HTTP connection is opened. Preflight retains one 64-bit ID per record to
verify uniqueness; it does not buffer the encoded NDJSON body.

## Configuration

```ini
[OUTPUT]
    Name               manticore
    Match              *
    Host               manticore
    Port               9308
    Table              logs
    Action             insert
    Id_Key             id
    Stream_Chunk_Size  64K
```

### One chunk for a finite import

Fluent Bit normally splits a large input into several internal chunks. To
publish all of them as one Manticore disk chunk, enable `single_chunk` and use a
dedicated durable spool path:

```ini
[INPUT]
    Name          tail
    Path          /data/import.ndjson
    Read_From_Head On
    Exit_On_Eof   On
    Parser        json

[OUTPUT]
    Name          manticore
    Match         *
    Host          manticore
    Port          9308
    Table         logs
    Action        insert
    Workers       1
    Single_Chunk  On
    Spool_Path    /var/lib/fluent-bit/manticore-logs.ndjson
```

In this mode, `FLB_OK` means that the callback is durably staged locally; it
does not mean Manticore has published it yet. Flush callbacks serialize records
to the spool, `fsync` the data, and then `fsync` the callback's committed byte
offset and checksum to a companion `<spool_path>.commit` journal. On recovery,
committed-data corruption stops startup without a network request; incomplete
data or journal tails are truncated to the last complete, checksummed commit
record. Retained serialized data is replayed using the current output
configuration. When Fluent Bit shuts down after input EOF, the plugin first
requires zero running tasks and zero pending storage chunks, then streams the
committed spool in one HTTP request. Both files are removed only after Manticore
acknowledges the request. A failed final upload keeps both files and is reported
in the log, but does not change Fluent Bit's process exit status: shutdown
success means that Fluent Bit stopped, not that Manticore published the import.
The next run replays the committed spool before accepting new input.

Use this mode only for finite imports with an explicit process completion
boundary such as `Exit_On_Eof On`. A continuously running Fluent Bit process
does not publish the session until shutdown. `single_chunk` requires `insert`,
a writable `spool_path` dedicated to one output instance, and one output worker.
It is not currently supported on Windows. A permanent record error aborts the
whole session without contacting Manticore and removes the partial spool; rerun
the finite source after correcting the record.

Session-wide duplicate detection is memory-resident and capped by
`max_session_ids` (default 1,048,576 IDs). Raise that explicit limit for larger
imports; the hash table uses up to roughly 16 bytes per allowed ID.

Recovery is at-least-once. If the process loses power after Manticore commits the
request but before the local commit journal is cleared, the next run can replay
the same stable IDs. Rows remain correct because `insert` replaces those IDs,
but the replay can create one additional Manticore disk chunk.

TLS uses the standard Fluent Bit output options:

```ini
    TLS        On
    TLS.Verify On
```

HTTP Basic authentication is available through `HTTP_User` and `HTTP_Passwd`.

| Option | Description | Default |
|---|---|---|
| `table` | Existing target Manticore table. Required. | none |
| `action` | Direct-to-disk `/bulk` action: `insert` or `create`. | `insert` |
| `id_key` | Required top-level non-zero numeric ID, moved to `id` and removed from `doc`. | `id` |
| `single_chunk` | Stage all Fluent Bit flushes and publish one request at shutdown. | `false` |
| `spool_path` | Exclusive durable spool file required when `single_chunk` is enabled. | none |
| `max_session_ids` | Maximum IDs retained for session-wide duplicate detection. | `1M` |
| `stream_chunk_size` | Maximum NDJSON bytes buffered before an HTTP chunk is written. A single larger record is sent separately. | `64K` |
| `buffer_size` | Maximum buffer used to read the Manticore response. | `64K` |
| `http_user` | HTTP Basic authentication user. | none |
| `http_passwd` | HTTP Basic authentication password. | empty |

## Response and retry behavior

- HTTP `2xx` with `"errors": false`: the Fluent Bit chunk is acknowledged.
- A response with `"errors": true` and any item status `408`, `429`, or `5xx`:
  Fluent Bit retries the whole chunk.
- HTTP `408` or `429`, transport failures, and HTTP `5xx` without a readable
  item status: Fluent Bit retries the whole chunk.
- A response with only permanent item statuses is rejected permanently, even
  when Manticore reports the request itself as HTTP `5xx`. Other HTTP `4xx`
  responses are also permanent.

A mixed `/bulk` response can contain successful and transiently failed batches.
Fluent Bit can only retry its original chunk, so successful batches are
replayed. Bulk import publication replaces rows with matching IDs already in
the table, making replay safe when every record has a stable ID. Within one
batch, duplicate numeric IDs are invalid; the plugin rejects them before
delivery.
