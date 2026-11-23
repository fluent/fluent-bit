# Keep a request's diagnostics when an error occurs

Run from this directory with the built Fluent Bit executable:

```sh
/path/to/fluent-bit -c fluent-bit.yaml
```

After one second, stdout contains three sanitized events: both events from
`request-with-error`, plus INFO from `successful-request`. DEBUG from the
successful request is discarded. Stop the process after observing the output.
The input file contains synthetic data only; no custom Lua is needed to consume
this recipe. The matching conditions and composition are implemented in Lua.

Set `keys` to a trusted tenant/request identity in your own source. Configure
`hold_ms` for the decision deadline. The deadline starts with the first admitted
record and does not extend on subsequent arrivals. The clock is sampled once
per FTS callback batch; records admitted from that batch use that processing-time
snapshot. It is not an event-time watermark. `retain_when` matches ERROR;
one match retains every admitted record in that window. `keep_when` preserves
non-DEBUG records even when no error matches. Within each window, release preserves
admission order. Ordering across windows, keys and late pass-through events can change.

`late_ms` controls the closed-key marker horizon. Records for a known closed
window pass through sanitized and are counted as `late_passthrough`; a late
ERROR cannot restore already discarded DEBUG records. After the marker expires,
a new generation can begin, subject to the same key/byte limits.

`state_limit` includes bucket tables, keys, records, tags, encoded payloads,
closed markers and the bounded key scratch buffer. `max_keys` includes ready
window generations awaiting release. Overflow keeps the sanitized event without
admitting it to a window. Successful release transfers ownership to the engine
queue; a busy queue preserves the frozen payload until a later timer tick.
`ready_timeout_ms` bounds that retry period from the decision deadline; expiry
discards and counts the remaining records.

The recipe is input-only and commits retention locally at the successful FTS
batch boundary. Retention is volatile: crash and graceful shutdown lose pending
records. Graceful stop counts its discards and cancels the timer before context
cleanup. A source retry following an outer failure can duplicate held records.
Engine queue acceptance is not an exporter acknowledgment. Grouping across
processes/agents requires deployment affinity; this is not whole-request capture
across distributed inputs.

Inspect `fluentbit_processor_items_held_current`, `items_held_total`,
`items_out_total`, `items_drop_total` and `accounting_errors_total` with the
processor's stage labels. `fluentbit_fts_window_events_total` distinguishes
held, released, decision, shutdown, ready_expired, release_retry,
late_passthrough and overflow_keep. Recipe callback outcome HOLD records an
attempt; it is not a retained-inventory or delivery counter.

Processing-time clocks are monotonic. Lookup work is charged to the Lua callback
budget. Store commit, deadline scans and encoding are bounded by the configured
key/byte/output limits; these are not hard real-time execution guarantees.
