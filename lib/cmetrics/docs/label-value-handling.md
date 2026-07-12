# Long metric label handling

## Context

Before this fix, CMetrics rejected any string longer than 1024 bytes while
decoding its internal MessagePack representation. The validation was performed
by the generic string decoder, so it applied not only to label values, but also
to metric names, namespaces, subsystems, descriptions, and label names.

This behavior caused
[fluent/fluent-bit#9297](https://github.com/fluent/fluent-bit/issues/9297): a
valid Prometheus scrape containing a `process_command_line` label longer than
1024 bytes was accepted by the Prometheus parser, but failed during the
subsequent CMetrics MessagePack round trip. The failure discarded all metrics
from the scrape without a useful diagnostic.

[PR #224](https://github.com/fluent/cmetrics/pull/224) proposed retaining the
first 1024 bytes and appending `...` during MessagePack decoding. The issue is
valid, but that behavior should not be implemented in the generic decoder.

## Why silent truncation is unsafe

Prometheus identifies a time series using its metric name and complete label
set. Consider two label values with the same 1024-byte prefix:

```text
process_command_line="<common prefix>A"
process_command_line="<common prefix>B"
```

Blindly replacing both suffixes with `...` gives both samples the same series
identity. This can merge unrelated series and produce incorrect results.

Truncating at a fixed byte offset can also split a multi-byte UTF-8 character.
Because the generic MessagePack helper decodes every CMetrics string, the same
policy could silently alter metric names, descriptions, and label names.

Presentation requirements must not be implemented by mutating the internal
data model during deserialization. An output encoder may abbreviate a value for
display, but the stored value must remain unchanged.

## Ecosystem behavior

There is no universal 1024-byte limit for Prometheus label values:

- Prometheus accepts label values without a length limit by default. When a
  `label_value_length_limit` is configured, one violation fails the scrape
  instead of silently rewriting the value.
- VictoriaMetrics provides a configurable label-value limit. It ignores an
  oversized series and reports the event through logs and an internal metric.
- Grafana Mimir provides configurable `error`, `drop`, and `truncate`
  strategies. Its truncation strategy includes a hash of the original value so
  that values with a common prefix remain distinct.
- OpenTelemetry metric attributes are currently exempt from the general SDK
  attribute-length limits.

References:

- [Prometheus data model](https://prometheus.io/docs/concepts/data_model/)
- [Prometheus scrape configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)
- [VictoriaMetrics ingestion limits](https://docs.victoriametrics.com/victoriametrics/single-server-victoriametrics/)
- [Grafana Mimir configuration](https://grafana.com/docs/mimir/latest/configure/configuration-parameters/)
- [OpenTelemetry attribute limits](https://opentelemetry.io/docs/specs/otel/common/#attribute-limits)

## Recommended CMetrics behavior

The internal MessagePack decoder should:

1. Decode valid strings losslessly by default.
2. Treat resource limits separately from string contents and metric semantics.
3. Prevent integer overflow when calculating allocation sizes.
4. Bound allocations made from untrusted length fields.
5. Return a distinct resource-limit error with enough context for callers to
   emit a useful diagnostic.
6. Never silently truncate metric identifiers or labels.

This fix implements those requirements for data-backed CMetrics MessagePack
decoding. It verifies that all declared string bytes are present before making
an allocation, then copies the complete value into CMetrics-owned storage. A
malicious length field therefore cannot trigger an allocation larger than its
available input, while valid long strings round-trip without modification.

A configurable safety ceiling may be appropriate for callers that process
untrusted MessagePack. Such a ceiling should apply to decoder resources, be
documented in bytes, and reject input explicitly. It must not reinterpret an
oversized string as valid data with different contents.

If Fluent Bit or another caller needs an ingestion policy, it should be
implemented above the MessagePack decoder. Useful policies are:

- `preserve`: retain the complete value; this matches Prometheus defaults.
- `reject`: reject the scrape or batch with a diagnostic.
- `drop`: discard only the offending series and increment an error counter.
- `truncate_hash`: truncate on a valid UTF-8 boundary and append a hash derived
  from the complete value to preserve series identity as far as practical.

The selected policy and limit should be configurable by the component that
owns ingestion, because CMetrics is also used with OTLP and other formats whose
requirements differ.

## Regression coverage

An implementation should include tests for:

- Values of 1023, 1024, 1025, 2048, and 65536 bytes.
- Two values with an identical 1024-byte prefix and different suffixes.
- UTF-8 characters crossing any configured boundary.
- Long metric names, descriptions, label names, and label values independently.
- Multiple fields and metrics after a long string, proving that the MessagePack
  reader remains synchronized.
- A declared string length larger than the available input.
- A declared length near the integer and configured allocation limits.
- Allocation failure and cleanup paths.
- End-to-end Prometheus scrape, CMetrics MessagePack encode/decode, and output.

Memory-safety validation should include AddressSanitizer, UndefinedBehaviorSanitizer,
and Valgrind in addition to the focused unit tests.
