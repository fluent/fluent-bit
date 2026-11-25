# CMetrics architecture

CMetrics is a static C library that owns metric contexts and converts them to
and from several metrics protocols. The installed API is declared under
`include/cmetrics/`; implementations live under `src/`.

## Core model

`struct cmt` is the top-level context. Metric-family modules implement counters,
gauges, untyped metrics, summaries, histograms, and exponential histograms.
Each family owns a `struct cmt_map`, whose static or labeled datapoints are
represented by `struct cmt_metric`. Labels, options, timestamps, values, and
family-specific storage are shared by codecs and filters.

The main entry points are:

- `cmetrics.c`: context initialization and destruction.
- `cmt_map.c`, `cmt_metric.c`: datapoint lookup, storage, indexing, expiration,
  and value representation.
- `cmt_<type>.c`: metric-family creation and mutation.
- `cmt_cat.c`, `cmt_filter.c`: context combination and selection.
- `cmt_encode_*.c`, `cmt_decode_*.c`: protocol boundaries.

## Protocol boundaries

OTLP uses generated protobuf definitions supplied by fluent-otel-proto.
Prometheus remote write uses generated protobuf-C files in the repository.
Prometheus text decoding uses Flex/Bison sources and build-directory generated
parsers. CMetrics MessagePack is an internal serialized representation used by
format-conversion and downstream flows.

Changes at these boundaries should preserve metric identity, label ordering,
numeric type, timestamps, aggregation fields, and decoder synchronization unless
the format contract intentionally changes. Tests under `tests/encoding.c`,
`tests/decoding.c`, `tests/opentelemetry.c`, `tests/format_conversion.c`, and
the Prometheus-specific test files cover these paths.

## Ownership and concurrency

Metric families own their maps; maps own dynamic metrics and label storage.
Some encoders create temporary heap or arena-backed protobuf structures before
packing them into an SDS result. Allocation family and lifetime must remain
consistent across success and partial-initialization cleanup.

Map lookup, mutation, indexing, expiration, and destruction share internal
state and must be reviewed together for concurrent access. Public structures in
installed headers also constrain internal layout changes because downstream C
code can compile against them.
