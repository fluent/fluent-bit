# CMetrics

> DISCLAIMER: THIS LIBRARY IS STILL IN ACTIVE DEVELOPMENT

[CMetrics](https://github.com/calyptia/cmetrics) is a standalone C library to
create, mutate, aggregate, encode, and decode metrics contexts.

## Supported Metric Types

- Counter
- Gauge
- Untyped
- Histogram
- Exponential Histogram
- Summary

All metric points store a sample `timestamp` in nanoseconds.

## Datapoint Start Timestamp (OTLP)

CMetrics also supports an optional native `start_timestamp` per datapoint.
This is primarily relevant for OTLP cumulative streams.

API (`cmt_metric.h`):

- `cmt_metric_set_start_timestamp(...)`
- `cmt_metric_unset_start_timestamp(...)`
- `cmt_metric_has_start_timestamp(...)`
- `cmt_metric_get_start_timestamp(...)`

Backward compatibility: existing code that only uses `timestamp` is unchanged.

## Supported Encoders

- OpenTelemetry Metrics (OTLP protobuf)
- Prometheus text exposition
- Prometheus Remote Write
- Influx line protocol
- Splunk HEC
- CloudWatch EMF
- CMetrics msgpack (internal format)
- Text (human-readable)

## Supported Decoders

- OpenTelemetry Metrics (OTLP protobuf)
- Prometheus text exposition
- Prometheus Remote Write
- StatsD
- CMetrics msgpack (internal format)

## OTLP and `start_timestamp`

- OTLP decoder populates native `start_timestamp` from
  `start_time_unix_nano`.
- OTLP encoder prefers native `start_timestamp` and falls back to OTLP metadata
  when needed.
- Internal CMetrics msgpack supports optional `start_ts` to preserve this value
  across internal encode/decode flows.

Non-OTLP formats (for example Prometheus text, Influx, Splunk HEC, and
CloudWatch EMF) do not define an OTLP-style start timestamp field, so they
serialize sample timestamps only.

## C Usage Example

```c
#include <stdint.h>
#include <stdio.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_map.h>
#include <cmetrics/cmt_metric.h>
#include <cmetrics/cmt_encode_opentelemetry.h>

int main(void)
{
    struct cmt *ctx;
    struct cmt_counter *requests_total;
    struct cmt_metric *sample;
    cfl_sds_t otlp_payload;
    uint64_t start_ns;
    uint64_t sample_ns;

    ctx = cmt_create();
    if (ctx == NULL) {
        return 1;
    }

    requests_total = cmt_counter_create(ctx,
                                        "demo",      /* namespace   */
                                        "service",   /* subsystem   */
                                        "requests_total",
                                        "Total requests",
                                        0,           /* label keys  */
                                        NULL);
    if (requests_total == NULL) {
        cmt_destroy(ctx);
        return 1;
    }

    start_ns = 1700000000000000000ULL;
    sample_ns = start_ns + 5000000000ULL;

    /* Write sample value (cumulative stream example). */
    if (cmt_counter_set(requests_total, sample_ns, 42.0, 0, NULL) != 0) {
        cmt_destroy(ctx);
        return 1;
    }

    /* Access the same datapoint and attach native start timestamp. */
    sample = cmt_map_metric_get(&requests_total->opts,
                                requests_total->map,
                                0, NULL,
                                CMT_FALSE);
    if (sample == NULL) {
        cmt_destroy(ctx);
        return 1;
    }
    cmt_metric_set_start_timestamp(sample, start_ns);

    /* Encode OTLP metrics payload. */
    otlp_payload = cmt_encode_opentelemetry_create(ctx);
    if (otlp_payload == NULL) {
        cmt_destroy(ctx);
        return 1;
    }

    printf("Encoded OTLP payload size: %zu bytes\n", cfl_sds_len(otlp_payload));

    cmt_encode_opentelemetry_destroy(otlp_payload);
    cmt_destroy(ctx);
    return 0;
}
```

## Design Reference

CMetrics is heavily inspired by the Go Prometheus Client API design:

- https://pkg.go.dev/github.com/prometheus/client_golang/prometheus#section-documentation

## License

This program is under the terms of the
[Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Authors

[Calyptia Team](https://www.calyptia.com)
