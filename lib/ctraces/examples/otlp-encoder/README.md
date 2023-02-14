# Instructions to run

After building the project with `-CTR_DEV=on`, the example can be found at `build/examples/ctraces-otlp-encoder`

The example encodes a ctraces context to a buffer and sends it to a locally running instance of the [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/). After setting up the collector locally by [following the instructions from their docs](https://opentelemetry.io/docs/collector/getting-started/), you can start the collector with the following config file:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: "0.0.0.0:4318"

exporters:
  logging:
    loglevel: debug

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [logging]
```

Now you can run the example and see the trace data logged by the collector instance.

