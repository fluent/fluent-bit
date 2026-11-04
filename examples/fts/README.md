# Fluent Typed Scripting (FTS) examples

Runnable policies for the [`fts` processor](../../plugins/processor_fts/README.md).
The OpenTelemetry examples share one layout; the quickstart has only a
configuration with an inline policy and its expected output.

| File                   | Content |
| ---------------------- | ------- |
| `fluent-bit.yaml`      | Pipeline: `opentelemetry` input, `fts` processor, `stdout` output in `otlp_json` format. |
| `policy.lua`           | The FTS policy. |
| `input.json`           | OTLP/HTTP JSON request sent to the input. |
| `expected-output.json` | What Fluent Bit prints, as a JSON array with one entry per printed line. |

| Example | Signal | Shows |
| ------- | ------ | ----- |
| [`quickstart`](quickstart/) | Logs | Inline policy on a `dummy` input. No other tools needed. |
| [`logs-redaction`](logs-redaction/) | Logs | Key and free-form redaction, dropping records, severity and resource enrichment. |
| [`metrics-normalization`](metrics-normalization/) | Metrics | Unit conversion and aggregation that reduces series cardinality. |
| [`traces-filtering`](traces-filtering/) | Traces | Attribute migration, query-string removal, event redaction and selective span drop. |

## Requirements

A Fluent Bit binary built with FTS. FTS is in the `master` branch and is not
part of any published release yet; see
[Availability](../../plugins/processor_fts/README.md#availability). To build it:

```shell
cmake -S . -B build
cmake --build build -j8
./build/bin/fluent-bit --help | grep fts
```

The OTLP examples also need `curl` and `python3`.

## Run the quickstart

```shell
cd examples/fts/quickstart
../../../build/bin/fluent-bit -c fluent-bit.yaml
```

Stop it with Ctrl-C. Expected output:

```json
{"user":"ana","password":"[REDACTED]","path":"/login","status":200,"environment":"dev"}
```

## Run an OTLP example

The helper starts Fluent Bit, posts `input.json`, prints the output and
compares it with `expected-output.json`:

```shell
examples/fts/run.sh examples/fts/logs-redaction
```

It uses `build/bin/fluent-bit` unless you pass another binary as the second
argument or set `FLUENT_BIT_BINARY`. The examples listen on `127.0.0.1:4318`,
so that port must be free.

To run an example by hand, start Fluent Bit from the example directory, because
relative `script` paths are resolved from the working directory:

```shell
cd examples/fts/logs-redaction
../../../build/bin/fluent-bit -c fluent-bit.yaml
```

In a second terminal, send the input to the endpoint of the signal (`logs`,
`metrics` or `traces`):

```shell
curl -H 'Content-Type: application/json' --data-binary @input.json \
     http://127.0.0.1:4318/v1/logs
```

Fluent Bit prints each processed chunk as one OTLP JSON line.

## Reading the output

- The `otlp_json` format of the `stdout` output, like the `opentelemetry`
  output, uses the `log` or `message` key of a map body as the whole body and
  omits the other keys. The logs example uses a `msg` key so that the complete
  redacted body is visible.
- Metric families can be printed in a different order than they were sent:
  the internal metrics representation groups families by type. This happens
  with or without FTS.
- These examples are regression tested by
  `tests/integration/scenarios/processor_fts/tests/test_fts_examples.py`.
