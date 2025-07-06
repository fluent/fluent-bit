# Fluent Bit Internal Tests

The following directory contains unit tests to validate specific functions of Fluent Bit core (not plugins).

## OpenTelemetry Test Cases

OpenTelemetry JSON tests are described in a single file located at
`data/opentelemetry/test_cases.json`. Each entry is keyed by the test name and
contains the following fields:

```
{
  "test_name": {
    "input": { ... },          # OTLP/JSON payload
    "expected": {               # successful result
      "metadata": { ... },
      "body": { ... },
      "log": { ... }
    }
  },
  "error_case": {
    "input": { ... },
    "expected_error": {
      "code": "FLB_OTEL_LOGS_ERR_*",
      "message": "<error text>"
    }
  }
}
```

When `expected_error` is present the unit test checks that
`flb_opentelemetry_logs_json_to_msgpack()` fails with the given error code and
message.
