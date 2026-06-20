# Fluent Bit Internal Tests

The following directory contains unit tests to validate specific functions of Fluent Bit core (not plugins).

## OpenTelemetry Test Cases

OpenTelemetry JSON tests are described in two separate files:

### Logs Test Cases (`data/opentelemetry/logs.json`)

Logs test cases validate the `flb_opentelemetry_logs_json_to_msgpack()` function.
Each entry is keyed by the test name and contains the following fields:

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

### Traces Test Cases (`data/opentelemetry/traces.json`)

Traces test cases validate the `flb_opentelemetry_json_traces_to_ctrace()` function.
Each entry is keyed by the test name and contains the following fields:

```
{
  "test_name": {
    "input": { ... },          # OTLP/JSON traces payload
    "expected": {               # successful result (optional)
      # For successful cases, the test validates that a valid ctrace object is created
    }
  },
  "error_case": {
    "input": { ... },
    "expected_error": {
      "code": "FLB_OTEL_TRACES_ERR_*",
      "message": "<error text>"
    }
  }
}
```

### Error Handling

When `expected_error` is present, the unit tests check that the respective functions fail with the given error code and message:

- **Logs**: `flb_opentelemetry_logs_json_to_msgpack()` should fail with `FLB_OTEL_LOGS_ERR_*` codes
- **Traces**: `flb_opentelemetry_json_traces_to_ctrace()` should fail with `FLB_OTEL_TRACES_ERR_*` codes

### Test Coverage

Both test files include comprehensive coverage for:

- **Valid payloads**: Successful processing of well-formed OTLP JSON
- **Invalid structure**: Missing required fields, wrong data types
- **Hex decoding errors**: Invalid trace_id/span_id formats, zero-length strings, odd-length hex
- **Field validation**: Required vs optional fields according to OpenTelemetry specification
- **Edge cases**: Empty payloads, malformed JSON, boundary conditions
