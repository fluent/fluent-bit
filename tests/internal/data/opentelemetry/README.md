# OpenTelemetry Test Cases

This directory contains test cases for the OpenTelemetry JSON to MessagePack conversion functionality.

## Test Case Format

### Legacy Format (Single Group, Single Record)

The legacy format supports testing a single group with a single record:

```json
{
  "test_case_name": {
    "input": {
      "resourceLogs": [{
        "scopeLogs": [{
          "logRecords": [{
            "timeUnixNano": "1640995200000000000",
            "body": {"stringValue": "test log message"}
          }]
        }]
      }]
    },
    "expected": {
      "group_metadata": {"schema":"otlp","resource_id":0,"scope_id":0},
      "group_body": {"resource":{}},
      "log_metadata": {"otlp":{}},
      "log_body": {"log": "test log message"}
    }
  }
}
```

### Extended Format (Multiple Groups, Multiple Records)

The extended format supports testing multiple groups with multiple records each:

```json
{
  "test_case_name": {
    "input": {
      "resourceLogs": [
        {
          "resource": {
            "attributes": [
              {"key": "service.name", "value": {"stringValue": "service-1"}}
            ]
          },
          "scopeLogs": [
            {
              "scope": {
                "name": "scope-1",
                "version": "1.0.0"
              },
              "logRecords": [
                {
                  "timeUnixNano": "1640995200000000000",
                  "body": {"stringValue": "first log from service-1 scope-1"}
                },
                {
                  "timeUnixNano": "1640995201000000000",
                  "body": {"stringValue": "second log from service-1 scope-1"}
                }
              ]
            }
          ]
        }
      ]
    },
    "expected": {
      "groups": [
        {
          "metadata": {"schema":"otlp","resource_id":0,"scope_id":0},
          "body": {
            "resource": {
              "attributes": {"service.name":"service-1"}
            },
            "scope": {
              "name": "scope-1",
              "version": "1.0.0"
            }
          },
          "records": [
            {
              "metadata": {"otlp":{}},
              "body": {"log": "first log from service-1 scope-1"}
            },
            {
              "metadata": {"otlp":{}},
              "body": {"log": "second log from service-1 scope-1"}
            }
          ]
        }
      ]
    }
  }
}
```

## Structure Explanation

### Input Format
- `resourceLogs`: Array of resource logs
  - `resource`: Resource attributes and metadata
  - `scopeLogs`: Array of scope logs
    - `scope`: Scope metadata (name, version, attributes)
    - `logRecords`: Array of log records
      - `timeUnixNano`: Timestamp in nanoseconds
      - `body`: Log body content
      - `attributes`: Log attributes (optional)
      - `traceId`: Trace ID (optional)
      - `spanId`: Span ID (optional)

### Expected Output Format

#### Legacy Format
- `group_metadata`: Expected group metadata
- `group_body`: Expected group body
- `log_metadata`: Expected log metadata
- `log_body`: Expected log body

#### Extended Format
- `groups`: Array of expected groups
  - `metadata`: Group metadata
  - `body`: Group body
  - `records`: Array of expected records
    - `metadata`: Record metadata
    - `body`: Record body

## Error Cases

For error cases, use the `expected_error` field:

```json
{
  "test_case_name": {
    "input": { ... },
    "expected_error": {
      "code": "FLB_OTEL_LOGS_ERR_UNEXPECTED_LOGRECORDS_ENTRY_TYPE"
    }
  }
}
```

## Empty Payload Cases

For cases where no data should be ingested:

```json
{
  "test_case_name": {
    "input": { ... },
    "expected": {
      "empty_payload": true
    }
  }
}
```

## Backward Compatibility

The test framework automatically detects whether a test case uses the legacy or extended format:
- If `expected` contains a `groups` field, it uses the extended format
- Otherwise, it falls back to the legacy format

This ensures all existing test cases continue to work without modification.