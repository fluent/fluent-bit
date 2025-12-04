# Fluent Bit → Parseable Final Configuration

## ✅ Successfully Configured

### Plugin Updates
1. **Endpoints**: `/v1/metrics` and `/v1/logs` (without `/api/` prefix)
2. **Data Format**: JSON arrays `[{...}, {...}]` instead of newline-delimited JSON
3. **Headers**: 
   - `X-P-Stream`: Stream name
   - `X-P-Log-Source`: `otel-metrics` or `otel-logs`
   - `Authorization`: Basic auth

### Current Configuration

#### Metrics Output
```ini
[OUTPUT]
    Name          parseable
    Match         metrics.*
    Host          localhost
    Port          8000
    TLS           Off
    Stream        metrics
    data_type     metrics
    log_source    otel-metrics
    auth_header   Basic YWRtaW46YWRtaW4=
    compress      gzip
```
**Sends to**: `http://localhost:8000/v1/metrics`  
**Stream**: `metrics`  
**Data includes**: `metric_type`, `metric_name`, `unit`, `cpu_stats`, etc.

#### Application Logs Output
```ini
[OUTPUT]
    Name          parseable
    Match         logs.application
    Host          localhost
    Port          8000
    TLS           Off
    Stream        application-logs
    data_type     logs
    log_source    otel-logs
    auth_header   Basic YWRtaW46YWRtaW4=
    compress      gzip
```
**Sends to**: `http://localhost:8000/v1/logs`  
**Stream**: `application-logs`  
**Data includes**: `level`, `service`, `request_id`, `status`, etc.

#### Error Logs Output
```ini
[OUTPUT]
    Name          parseable
    Match         logs.errors
    Host          localhost
    Port          8000
    TLS           Off
    Stream        error-logs
    data_type     logs
    log_source    otel-logs
    auth_header   Basic YWRtaW46YWRtaW4=
    compress      gzip
```
**Sends to**: `http://localhost:8000/v1/logs`  
**Stream**: `error-logs`  
**Data includes**: `level`, `error_code`, `error_message`, `stack_trace`, etc.

## Current Error

```
Datafusion Error: Schema error: No field named metric_type.
```

### Analysis

This error suggests:
1. ✅ Data is being accepted by Parseable (no more 400 errors about format)
2. ✅ JSON array format is working
3. ⚠️ The query or stream schema doesn't have the `metric_type` field

### Possible Causes

1. **Stream Created with Wrong Schema**: The `metrics` stream may have been created without the `metric_type` field
2. **Data Sent to Wrong Stream**: Metrics data might be going to a logs stream
3. **Query Issue**: The query being run doesn't match the actual schema

### Sample Metrics Data Being Sent

```json
[
  {
    "date": 1763752806.577653,
    "metric_type": "gauge",
    "metric_name": "cpu_usage",
    "unit": "percent",
    "user_p": 0.125,
    "system_p": 0.125,
    "cpu_stats": {
      "cpu_p": 0.25,
      "cpu0.p_cpu": 0.0,
      ...
    },
    "environment": "production",
    "cluster": "main-cluster",
    "hostname": "docker-desktop"
  }
]
```

### Sample Logs Data Being Sent

```json
[
  {
    "date": 1763752806.577159,
    "level": "info",
    "service": "web-api",
    "request_id": "req-12345",
    "method": "POST",
    "path": "/api/users",
    "status": 200,
    "duration_ms": 45,
    "user_id": "user-789",
    "log_type": "application",
    "severity": "low",
    "environment": "production"
  }
]
```

## Recommendations

### Option 1: Delete and Recreate Streams
Delete the existing streams on Parseable and let them be recreated with the correct schema:

```bash
# Delete streams (adjust URL/auth as needed)
curl -X DELETE http://localhost:8000/api/v1/logstream/metrics \
  -H "Authorization: Basic YWRtaW46YWRtaW4="

curl -X DELETE http://localhost:8000/api/v1/logstream/application-logs \
  -H "Authorization: Basic YWRtaW46YWRtaW4="

curl -X DELETE http://localhost:8000/api/v1/logstream/error-logs \
  -H "Authorization: Basic YWRtaW46YWRtaW4="
```

### Option 2: Use Different Stream Names
Update the configuration to use fresh stream names:

```ini
# For metrics
Stream        fluent-bit-metrics-v2

# For logs
Stream        fluent-bit-app-logs-v2
Stream        fluent-bit-error-logs-v2
```

### Option 3: Check Parseable Stream Schema
Query Parseable to see what schema the streams have:

```bash
curl http://localhost:8000/api/v1/logstream/metrics/schema \
  -H "Authorization: Basic YWRtaW46YWRtaW4="
```

## Verification

Once streams are recreated, verify data is flowing:

```bash
# Check metrics stream
curl "http://localhost:8000/api/v1/query" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SELECT * FROM metrics LIMIT 10",
    "startTime": "2025-11-21T00:00:00Z",
    "endTime": "2025-11-21T23:59:59Z"
  }'

# Check application logs
curl "http://localhost:8000/api/v1/query" \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SELECT * FROM \"application-logs\" LIMIT 10",
    "startTime": "2025-11-21T00:00:00Z",
    "endTime": "2025-11-21T23:59:59Z"
  }'
```

## Files Modified

1. `/plugins/out_parseable/parseable.h` - Added data_type field
2. `/plugins/out_parseable/parseable.c` - Updated endpoints and JSON array formatting
3. `/Dockerfile` - Already had FLB_OUT_PARSEABLE=On
4. `/parseable-demo.conf` - Updated with data_type and log_source parameters
