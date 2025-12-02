# Parseable Output Plugin for Fluent Bit

This output plugin sends log data to [Parseable](https://www.parseable.com/), a log analytics system.

## Configuration Parameters

| Key | Description | Default | Required |
|-----|-------------|---------|----------|
| `Host` | Parseable server hostname | `127.0.0.1` | No |
| `Port` | Parseable server port | `8000` | No |
| `stream` | Parseable stream name (sent as `X-P-Stream` header) | - | **Yes** |
| `log_source` | Log source identifier (sent as `X-P-Log-Source` header) | - | No |
| `uri` | URI path for ingestion endpoint | `/api/v1/ingest` | No |
| `auth_header` | Authorization header value (e.g., `Basic <base64>`) | - | No |
| `json_date_format` | JSON date format: `0`=epoch, `1`=iso8601, `2`=java_sql_timestamp | `0` | No |
| `json_date_key` | Key name for timestamp in JSON output | `timestamp` | No |
| `compress` | Enable payload compression: `gzip` | - | No |
| `batch_size` | Maximum batch size in bytes | `5242880` (5MB) | No |
| `retry_limit` | Maximum number of retries (`-1` = unlimited, `0` = no retries) | `-1` | No |
| `header` | Add custom HTTP header (can be specified multiple times) | - | No |
| `tls` | Enable TLS/SSL | `Off` | No |
| `tls.verify` | Verify TLS certificate | `On` | No |

## Example Configuration

### Basic Configuration
```ini
[OUTPUT]
    Name          parseable
    Match         *
    Host          parseable.example.com
    Port          443
    stream        my-application-logs
    log_source    production-server-01
    auth_header   Basic YWRtaW46cGFzc3dvcmQ=
    tls           On
    tls.verify    On
```

### Advanced Configuration with All Features
```ini
[OUTPUT]
    Name          parseable
    Match         *
    Host          parseable.example.com
    Port          443
    stream        my-application-logs
    log_source    production-server-01
    uri           /api/v1/ingest
    
    # Authentication
    auth_header   Basic YWRtaW46cGFzc3dvcmQ=
    
    # Compression
    compress      gzip
    
    # Batch size limit (10MB)
    batch_size    10485760
    
    # Retry configuration (max 5 retries)
    retry_limit   5
    
    # Custom headers
    header        X-Custom-Header Custom-Value
    header        X-Environment production
    header        X-Region us-east-1
    
    # TLS
    tls           On
    tls.verify    On
    
    # JSON formatting
    json_date_format  1
    json_date_key     timestamp
```

## How It Works

1. **Data Format**: The plugin converts Fluent Bit's internal msgpack format to JSON
2. **Compression**: Optionally compresses payload using gzip before sending
3. **Batch Size Control**: Monitors and warns if batch exceeds configured limit
4. **HTTP POST**: Sends data via HTTP POST to the configured Parseable endpoint
5. **Headers**: Automatically adds required Parseable headers:
   - `Content-Type: application/json`
   - `Content-Encoding: gzip` (if compression enabled)
   - `X-P-Stream: <stream-name>`
   - `X-P-Log-Source: <log-source>` (if configured)
   - `Authorization: <auth-header>` (if configured)
   - Custom headers (if configured)
6. **Retry Logic**: Implements configurable retry limits with smart retry decisions
7. **Metrics**: Tracks requests, errors, records, bytes, and batch sizes

## Building

The plugin is built as part of the main Fluent Bit build process:

```bash
cd fluent-bit/build
cmake ..
make
```

## Testing

1. Start a Parseable instance (see [Parseable docs](https://www.parseable.com/docs))

2. Create a test configuration file:

```ini
[SERVICE]
    Flush     5
    Log_Level info

[INPUT]
    Name   dummy
    Tag    test

[OUTPUT]
    Name    parseable
    Match   *
    Host    localhost
    Port    8000
    stream  test-stream
```

3. Run Fluent Bit:

```bash
./bin/fluent-bit -c parseable_test.conf
```

## Authentication

To use basic authentication with Parseable:

1. Encode your credentials:
   ```bash
   echo -n "username:password" | base64
   ```

2. Add to configuration:
   ```ini
   auth_header   Basic <base64-encoded-credentials>
   ```

## Error Handling

- **HTTP 2xx**: Success, data accepted
- **HTTP 429, 408**: Retryable errors (rate limit, timeout)
- **HTTP 5xx**: Server errors, will retry
- **HTTP 4xx** (except 429, 408): Client errors, will not retry

## Troubleshooting

Enable debug logging to see detailed HTTP interactions:

```ini
[SERVICE]
    Log_Level debug
```

Check for common issues:
- Ensure `stream` parameter is set (required)
- Verify Parseable server is accessible
- Check authentication credentials if using `auth_header`
- Verify TLS settings if using HTTPS
- Check batch_size if seeing warnings about large chunks
- Verify compression is working if enabled

## Metrics

The plugin exposes the following metrics via Fluent Bit's metrics endpoint:

### Counters

- **`parseable_requests_total{status="<http_status>"}`**: Total number of HTTP requests by status code
- **`parseable_errors_total{type="<error_type>"}`**: Total number of errors by type
  - Types: `connection`, `http_client`, `http_error`, `network`
- **`parseable_records_total`**: Total number of log records successfully sent
- **`parseable_bytes_total`**: Total bytes sent (after compression if enabled)

### Gauges

- **`parseable_batch_size_bytes`**: Current batch size in bytes

### Viewing Metrics

Enable the built-in HTTP server in Fluent Bit to expose metrics:

```ini
[SERVICE]
    HTTP_Server  On
    HTTP_Listen  0.0.0.0
    HTTP_Port    2020

[OUTPUT]
    Name       parseable
    Match      *
    stream     my-stream
```

Access metrics at: `http://localhost:2020/api/v1/metrics/prometheus`

## Performance Tuning

### Compression

Enable gzip compression to reduce network bandwidth:

```ini
compress  gzip
```

Compression typically reduces payload size by 60-80% but adds CPU overhead.

### Batch Size

Adjust batch size based on your network and Parseable capacity:

```ini
# For high-throughput scenarios (10MB)
batch_size  10485760

# For low-latency scenarios (1MB)
batch_size  1048576
```

### Retry Configuration

Configure retry behavior based on your reliability requirements:

```ini
# Unlimited retries (default)
retry_limit  -1

# No retries (fail fast)
retry_limit  0

# Limited retries (balance reliability and latency)
retry_limit  3
```

### Custom Headers

Add custom headers for routing, authentication, or metadata:

```ini
header  X-Environment production
header  X-Datacenter us-east-1
header  X-Application my-app
```

## Kubernetes Autodiscovery

The Parseable plugin supports Datadog-like autodiscovery for Kubernetes. This allows you to add annotations to your pods to automatically route logs to different Parseable streams.

### Enable Dynamic Stream Routing

```ini
[OUTPUT]
    Name           parseable
    Match          parseable.*
    Host           parseable.example.com
    Port           8000
    dynamic_stream On
    log_source     kubernetes
    auth_header    Basic YWRtaW46cGFzc3dvcmQ=
```

### Supported Pod Annotations

| Annotation | Description | Example |
|------------|-------------|---------|
| `parseable.io/stream` | Target Parseable stream name | `parseable.io/stream: "my-app-logs"` |
| `parseable.io/log-source` | Log source type | `parseable.io/log-source: "otel-logs"` |
| `parseable.io/exclude` | Exclude logs from this pod | `parseable.io/exclude: "true"` |
| `parseable.io/env` | Environment tag | `parseable.io/env: "production"` |
| `parseable.io/service` | Service name tag | `parseable.io/service: "api-gateway"` |
| `parseable.io/version` | Version tag | `parseable.io/version: "v1.2.3"` |

### Example Pod with Annotations

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-application
  annotations:
    parseable.io/stream: "my-app-logs"
    parseable.io/env: "production"
    parseable.io/service: "my-app"
    parseable.io/version: "v1.0.0"
spec:
  containers:
  - name: app
    image: my-app:latest
```

### Complete Kubernetes Setup

See the `k8s/` directory for complete DaemonSet configuration and example deployments:

- `k8s/parseable-fluent-bit-daemonset.yaml` - Full DaemonSet with Lua filter for annotation processing
- `k8s/example-app-with-annotations.yaml` - Example applications with various annotation patterns
- `scripts/parseable_routing.lua` - Lua filter script for processing annotations
