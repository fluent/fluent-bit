# Fluent Bit → Parseable Complex Data Demo

## Overview
This configuration sends multiple types of metrics and logs to Parseable at `localhost:8000` with authentication.

## Data Streams Being Sent

### 1. **CPU Metrics** → Stream: `cpu-metrics`
- **Frequency**: Every 1 second
- **Data includes**:
  - Overall CPU usage percentage
  - Per-core CPU statistics (user, system)
  - Environment metadata (production, main-cluster)
  - Hostname

**Sample Data**:
```json
{
  "cpu_p": 0.625,
  "user_p": 0.5,
  "system_p": 0.125,
  "cpu_stats": {
    "cpu0.p_cpu": 0.0,
    "cpu1.p_cpu": 1.0,
    "cpu2.p_cpu": 2.0
  },
  "environment": "production",
  "cluster": "main-cluster",
  "hostname": "docker-desktop"
}
```

### 2. **Memory Metrics** → Stream: `memory-metrics`
- **Frequency**: Every 1 second
- **Data includes**:
  - Total, used, and free memory
  - Swap usage statistics
  - Nested memory stats structure

**Sample Data**:
```json
{
  "memory_stats": {
    "Mem.total": 8025128,
    "Mem.used": 7912768,
    "Mem.free": 112360
  },
  "Swap.total": 1048572,
  "Swap.used": 0,
  "Swap.free": 1048572,
  "environment": "production"
}
```

### 3. **Disk I/O Metrics** → Stream: `disk-metrics`
- **Frequency**: Every 2 seconds
- **Data includes**:
  - Read/write sizes
  - I/O operations

**Sample Data**:
```json
{
  "read_size": 0,
  "write_size": 57344,
  "environment": "production",
  "cluster": "main-cluster"
}
```

### 4. **Network Metrics** → Stream: `network-metrics`
- **Frequency**: Every 2 seconds
- **Data includes**:
  - Bytes/packets received and transmitted
  - Network errors
  - Per-interface statistics (eth0)

**Sample Data**:
```json
{
  "eth0.rx.bytes": 330,
  "eth0.rx.packets": 5,
  "eth0.tx.bytes": 8986,
  "eth0.tx.packets": 9,
  "eth0.tx.errors": 0
}
```

### 5. **Application Logs** → Stream: `application-logs`
- **Frequency**: 2 records per second
- **Data includes**:
  - HTTP request details (method, path, status)
  - User information and tracking IDs
  - Performance metrics (duration_ms, response_size)
  - Rich metadata (region, datacenter, version)
  - Auto-enriched fields (severity, alert status, log_type)

**Sample Data**:
```json
{
  "timestamp": "2025-11-21T10:45:00Z",
  "level": "info",
  "service": "web-api",
  "host": "server-01",
  "request_id": "req-12345",
  "method": "POST",
  "path": "/api/users",
  "status": 200,
  "duration_ms": 45,
  "user_id": "user-789",
  "ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0",
  "response_size": 1024,
  "tags": ["production", "api", "success"],
  "metadata": {
    "region": "us-west-2",
    "datacenter": "dc1",
    "version": "v2.3.1"
  },
  "severity": "low",
  "alert": false,
  "log_type": "application",
  "category": "business_logic",
  "pipeline": "fluent-bit-parseable",
  "processed_at": "2025-11-21T18:47:01Z"
}
```

### 6. **Error Logs** → Stream: `error-logs`
- **Frequency**: 1 record per second
- **Data includes**:
  - Error codes and messages
  - Transaction details (ID, amount, currency)
  - Stack traces
  - Retry information
  - Auto-marked as high severity with alert flag

**Sample Data**:
```json
{
  "timestamp": "2025-11-21T10:45:00Z",
  "level": "error",
  "service": "payment-service",
  "host": "server-02",
  "error_code": "PAYMENT_FAILED",
  "error_message": "Transaction declined by bank",
  "transaction_id": "txn-98765",
  "amount": 150.50,
  "currency": "USD",
  "user_id": "user-456",
  "retry_count": 3,
  "stack_trace": "at processPayment (payment.js:123)\\nat handleRequest (server.js:456)",
  "tags": ["production", "payment", "failure"],
  "severity": "high",
  "alert": true,
  "log_type": "error",
  "category": "system_error",
  "pipeline": "fluent-bit-parseable"
}
```

### 7. **System Logs** → Stream: `system-logs`
- **Source**: `/var/log/syslog` (if available in container)
- **Includes**: System-level log messages with file path tracking

## Enrichment Features

### Automatic Enrichment via Lua Script
All logs are enriched with:
- **processed_at**: ISO8601 timestamp when processed
- **severity**: Calculated from log level (high/medium/low)
- **alert**: Boolean flag for critical issues
- **log_type**: Categorization (application/error/system)
- **category**: Business context (business_logic/system_error/infrastructure)
- **pipeline**: Tracking identifier
- **processed_by**: Fluent Bit version

### Global Metadata
All records include:
- **environment**: "production"
- **cluster**: "main-cluster"
- **fluent_bit_version**: "4.2.1"
- **hostname**: Container hostname

## Configuration Features

### Compression
- All outputs use **gzip compression** to reduce bandwidth

### Retry Logic
- **Retry_Limit**: 3 attempts for failed sends
- Automatic retry on network failures

### Authentication
- **Basic Auth**: admin:admin (base64 encoded)
- Sent with every request

### Multiple Streams
- 7 separate streams for organized data
- Different streams for different data types
- Easy filtering and querying in Parseable

## Running the Demo

```bash
docker run --rm --network host \
  -v "$PWD/parseable-demo.conf:/fluent-bit/etc/parseable-demo.conf" \
  -v "$PWD/enrich.lua:/fluent-bit/etc/enrich.lua" \
  fluent-bit-local:latest \
  /fluent-bit/bin/fluent-bit -c /fluent-bit/etc/parseable-demo.conf
```

## Files Created

1. **parseable-demo.conf** - Main Fluent Bit configuration
2. **enrich.lua** - Lua script for log enrichment
3. **PARSEABLE_DEMO_SUMMARY.md** - This documentation

## Data Volume

Approximate data generation:
- **CPU metrics**: ~1 record/sec = ~60/min
- **Memory metrics**: ~1 record/sec = ~60/min
- **Disk metrics**: ~0.5 records/sec = ~30/min
- **Network metrics**: ~0.5 records/sec = ~30/min
- **Application logs**: ~2 records/sec = ~120/min
- **Error logs**: ~1 record/sec = ~60/min

**Total**: ~360 records per minute across all streams

## Parseable Streams Created

Check your Parseable UI at `http://localhost:8000` for these streams:
1. cpu-metrics
2. memory-metrics
3. disk-metrics
4. network-metrics
5. application-logs
6. error-logs
7. system-logs
