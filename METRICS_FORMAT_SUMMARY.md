# Fluent Bit Metrics Format for Parseable

## Overview
CPU, Memory, Disk, and Network metrics are now sent to Parseable with proper metrics metadata fields, making them identifiable as metrics rather than plain logs.

## Metrics Stream Configuration

All system metrics are sent to a unified **`metrics`** stream in Parseable with the following structure:

### CPU Metrics
```json
{
  "date": 1763751020.128289,
  "metric_type": "gauge",
  "metric_name": "cpu_usage",
  "unit": "percent",
  "user_p": 0.25,
  "system_p": 0.125,
  "cpu_stats": {
    "cpu_p": 0.375,
    "cpu0.p_cpu": 0.0,
    "cpu1.p_cpu": 0.0,
    "cpu2.p_cpu": 0.0
  },
  "environment": "production",
  "cluster": "main-cluster",
  "hostname": "docker-desktop"
}
```

### Memory Metrics
```json
{
  "date": 1763751020.128365,
  "metric_type": "gauge",
  "metric_name": "memory_usage",
  "unit": "bytes",
  "memory_stats": {
    "Mem.total": 8025128,
    "Mem.used": 7890476,
    "Mem.free": 134652
  },
  "Swap.total": 1048572,
  "Swap.used": 0,
  "Swap.free": 1048572,
  "environment": "production",
  "cluster": "main-cluster",
  "hostname": "docker-desktop"
}
```

### Disk I/O Metrics
```json
{
  "date": 1763751020.128402,
  "metric_type": "counter",
  "metric_name": "disk_io",
  "unit": "bytes",
  "read_size": 0,
  "write_size": 57344,
  "environment": "production",
  "cluster": "main-cluster",
  "hostname": "docker-desktop"
}
```

### Network Metrics
```json
{
  "date": 1763751020.128450,
  "metric_type": "counter",
  "metric_name": "network_io",
  "unit": "bytes",
  "eth0.rx.bytes": 330,
  "eth0.rx.packets": 5,
  "eth0.tx.bytes": 8986,
  "eth0.tx.packets": 9,
  "eth0.tx.errors": 0,
  "environment": "production",
  "cluster": "main-cluster",
  "hostname": "docker-desktop"
}
```

## Metric Metadata Fields

All metrics include these standard fields:

| Field | Description | Values |
|-------|-------------|--------|
| `metric_type` | Type of metric | `gauge` (point-in-time value) or `counter` (cumulative) |
| `metric_name` | Name identifying the metric | `cpu_usage`, `memory_usage`, `disk_io`, `network_io` |
| `unit` | Unit of measurement | `percent`, `bytes` |
| `date` | Unix timestamp with microseconds | e.g., `1763751020.128289` |

## Additional Context Fields

All metrics also include:
- `environment`: "production"
- `cluster`: "main-cluster"  
- `fluent_bit_version`: "4.2.1"
- `hostname`: Container/host identifier

## Parseable Query Examples

### Query CPU metrics
```sql
SELECT 
  date,
  metric_name,
  cpu_stats.cpu_p as overall_cpu,
  hostname
FROM metrics
WHERE metric_name = 'cpu_usage'
ORDER BY date DESC
LIMIT 100
```

### Query Memory metrics
```sql
SELECT 
  date,
  metric_name,
  memory_stats.Mem.used / memory_stats.Mem.total * 100 as memory_percent,
  hostname
FROM metrics
WHERE metric_name = 'memory_usage'
ORDER BY date DESC
LIMIT 100
```

### Query all metrics by type
```sql
SELECT 
  metric_name,
  metric_type,
  COUNT(*) as count,
  AVG(CASE WHEN metric_name = 'cpu_usage' THEN cpu_stats.cpu_p END) as avg_cpu
FROM metrics
WHERE metric_type = 'gauge'
GROUP BY metric_name, metric_type
```

## Configuration Details

### Filters Applied
Each metric type has a dedicated filter that adds metadata:

```ini
[FILTER]
    Name          modify
    Match         metrics.cpu
    Add           metric_type gauge
    Add           metric_name cpu_usage
    Add           unit percent
```

### Unified Output
All metrics are sent through a single output:

```ini
[OUTPUT]
    Name          parseable
    Match         metrics.*
    Host          localhost
    Port          8000
    TLS           Off
    Stream        metrics
    auth_header   Basic YWRtaW46YWRtaW4=
    compress      gzip
    Retry_Limit   3
```

## Benefits of This Approach

1. **Unified Stream**: All metrics in one Parseable stream for easier querying
2. **Type Safety**: `metric_type` field clearly identifies gauge vs counter metrics
3. **Searchability**: `metric_name` allows filtering specific metric types
4. **Unit Clarity**: `unit` field documents measurement units
5. **Compression**: Gzip reduces bandwidth usage
6. **Rich Context**: Nested structures (cpu_stats, memory_stats) preserve detail
7. **Metadata**: Environment, cluster, hostname for multi-environment setups

## Streams Summary

| Stream | Purpose | Record Types |
|--------|---------|--------------|
| `metrics` | All system metrics | CPU, Memory, Disk, Network (with metric_type field) |
| `application-logs` | Application request logs | HTTP requests, API calls |
| `error-logs` | Error and failure logs | Payment failures, exceptions |
| `system-logs` | System-level logs | Syslog entries |

## Running

```bash
docker run --rm --network host \
  -v "$PWD/parseable-demo.conf:/fluent-bit/etc/parseable-demo.conf" \
  -v "$PWD/enrich.lua:/fluent-bit/etc/enrich.lua" \
  fluent-bit-local:latest \
  /fluent-bit/bin/fluent-bit -c /fluent-bit/etc/parseable-demo.conf
```

Access Parseable UI at: http://localhost:8000
