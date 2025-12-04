# Parseable Output Plugin - Implementation Guide

This document provides technical details about the implementation of the Parseable output plugin.

## File Structure

```
plugins/out_parseable/
├── CMakeLists.txt              # Build configuration
├── parseable.h                 # Header file with constants and structures
├── parseable.c                 # Main implementation
├── README.md                   # User documentation
├── FEATURES.md                 # Feature summary
├── IMPLEMENTATION.md           # This file
└── parseable_example.conf      # Example configuration
```

## Header File (parseable.h)

### Purpose
The header file defines:
- Default configuration constants
- HTTP header constants
- Enum-like constants for options
- The main plugin context structure

### Key Constants

```c
// Connection defaults
FLB_PARSEABLE_DEFAULT_HOST        "127.0.0.1"
FLB_PARSEABLE_DEFAULT_PORT        8000
FLB_PARSEABLE_DEFAULT_URI         "/api/v1/ingest"
FLB_PARSEABLE_DEFAULT_TIME_KEY    "timestamp"
FLB_PARSEABLE_DEFAULT_BATCH_SIZE  5242880  /* 5MB */

// HTTP headers
FLB_PARSEABLE_CONTENT_TYPE        "Content-Type"
FLB_PARSEABLE_MIME_JSON           "application/json"
FLB_PARSEABLE_HEADER_STREAM       "X-P-Stream"
FLB_PARSEABLE_HEADER_LOG_SOURCE   "X-P-Log-Source"

// JSON date formats
FLB_PARSEABLE_JSON_DATE_EPOCH              0
FLB_PARSEABLE_JSON_DATE_ISO8601            1
FLB_PARSEABLE_JSON_DATE_JAVA_SQL_TIMESTAMP 2

// Compression
FLB_PARSEABLE_COMPRESS_NONE       0
FLB_PARSEABLE_COMPRESS_GZIP       1

// Retry limits
FLB_PARSEABLE_RETRY_UNLIMITED     -1
FLB_PARSEABLE_RETRY_NONE          0
```

### Context Structure

```c
struct flb_out_parseable {
    // Connection
    flb_sds_t host;
    int port;
    flb_sds_t uri;
    
    // Parseable headers
    flb_sds_t stream;
    flb_sds_t log_source;
    flb_sds_t auth_header;
    
    // Custom headers
    struct mk_list *headers;
    
    // Format
    int json_date_format;
    flb_sds_t date_key;
    
    // Features
    int compress_gzip;
    size_t batch_size;
    int retry_limit;
    
    // Metrics
    struct cmt_counter *cmt_requests_total;
    struct cmt_counter *cmt_errors_total;
    struct cmt_counter *cmt_records_total;
    struct cmt_counter *cmt_bytes_total;
    struct cmt_gauge *cmt_batch_size_bytes;
    
    // Upstream
    struct flb_upstream *u;
    struct flb_output_instance *ins;
};
```

## Implementation File (parseable.c)

### Function Overview

#### 1. `cb_parseable_init()`
**Purpose**: Initialize plugin context and validate configuration

**Flow**:
1. Allocate context structure
2. Set default network configuration
3. Load configuration map
4. Validate required parameters (stream)
5. Parse compression settings
6. Create upstream connection
7. Initialize metrics
8. Set plugin context

**Key Operations**:
- Uses `flb_output_config_map_set()` for automatic config parsing
- Creates cmetrics counters and gauges
- Validates `stream` parameter (required)

#### 2. `parseable_format_json()`
**Purpose**: Convert msgpack to JSON format

**Flow**:
1. Determine JSON date format from config
2. Call `flb_pack_msgpack_to_json_format()`
3. Return JSON string and size

**Supported Formats**:
- Epoch (seconds since 1970)
- ISO8601 (YYYY-MM-DDTHH:MM:SS.sssZ)
- Java SQL Timestamp

#### 3. `parseable_http_post()`
**Purpose**: Send HTTP POST request to Parseable

**Flow**:
1. Get upstream connection
2. Compress payload if enabled
3. Update batch size metric
4. Create HTTP client
5. Add headers:
   - Content-Type
   - Content-Encoding (if compressed)
   - X-P-Stream
   - X-P-Log-Source (optional)
   - Authorization (optional)
   - Custom headers
6. Perform HTTP request
7. Update metrics based on response
8. Determine retry strategy
9. Cleanup

**Retry Logic**:
- **Retry**: 5xx, 429, 408, network errors
- **No Retry**: 4xx (except 429, 408)
- **Success**: 2xx

**Metrics Updated**:
- `requests_total` (with status label)
- `errors_total` (with type label)
- `records_total` (on success)
- `bytes_total` (on success)
- `batch_size_bytes` (always)

#### 4. `cb_parseable_flush()`
**Purpose**: Main flush callback, processes event chunks

**Flow**:
1. Check retry limit
2. Count records in chunk
3. Check batch size limit (warn if exceeded)
4. Format data to JSON
5. Send HTTP POST
6. Cleanup

**Retry Limit Handling**:
- Checks `ctx->ins->retry_requests` against `ctx->retry_limit`
- Discards chunk if limit exceeded
- Prevents infinite retry loops

#### 5. `cb_parseable_exit()`
**Purpose**: Cleanup on plugin shutdown

**Flow**:
1. Destroy upstream connection
2. Free context structure

**Note**: Metrics are automatically cleaned up by Fluent Bit

## Configuration Map

The plugin uses Fluent Bit's config map system for automatic parameter parsing:

```c
static struct flb_config_map config_map[] = {
    // String parameters
    FLB_CONFIG_MAP_STR with offsetof()
    
    // Integer parameters
    FLB_CONFIG_MAP_INT with offsetof()
    
    // Size parameters (supports K, M, G suffixes)
    FLB_CONFIG_MAP_SIZE with offsetof()
    
    // Multiple string list parameters
    FLB_CONFIG_MAP_SLIST_1 with FLB_CONFIG_MAP_MULT
};
```

## Metrics Implementation

### Metric Types

**Counters** (monotonically increasing):
- `parseable_requests_total{status}`
- `parseable_errors_total{type}`
- `parseable_records_total`
- `parseable_bytes_total`

**Gauges** (can increase/decrease):
- `parseable_batch_size_bytes`

### Metric Creation

```c
ctx->cmt_requests_total = cmt_counter_create(
    ins->cmt,           // metrics context
    "parseable",        // namespace
    "requests",         // subsystem
    "total",            // name
    "description",      // help text
    1,                  // number of labels
    (char *[]) {"status"}  // label names
);
```

### Metric Updates

```c
// Increment counter
cmt_counter_inc(ctx->cmt_requests_total, timestamp, 
                1, (char *[]) {"200"});

// Add to counter
cmt_counter_add(ctx->cmt_records_total, timestamp, 
                record_count, 0, NULL);

// Set gauge
cmt_gauge_set(ctx->cmt_batch_size_bytes, timestamp, 
              payload_size, 0, NULL);
```

## Compression Implementation

Uses Fluent Bit's built-in gzip compression:

```c
ret = flb_gzip_compress(
    (void *) body,      // input buffer
    body_len,           // input size
    &payload_buf,       // output buffer (allocated)
    &payload_size       // output size
);
```

**Important**: 
- Output buffer is allocated by `flb_gzip_compress()`
- Must be freed with `flb_free()` after use
- Falls back to uncompressed on failure

## Custom Headers Implementation

Uses Fluent Bit's config map multi-value list:

```c
// Config map entry
{
 FLB_CONFIG_MAP_SLIST_1, "header", NULL,
 FLB_CONFIG_MAP_MULT, FLB_TRUE, 
 offsetof(struct flb_out_parseable, headers),
 "Add custom HTTP header"
}

// Iteration
flb_config_map_foreach(head, mv, ctx->headers) {
    key = mk_list_entry_first(mv->val.list, ...);
    val = mk_list_entry_last(mv->val.list, ...);
    flb_http_add_header(c, key->str, ..., val->str, ...);
}
```

## Error Handling

### Error Types Tracked

1. **connection**: Failed to get upstream connection
2. **http_client**: Failed to create HTTP client
3. **http_error**: HTTP response error (non-2xx)
4. **network**: Network/transport error

### Return Codes

- `FLB_OK`: Success
- `FLB_RETRY`: Transient error, retry
- `FLB_ERROR`: Permanent error, discard

## Testing Checklist

### Unit Testing
- [ ] Config parsing with valid values
- [ ] Config parsing with invalid values
- [ ] Required parameter validation
- [ ] Default value handling

### Integration Testing
- [ ] Successful data transmission
- [ ] Compression enabled/disabled
- [ ] Custom headers present in requests
- [ ] Batch size warnings
- [ ] Retry limit enforcement
- [ ] Metrics increment correctly
- [ ] TLS connection
- [ ] Authentication

### Performance Testing
- [ ] High throughput (>10K records/sec)
- [ ] Large batches (>10MB)
- [ ] Compression CPU overhead
- [ ] Memory usage under load
- [ ] Connection pooling

## Build Integration

### CMakeLists.txt

```cmake
set(src
  parseable.c
)

FLB_PLUGIN(out_parseable "${src}" "")
```

### Plugin Registration

In `plugins/CMakeLists.txt`:
```cmake
REGISTER_OUT_PLUGIN("out_parseable")
```

This generates code in `flb_plugins.h`:
```c
extern struct flb_output_plugin out_parseable_plugin;

// In flb_plugins_register():
out = flb_malloc(sizeof(struct flb_output_plugin));
memcpy(out, &out_parseable_plugin, sizeof(struct flb_output_plugin));
mk_list_add(&out->_head, &config->out_plugins);
```

## Dependencies

### Fluent Bit Libraries
- `flb_output_plugin.h` - Output plugin interface
- `flb_http_client.h` - HTTP client
- `flb_pack.h` - Msgpack to JSON conversion
- `flb_gzip.h` - Compression
- `flb_config_map.h` - Configuration parsing
- `flb_upstream.h` - Connection management

### External Libraries
- `cmetrics` - Metrics library
- `msgpack` - Message pack parsing

## Future Enhancements

### Potential Additions
1. **Snappy/Zstd compression** - Additional compression algorithms
2. **Batch splitting** - Automatic split of oversized batches
3. **Circuit breaker** - Prevent overwhelming failed endpoints
4. **Request pooling** - Reuse HTTP connections
5. **Async metrics** - Non-blocking metrics updates
6. **Health checks** - Periodic endpoint health verification

### Code Locations for Extensions

- **New compression**: Add in `parseable_http_post()` after line 319
- **Batch splitting**: Add in `cb_parseable_flush()` before line 510
- **Circuit breaker**: Add state to context, check in `parseable_http_post()`
- **New metrics**: Add to context, initialize in `cb_parseable_init()`
