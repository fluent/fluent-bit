# Parseable Plugin Endpoint Update

## Changes Made

The Fluent Bit parseable output plugin has been updated to support different API endpoints for logs, metrics, and traces.

### New Configuration Parameter: `data_type`

**Parameter**: `data_type`  
**Values**: `logs`, `metrics`, `traces`  
**Default**: `logs`

This parameter automatically sets the correct Parseable API endpoint:

| data_type | Endpoint |
|-----------|----------|
| `logs` | `/api/v1/logs` |
| `metrics` | `/api/v1/metrics` |
| `traces` | `/api/v1/traces` |

### Code Changes

#### 1. parseable.h
- Added `flb_sds_t data_type` field to `struct flb_out_parseable`
- Removed `FLB_PARSEABLE_DEFAULT_URI` constant (now auto-set based on data_type)

#### 2. parseable.c
- Added `data_type` configuration parameter to config_map
- Updated `uri` parameter to be optional (auto-set if not provided)
- Added logic in `cb_parseable_init()` to automatically set URI based on data_type:
  ```c
  if (!ctx->uri) {
      if (ctx->data_type) {
          if (strcasecmp(ctx->data_type, "metrics") == 0) {
              ctx->uri = flb_sds_create("/api/v1/metrics");
          }
          else if (strcasecmp(ctx->data_type, "traces") == 0) {
              ctx->uri = flb_sds_create("/api/v1/traces");
          }
          else {
              ctx->uri = flb_sds_create("/api/v1/logs");
          }
      }
  }
  ```

### Configuration Examples

#### Sending Metrics
```ini
[OUTPUT]
    Name          parseable
    Match         metrics.*
    Host          localhost
    Port          8000
    Stream        metrics
    data_type     metrics
    auth_header   Basic YWRtaW46YWRtaW4=
```
**Result**: Data sent to `http://localhost:8000/api/v1/metrics`

#### Sending Logs
```ini
[OUTPUT]
    Name          parseable
    Match         logs.*
    Host          localhost
    Port          8000
    Stream        application-logs
    data_type     logs
    auth_header   Basic YWRtaW46YWRtaW4=
```
**Result**: Data sent to `http://localhost:8000/api/v1/logs`

#### Sending Traces
```ini
[OUTPUT]
    Name          parseable
    Match         traces.*
    Host          localhost
    Port          8000
    Stream        distributed-traces
    data_type     traces
    auth_header   Basic YWRtaW46YWRtaW4=
```
**Result**: Data sent to `http://localhost:8000/api/v1/traces`

#### Manual URI Override
You can still manually specify the URI if needed:
```ini
[OUTPUT]
    Name          parseable
    Match         *
    Host          localhost
    Port          8000
    Stream        custom-stream
    uri           /api/v2/custom/endpoint
    auth_header   Basic YWRtaW46YWRtaW4=
```

### Backward Compatibility

- **Default behavior**: If `data_type` is not specified, it defaults to `logs` and uses `/api/v1/logs`
- **Manual URI**: If `uri` is explicitly set, it takes precedence over `data_type`
- **Old configurations**: Existing configurations without `data_type` will automatically use `/api/v1/logs`

### Verification

Check the Fluent Bit logs on startup to see which endpoint is being used:

```
[info] [output:parseable:parseable.0] auto-set URI to /api/v1/metrics for metrics data
[info] [output:parseable:parseable.0] initialized: host=localhost port=8000 stream=metrics uri=/api/v1/metrics
```

### Current Status

✅ **Plugin updated** with data_type parameter  
✅ **Docker image rebuilt** with updated plugin  
✅ **Configuration updated** to use correct data_types  
✅ **Endpoints being called correctly**:
  - Metrics → `/api/v1/metrics`
  - Logs → `/api/v1/logs`

⚠️ **Note**: If you're seeing 404 or 405 errors from Parseable, this means:
- The Parseable server may not have implemented these specific endpoints yet
- The endpoints may require different request formats or headers
- Check your Parseable server version and API documentation

### Testing

To verify the plugin is working:

```bash
# Build the image
docker build -t fluent-bit-local:latest .

# Run with configuration
docker run --rm --network host \
  -v "$PWD/parseable-demo.conf:/fluent-bit/etc/parseable-demo.conf" \
  fluent-bit-local:latest \
  /fluent-bit/bin/fluent-bit -c /fluent-bit/etc/parseable-demo.conf

# Check logs for endpoint initialization
docker logs <container-id> 2>&1 | grep "auto-set URI"
```

### Files Modified

1. `/plugins/out_parseable/parseable.h` - Added data_type field
2. `/plugins/out_parseable/parseable.c` - Added data_type config and auto-URI logic
3. `/Dockerfile` - Already had FLB_OUT_PARSEABLE=On
4. `/parseable-demo.conf` - Updated with data_type parameters
