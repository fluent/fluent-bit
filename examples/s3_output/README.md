# Fluent Bit S3 Output - Test Example

This example demonstrates Fluent Bit's S3 output plugin with two typical upload scenarios: **PutObject API** for small files and **Multipart Upload API** for large files.

## Features Tested

- **Upload Methods**: PutObject (single request) and Multipart Upload (chunked)
- **Formats**: JSON and Parquet
- **Compression**: GZIP (for both JSON and Parquet internal compression)
- **Traffic Levels**: Low (10 events/sec) and High (100 events/sec)
- **upload_timeout**: Time-based upload trigger parameter

## Files

- `fluent-bit-s3-parquet.conf` - Test configuration with 2 input sources and 2 output configurations
- `athena-queries.sql` - AWS Athena table definitions and query examples
- `run-s3-parquet-test.sh` - Test execution script

## Configuration Overview

### Input Sources - Realistic Scenarios

#### 1. Application Logs (10 events/sec total) - Low Traffic

Simulates backend application logs with various severity levels:

- **INFO - Authentication** (3/sec): Successful user logins
- **WARN - Database** (2/sec): Connection pool capacity warnings
- **ERROR - Payment** (1/sec): Payment processing failures
- **INFO - Cache** (2/sec): Cache hit events
- **DEBUG - Query** (2/sec): Database query execution logs

**Data characteristics:**

- Mixed log levels (info, warn, error, debug)
- Request tracing with request_id
- User context (user_id, amounts)
- Database metrics (pool_size, query_time)

#### 2. Access Logs (100 events/sec total) - High Traffic

Simulates HTTP access logs from API gateway/web server:

- **GET /api/users** - 200 (40/sec): Successful user profile requests
- **POST /api/orders** - 201 (15/sec): Order creation
- **PUT /api/users/profile** - 200 (10/sec): Profile updates
- **GET /api/products** - 404 (5/sec): Product not found
- **POST /api/payments** - 500 (3/sec): Payment gateway errors
- **GET /health** - 200 (20/sec): Health check probes
- **POST /api/auth/login** - 401 (7/sec): Failed login attempts

**Data characteristics:**

- Various HTTP methods (GET, POST, PUT)
- Multiple status codes (200, 201, 404, 500, 401)
- Response times (2ms to 5000ms)
- Client information (IP, user agent)

### Output Configurations

#### Case 1: Low Traffic + PutObject API (Small Files)

```ini
[OUTPUT]
    Name                s3
    Match               app.logs
    total_file_size     3M
    upload_timeout      5m
    use_put_object      true
    format              json
    compression         gzip
```

**Characteristics:**

- **API**: PutObject (single request, no chunking)
- **File size**: 3MB (< 10MB triggers PutObject)
- **Upload trigger**: Every 5 minutes OR when file reaches 3MB
- **Use case**: Application logs, audit logs, low-frequency events
- **Benefit**: Simple, single-request upload for small files

#### Case 2: High Traffic + Multipart Upload (Large Files)

```ini
[OUTPUT]
    Name                s3
    Match               access.logs
    total_file_size     50M
    upload_chunk_size   10M
    upload_timeout      60m
    use_put_object      false
    format              parquet
    compression         gzip
    schema_str          {"fields":[...]}
```

**Characteristics:**

- **API**: S3 Multipart Upload (chunked transfer)
- **File size**: 50MB (large file requiring multipart)
- **Chunk size**: 10MB per part
- **Upload trigger**: Every 60 minutes OR when file reaches 50MB
- **Use case**: Access logs, high-volume metrics, streaming data
- **Benefit**: Efficient transfer of large files in parallel chunks

## Upload Trigger: upload_timeout Parameter

The `upload_timeout` parameter controls **time-based upload triggers**:

### How It Works

```
Upload Trigger = upload_timeout reached OR total_file_size reached
```

Whichever condition is met first will trigger the upload.

### Examples

| Scenario     | upload_timeout | total_file_size | Typical Trigger                                  |
| ------------ | -------------- | --------------- | ------------------------------------------------ |
| Low traffic  | 5m             | 3M              | **Time-based** (5 min) - data rarely reaches 3MB |
| High traffic | 60m            | 50M             | **Size-based** (50MB) - file fills quickly       |

### Configuration Tips

- **Low-frequency logs**: Use shorter `upload_timeout` (2m-5m) to ensure timely delivery
- **High-frequency logs**: Use longer `upload_timeout` (30m-60m) as size usually triggers first
- **Hourly archival**: Set `upload_timeout` to 60m for hourly file organization
- **Default value**: 10m (if not specified)

## Prerequisites

1. AWS credentials configured (access key, secret key, session token)
2. S3 bucket: `s3-bucket-kafka-sink`
3. Fluent Bit compiled with S3 and Parquet support
   - Ensure `FLB_PARQUET_ENCODER=On` in CMake
   - Arrow library version 10.0.0 or higher required

## Usage

1. Build Fluent Bit:

```bash
cd ../../build
cmake ..
make -j8
```

2. Set AWS credentials:

```bash
export AWS_ACCESS_KEY_ID="your_access_key"
export AWS_SECRET_ACCESS_KEY="your_secret_key"
export AWS_SESSION_TOKEN="your_session_token"  # if using temporary credentials
```

3. Run the test:

```bash
cd examples/s3_output
chmod +x run-s3-parquet-test.sh
./run-s3-parquet-test.sh
```

4. Monitor the output - you should see:
   - Both S3 output plugins initializing successfully
   - Case 1 showing: `use_put_object` enabled
   - Case 2 showing: `format=parquet: using GZIP compression internally`
   - Periodic upload timer callbacks
   - Successful file uploads to S3

## S3 Upload Paths

Files are uploaded to the following structure:

```
s3://s3-bucket-kafka-sink/fluent-bit-logs/
├── putobject/app/day=YYYYMMDD/      # Case 1: Small files via PutObject
└── multipart/access/day=YYYYMMDD/   # Case 2: Large files via Multipart Upload
```

## Querying Data with Athena

1. Open AWS Athena console
2. Run the table creation statements from `athena-queries.sql`
3. Execute the provided query examples to analyze the data

### Sample Queries Included

- Traffic level statistics
- Nested field access (request/response details)
- Array operations (user roles, payment items, stack traces)
- Complex filtering and aggregations
- Performance comparisons between formats and compression methods

## Key Features Demonstrated

### Parquet Schema Definition

The configuration demonstrates the new **user-defined schema** approach for Parquet files:

- **schema_str**: JSON string defining the Arrow schema
- **Format**: `{"fields":[{"name":"column_name","type":"data_type","nullable":true|false}]}`
- **Supported types**:
  - Basic: `bool`, `int32`, `int64`, `float`, `double`, `utf8`, `binary`
  - Complex: `timestamp` with units (s, ms, us, ns)
- **Example**:
  ```json
  {
    "fields": [
      { "name": "timestamp", "type": "int64", "nullable": false },
      { "name": "level", "type": "utf8", "nullable": false },
      { "name": "message", "type": "utf8", "nullable": false },
      { "name": "value", "type": "int64", "nullable": true }
    ]
  }
  ```

#### Type Mismatch and Data Handling

**IMPORTANT**: You are responsible for defining a correct schema that matches your data. When data doesn't match the schema:

1. **Type overflow/mismatch**:

   - If a value exceeds the type's range (e.g., value > INT32_MAX for `int32` field), the value will be **clamped** to the type's boundary (INT32_MAX or INT32_MIN)
   - A warning will be logged for each clamped value
   - **Recommendation**: Use `int64` for ID fields, timestamps, and other large integers to avoid data loss from clamping

2. **Missing fields**:

   - **Nullable fields** (`"nullable": true`): Missing fields are set to `NULL`
   - **Non-nullable fields** (`"nullable": false`): Missing fields use default values:
     - `int32`, `int64`: `0`
     - `float`, `double`: `0.0`
     - `bool`: `false`
     - `utf8`, `binary`: empty string/bytes
     - `timestamp`: `0` (Unix epoch: 1970-01-01 00:00:00)

3. **Best practices**:
   ```json
   {
     "fields": [
       { "name": "user_id", "type": "int64", "nullable": false }, // ✅ Use int64 for IDs
       { "name": "timestamp", "type": "int64", "nullable": false }, // ✅ Use int64 for timestamps
       { "name": "amount", "type": "double", "nullable": true }, // ✅ Use double for amounts
       { "name": "status", "type": "int32", "nullable": false }, // ✅ int32 OK for small ranges
       { "name": "message", "type": "utf8", "nullable": true } // ✅ Nullable for optional fields
     ]
   }
   ```

**⚠️ Warning**: Non-nullable fields with missing data will use default values without error. Ensure your data quality matches your schema definition.

### Schema Design Best Practices

#### Understanding Non-nullable Fields

**Why use default values instead of rejecting data?**

1. **Parquet format requirement**: Non-nullable fields in Parquet must have a value (cannot be NULL)
2. **Log collection reality**: Log data is inherently incomplete - some fields are often missing
3. **Data loss prevention**: Rejecting entire records would lose valuable information
4. **Practical balance**: Default values + data quality warnings provide better outcomes than data loss

**Data quality monitoring**:

When non-nullable fields are missing, you'll see warnings like:

```
[parquet] Data quality summary for 53206 records:
[parquet] Missing non-nullable fields (defaults used):
[parquet]   field='level' count=52506
[parquet]   field='timestamp' count=52506
```

#### When to Use Nullable vs Non-nullable

**Use `nullable: true` when**:

- Field may legitimately be absent (e.g., `user_agent` in some requests)
- You want to distinguish between "missing" and "zero/empty"
- Field is optional in your data model
- You need to query for missing values: `WHERE field IS NULL`

**Use `nullable: false` when**:

- Field should always be present in well-formed data
- Default value has reasonable semantics (e.g., `retry_count=0` means "no retries")
- You want to simplify queries (no NULL handling needed)
- Storage optimization (non-nullable columns are slightly more efficient)

**Example scenarios**:

```json
{
  "fields": [
    // ✅ Non-nullable: Core fields that should always exist
    { "name": "timestamp", "type": "int64", "nullable": false },
    { "name": "log_level", "type": "utf8", "nullable": false },
    { "name": "message", "type": "utf8", "nullable": false },

    // ✅ Nullable: Optional context fields
    { "name": "user_id", "type": "int64", "nullable": true },
    { "name": "request_id", "type": "utf8", "nullable": true },
    { "name": "response_time_ms", "type": "int32", "nullable": true },

    // ✅ Non-nullable with meaningful defaults
    { "name": "retry_count", "type": "int32", "nullable": false },
    { "name": "is_error", "type": "bool", "nullable": false },
    { "name": "bytes_sent", "type": "int64", "nullable": false }
  ]
}
```

#### Data Quality Recommendations

1. **Monitor logs for missing field warnings**

   - Set up alerts for high missing field counts
   - Review warnings regularly: `grep "Missing non-nullable fields" fluent-bit.log`
   - Adjust schema if fields are consistently missing

2. **Fix data sources when possible**

   - If critical field is always missing, fix the data generator
   - Example: Ensure application always logs `level` field

3. **Adjust schema based on reality**

   - If field is rarely present, change to `nullable: true`
   - If field should exist but doesn't, fix upstream

4. **Query considerations**
   - Be aware that `level=0` might be a default, not real data
   - Use timestamp ranges to exclude obviously invalid data: `WHERE timestamp > 0`
   - Consider adding a `data_quality` field to track completeness

**Example data quality query**:

```sql
-- Find records that might have used defaults
SELECT
  COUNT(*) as total_records,
  SUM(CASE WHEN timestamp = 0 THEN 1 ELSE 0 END) as invalid_timestamps,
  SUM(CASE WHEN level = '' THEN 1 ELSE 0 END) as empty_levels
FROM your_table
WHERE day = '20251224';
```

### Parquet Compression

The configuration demonstrates proper Parquet compression handling:

- Parquet format uses **internal compression only** (GZIP, SNAPPY, ZSTD, or NONE)
- Compression is specified via the `compression` parameter
- **Default behavior**: When `compression` is not specified, defaults to **none** (no compression)
- **No outer compression layer** - Parquet handles compression internally
- Compressed Parquet files are fully compatible with AWS Athena and other Parquet readers
- **Examples**:
  - Not specified or `compression=none` → Parquet without compression (default, fastest)
  - `compression=gzip` → Parquet with internal GZIP compression (good balance)
  - `compression=snappy` → Parquet with internal Snappy compression (faster compression)
  - `compression=zstd` → Parquet with internal ZSTD compression (best compression ratio)

### Partition Projection

All Athena tables use Partition Projection for automatic partition discovery:

- No need to run `MSCK REPAIR TABLE`
- Queries automatically discover partitions based on date patterns
- Improved query performance

### Complex Data Types

Examples include:

- Nested structs (user → address → city)
- Arrays of primitives (roles, tags, flags)
- Arrays of structs (payment items, stack traces)
- Multi-level nesting (request → headers → user-agent)

## Upload Method Comparison

### PutObject API (Case 1)

**Pros:**

- Simple single-request upload
- No overhead of managing multiple parts
- Suitable for files < 5MB

**Cons:**

- Limited to files < 5GB
- No parallel transfer
- Must retry entire file on failure

**When to use:**

- Low-traffic logs (application logs, audit logs)
- Small file sizes (< 10MB recommended)
- Simplicity preferred over performance

### Multipart Upload API (Case 2)

**Pros:**

- Efficient for large files
- Parallel part uploads (better throughput)
- Resume capability (failed parts can be retried)
- Support files up to 5TB

**Cons:**

- More complex (requires initiate, upload parts, complete)
- Small overhead for managing parts
- Requires `upload_chunk_size` configuration

**When to use:**

- High-traffic logs (access logs, metrics)
- Large file sizes (> 10MB)
- Need maximum throughput
- Large-scale production systems

## Performance Testing

### Data Generation Rate

The configuration generates realistic production-like traffic:

| Log Type         | Rate        | Size/event | Data/minute | Test Purpose               |
| ---------------- | ----------- | ---------- | ----------- | -------------------------- |
| Application Logs | 10/sec      | ~150 bytes | ~90KB       | Time-triggered upload test |
| Access Logs      | 100/sec     | ~200 bytes | ~1.2MB      | Size-triggered upload test |
| **Total**        | **110/sec** | ~175 bytes | **~1.29MB** | **Combined scenario**      |

### Upload Behavior Verification

#### Case 1: Application Logs (Time-Triggered)

**Expected Behavior:**

- Data accumulates at 10 events/sec ≈ 600 events/min ≈ 90KB/min
- With 3MB threshold: Would take ~33 minutes to reach size limit
- **Primary trigger**: `upload_timeout=5m` (time-based)
- **Result**: Files uploaded every 5 minutes with ~450KB each

**Verification Steps:**

1. Run test for 10 minutes
2. Expect ~2 files uploaded (at 5min and 10min marks)
3. Each file contains ~3000 events (~450KB)
4. Demonstrates time-triggered upload for low-traffic scenarios

#### Case 2: Access Logs (Size-Triggered)

**Expected Behavior:**

- Data accumulates at 100 events/sec ≈ 6000 events/min ≈ 1.2MB/min
- With 50MB threshold: Would take ~42 minutes to reach size limit
- **Primary trigger**: `total_file_size=50M` (size-based)
- **Fallback**: `upload_timeout=60m` (acts as safety net)
- **Result**: Files uploaded when reaching 50MB (before 60min timeout)

**Verification Steps:**

1. Run test for 60 minutes
2. Expect files uploaded as soon as they reach 50MB
3. Each file contains ~250,000 events
4. Demonstrates size-triggered upload with multipart chunking (10MB parts)

### Real-World Insights

This test demonstrates:

1. **Low-traffic pattern**: Application logs depend on time-based uploads to ensure timely delivery
2. **High-traffic pattern**: Access logs depend on size-based uploads for efficient batching
3. **Dual trigger mechanism**: Both conditions work together seamlessly
4. **PutObject vs Multipart**: Automatic selection based on file size and use_put_object setting
5. **Compression efficiency**: Compare JSON+GZIP vs Parquet+GZIP compression ratios

### Expected Test Results

After running for 10 minutes:

| Metric           | Case 1 (App Logs)  | Case 2 (Access Logs)       |
| ---------------- | ------------------ | -------------------------- |
| Files created    | ~2 files           | 0-1 files (size-dependent) |
| Records per file | ~3000 records      | ~250,000 records           |
| File size        | ~450KB compressed  | ~50MB when triggered       |
| Upload method    | PutObject          | Multipart (5 parts × 10MB) |
| Trigger type     | Time (5m)          | Size (50M) or Time (60m)   |
| Athena queries   | Log level analysis | HTTP performance analysis  |

## Troubleshooting

1. **AWS credentials expired**: Refresh your credentials and rerun
2. **Compilation errors**:
   - Ensure Parquet support is enabled: `cmake -DFLB_PARQUET_ENCODER=On ..`
   - Check Arrow library is installed: `brew install apache-arrow` (macOS) or package manager
   - Verify Arrow version >= 10.0.0
3. **S3 upload failures**: Check bucket permissions and region settings
4. **Athena query errors**: Verify table definitions match the data structure
5. **Parquet schema errors**:
   - Ensure `schema_str` parameter is provided for Parquet format
   - Verify JSON schema syntax is correct
   - Check that all field types are supported
   - Ensure field names match your data structure

## Notes

- Test files are stored in `/tmp/fluent-bit-test/` locally
- Each output plugin has its own store directory with size limits
- The test can be stopped with Ctrl+C at any time
- Files will continue uploading on the next run if buffer exists
