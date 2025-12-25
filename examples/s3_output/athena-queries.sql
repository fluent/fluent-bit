-- ============================================
-- Athena Table Definitions - S3 Output Test
-- ============================================
-- This file defines tables for querying data uploaded by Fluent Bit S3 output plugin
-- Two upload scenarios: PutObject API (small files) and Multipart Upload (large files)

-- ============================================
-- Table 1: Application Logs (PutObject API)
-- ============================================
-- Case 1: Low traffic with PutObject API
-- Format: JSON + GZIP compression
-- Upload: Every 5 minutes or when file reaches 3MB
-- Path: s3://bucket/fluent-bit-logs/putobject/app/day=YYYYMMDD/

CREATE EXTERNAL TABLE app_logs_json (
    `timestamp` bigint,
    `level` string,
    `message` string,
    `request_id` string,
    `user_id` bigint,
    `method` string,
    `endpoint` string,
    `pool_size` bigint,
    `max_pool` bigint,
    `database` string,
    `error_code` string,
    `amount` double,
    `cache_key` string,
    `ttl` bigint,
    `query_time_ms` double,
    `rows_affected` bigint,
    `table` string
)
PARTITIONED BY (
    day string
)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://s3-bucket-kafka-sink/fluent-bit-logs/putobject/app/'
TBLPROPERTIES (
    'projection.enabled'='true',
    'projection.day.type'='date',
    'projection.day.range'='2025/01/01,NOW',
    'projection.day.format'='yyyyMMdd',
    'storage.location.template'='s3://s3-bucket-kafka-sink/fluent-bit-logs/putobject/app/day=${day}'
);


-- ============================================
-- Table 2: Access Logs (Multipart Upload)
-- ============================================
-- Case 2: High traffic with Multipart Upload API
-- Format: Parquet + Internal GZIP compression
-- Upload: Every 60 minutes or when file reaches 50MB
-- Chunk size: 10MB per part
-- Path: s3://bucket/fluent-bit-logs/multipart/access/day=YYYYMMDD/

CREATE EXTERNAL TABLE access_logs_parquet (
    `timestamp` bigint,
    `level` string,
    `message` string,
    `method` string,
    `path` string,
    `status` bigint,
    `duration_ms` double,
    `client_ip` string,
    `user_agent` string
)
PARTITIONED BY (
    day string
)
STORED AS PARQUET
LOCATION 's3://s3-bucket-kafka-sink/fluent-bit-logs/multipart/access/'
TBLPROPERTIES (
    'parquet.compression'='GZIP',
    'projection.enabled'='true',
    'projection.day.type'='date',
    'projection.day.range'='2025/01/01,NOW',
    'projection.day.format'='yyyyMMdd',
    'storage.location.template'='s3://s3-bucket-kafka-sink/fluent-bit-logs/multipart/access/day=${day}'
);


-- ============================================
-- Query Examples
-- ============================================

-- ============================================
-- Application Logs Queries (JSON + PutObject)
-- ============================================

-- 1. Basic Application Log Query
-- View recent application logs with time-based filtering
SELECT
    from_unixtime(timestamp) as log_time,
    level,
    message,
    request_id
FROM app_logs_json
WHERE day='20251224'
ORDER BY timestamp DESC
LIMIT 100;

-- 2. Log Level Distribution
-- Analyze log severity distribution
SELECT
    level,
    COUNT(*) as count,
    COUNT(*) * 100.0 / SUM(COUNT(*)) OVER() as percentage
FROM app_logs_json
WHERE day='20251224'
GROUP BY level
ORDER BY count DESC;

-- 3. Time-based Activity Analysis
-- Analyze log patterns over time
SELECT
    DATE_FORMAT(from_unixtime(timestamp), '%Y-%m-%d %H:00:00') as hour,
    level,
    COUNT(*) as log_count
FROM app_logs_json
WHERE day='20251224'
GROUP BY DATE_FORMAT(from_unixtime(timestamp), '%Y-%m-%d %H:00:00'), level
ORDER BY hour, level;

-- 4. Request ID Tracking
-- Track specific request flows
SELECT
    from_unixtime(timestamp) as log_time,
    level,
    message,
    request_id
FROM app_logs_json
WHERE day='20251224'
  AND request_id = 'req-001'
ORDER BY timestamp;


-- ============================================
-- Access Logs Queries (Parquet + Multipart Upload)
-- ============================================

-- 5. Basic Access Log Query
-- View recent access logs
SELECT
    from_unixtime(timestamp) as access_time,
    method,
    path,
    status,
    duration_ms
FROM access_logs_parquet
WHERE day='20251224'
ORDER BY timestamp DESC
LIMIT 100;

-- 6. HTTP Status Code Distribution
-- Analyze response status codes
SELECT
    status,
    COUNT(*) as request_count,
    AVG(duration_ms) as avg_duration_ms,
    MIN(duration_ms) as min_duration_ms,
    MAX(duration_ms) as max_duration_ms
FROM access_logs_parquet
WHERE day='20251224'
GROUP BY status
ORDER BY request_count DESC;

-- 7. Endpoint Performance Analysis
-- Find slowest endpoints
SELECT
    path,
    method,
    COUNT(*) as request_count,
    AVG(duration_ms) as avg_duration_ms,
    approx_percentile(duration_ms, 0.95) as p95_duration_ms,
    MAX(duration_ms) as max_duration_ms
FROM access_logs_parquet
WHERE day='20251224'
GROUP BY path, method
ORDER BY avg_duration_ms DESC
LIMIT 20;

-- 8. Traffic Pattern by Hour
-- Analyze request volume over time
SELECT
    DATE_FORMAT(from_unixtime(timestamp), '%Y-%m-%d %H:00:00') as hour,
    method,
    COUNT(*) as request_count,
    AVG(duration_ms) as avg_duration_ms
FROM access_logs_parquet
WHERE day='20251224'
GROUP BY DATE_FORMAT(from_unixtime(timestamp), '%Y-%m-%d %H:00:00'), method
ORDER BY hour, method;

-- 9. Error Rate Analysis
-- Calculate error rates by endpoint
SELECT
    path,
    COUNT(*) as total_requests,
    SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) as errors,
    SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as error_rate_pct
FROM access_logs_parquet
WHERE day='20251224'
GROUP BY path
HAVING COUNT(*) >= 10
ORDER BY error_rate_pct DESC
LIMIT 20;

-- 10. Slow Request Analysis
-- Find requests exceeding performance thresholds
SELECT
    from_unixtime(timestamp) as access_time,
    method,
    path,
    status,
    duration_ms
FROM access_logs_parquet
WHERE day='20251224'
  AND duration_ms > 100  -- Requests slower than 100ms
ORDER BY duration_ms DESC
LIMIT 100;


-- ============================================
-- Cross-Table Comparison Queries
-- ============================================

-- 11. Upload Method Comparison
-- Compare record counts between PutObject and Multipart Upload
SELECT
    'PutObject (JSON)' as upload_method,
    'app.logs' as log_type,
    COUNT(*) as record_count,
    MIN(from_unixtime(timestamp)) as first_record,
    MAX(from_unixtime(timestamp)) as last_record
FROM app_logs_json
WHERE day='20251224'

UNION ALL

SELECT
    'Multipart Upload (Parquet)' as upload_method,
    'access.logs' as log_type,
    COUNT(*) as record_count,
    MIN(from_unixtime(timestamp)) as first_record,
    MAX(from_unixtime(timestamp)) as last_record
FROM access_logs_parquet
WHERE day='20251224';

-- 12. Format and Compression Efficiency
-- Note: Compare with actual S3 file sizes to calculate compression ratios
-- Run in AWS Console: aws s3 ls s3://s3-bucket-kafka-sink/fluent-bit-logs/ --recursive --human-readable
SELECT
    'JSON + GZIP (PutObject)' as configuration,
    COUNT(*) as records,
    COUNT(DISTINCT day) as days
FROM app_logs_json

UNION ALL

SELECT
    'Parquet + GZIP (Multipart)' as configuration,
    COUNT(*) as records,
    COUNT(DISTINCT day) as days
FROM access_logs_parquet;


-- ============================================
-- Troubleshooting Queries
-- ============================================

-- 13. Data Freshness Check
-- Verify recent data uploads
SELECT
    'app_logs_json' as table_name,
    MAX(from_unixtime(timestamp)) as latest_timestamp,
    MAX(day) as latest_partition,
    COUNT(*) as total_records
FROM app_logs_json

UNION ALL

SELECT
    'access_logs_parquet' as table_name,
    MAX(from_unixtime(timestamp)) as latest_timestamp,
    MAX(day) as latest_partition,
    COUNT(*) as total_records
FROM access_logs_parquet;

-- 14. Partition Discovery Test
-- Verify partition projection is working
SELECT DISTINCT day
FROM app_logs_json
ORDER BY day DESC
LIMIT 10;

SELECT DISTINCT day
FROM access_logs_parquet
ORDER BY day DESC
LIMIT 10;


-- ============================================
-- Performance Testing Queries
-- ============================================

-- 15. Query Performance Comparison
-- Test query performance between JSON and Parquet formats
-- Run these queries separately and compare execution times:

-- JSON Query (Full scan)
SELECT COUNT(*)
FROM app_logs_json
WHERE day >= '20251201';

-- Parquet Query (Full scan)
SELECT COUNT(*)
FROM access_logs_parquet
WHERE day >= '20251201';

-- 16. Aggregation Performance Test
-- Compare aggregation performance

-- JSON Aggregation
SELECT
    level,
    COUNT(*) as count
FROM app_logs_json
WHERE day >= '20251201'
GROUP BY level;

-- Parquet Aggregation
SELECT
    method,
    status,
    COUNT(*) as count,
    AVG(duration_ms) as avg_duration
FROM access_logs_parquet
WHERE day >= '20251201'
GROUP BY method, status;


-- ============================================
-- Notes
-- ============================================
-- 1. Update the 'day' parameter to match your test date (format: YYYYMMDD)
-- 2. Partition Projection automatically discovers new partitions without MSCK REPAIR TABLE
-- 3. For production use, adjust 'projection.day.range' to match your data retention policy
-- 4. JSON queries may be slower than Parquet for large datasets due to row-based format
-- 5. Parquet with GZIP provides better compression and query performance for analytical workloads
-- 6. Monitor S3 file sizes to understand actual compression ratios and storage costs
-- 7. Consider using Parquet format for high-volume logs (access logs, metrics)
-- 8. Consider using JSON format for low-volume logs (application logs, audit logs)
