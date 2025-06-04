# Fluent Bit Google Cloud Storage (GCS) Output Plugin

This plugin allows Fluent Bit to send log data to Google Cloud Storage (GCS) for long-term storage and compliance requirements. It closely mimics the functionality of the S3 output plugin while adapting for GCS-specific features.

## Features

- **Multiple Data Formats**: Support for text, JSON, and Parquet formats
- **Compression**: GZIP compression support for efficient storage
- **Flexible Authentication**: Service Account JSON keys, Application Default Credentials (ADC), and Workload Identity
- **Intelligent Batching**: Configurable file size and time-based upload triggers
- **Retry Mechanism**: Robust error handling with exponential backoff
- **Local Buffering**: Persistent local storage before upload
- **Object Key Formatting**: Time-based partitioning and custom naming patterns

## Configuration Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `bucket` | String | GCS bucket name (required) |

### Authentication Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `credentials_file` | String | - | Path to GCS service account JSON credentials file |
| `service_account_email` | String | - | Service account email for authentication |
| `project_id` | String | - | Google Cloud Project ID |

### File Organization Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `gcs_key_format` | String | `/fluent-bit-logs/%Y/%m/%d/%H/%M/%S_${tag}.log` | Format string for GCS object keys with time/tag placeholders |
| `region` | String | - | GCS bucket region |

### Buffering and Upload Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `store_dir` | String | `/tmp/fluent-bit/gcs` | Directory to store temporary files before upload |
| `total_file_size` | Size | `100MB` | Target file size for uploads |
| `upload_chunk_size` | Size | `5MB` | Size of upload chunks for resumable uploads |
| `upload_timeout` | Time | `5m` | Maximum time to wait for chunk accumulation before upload |
| `store_dir_limit_size` | Size | `0` | Maximum size for store directory (0 = unlimited) |

### Data Format Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `format` | String | `json` | Output format: `text`, `json`, `parquet` |
| `compression` | String | `none` | Compression type: `none`, `gzip` |
| `log_key` | String | - | Extract specific key from log record for output |
| `json_date_key` | String | `date` | Date field name in JSON output |
| `json_date_format` | Integer | `0` | Date format for JSON output: `0`=epoch, `1`=iso8601 |

### Reliability Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `retry_limit` | Integer | `3` | Number of retries for failed uploads |
| `preserve_data_ordering` | Boolean | `true` | Preserve log order during retries and failures |
| `use_put_object` | Boolean | `false` | Use simple PUT instead of resumable uploads for small files |

## Usage Examples

### Basic Configuration

```conf
[OUTPUT]
    Name                gcs
    Match               *
    bucket              my-log-bucket
    credentials_file    /path/to/service-account.json
```

### Advanced Configuration with Time-based Partitioning

```conf
[OUTPUT]
    Name                gcs
    Match               app.*
    bucket              production-logs
    credentials_file    /etc/fluent-bit/gcs-credentials.json
    gcs_key_format      logs/%Y/%m/%d/%H/${tag}_%Y%m%d_%H%M%S.json.gz
    format              json
    compression         gzip
    total_file_size     50MB
    upload_timeout      10m
    json_date_format    1
```

### Configuration for Multiple Environments

```conf
# Production logs
[OUTPUT]
    Name                gcs
    Match               prod.*
    bucket              prod-logs-bucket
    credentials_file    /etc/fluent-bit/prod-gcs-key.json
    gcs_key_format      production/%Y/%m/%d/${tag}_%H%M%S.json.gz
    format              json
    compression         gzip
    store_dir           /var/lib/fluent-bit/gcs-prod

# Development logs  
[OUTPUT]
    Name                gcs
    Match               dev.*
    bucket              dev-logs-bucket
    credentials_file    /etc/fluent-bit/dev-gcs-key.json
    gcs_key_format      development/%Y/%m/%d/${tag}_%H%M%S.txt
    format              text
    compression         none
    store_dir           /var/lib/fluent-bit/gcs-dev
```

### Parquet Format Configuration

```conf
[OUTPUT]
    Name                gcs
    Match               metrics.*
    bucket              analytics-data
    credentials_file    /etc/fluent-bit/analytics-gcs-key.json
    gcs_key_format      metrics/%Y/%m/%d/${tag}_%H%M%S.parquet
    format              parquet
    compression         none
    total_file_size     100MB
    upload_chunk_size   10MB
```

## Object Key Format Placeholders

The `gcs_key_format` parameter supports the following placeholders:

### Time Format Specifiers (strftime)
- `%Y` - 4-digit year (e.g., 2024)
- `%m` - Month (01-12)
- `%d` - Day of month (01-31)
- `%H` - Hour (00-23)
- `%M` - Minute (00-59)
- `%S` - Second (00-59)
- `%j` - Day of year (001-366)
- `%w` - Day of week (0-6, Sunday=0)
- `%W` - Week number (00-53)

### Dynamic Placeholders
- `${tag}` - Fluent Bit tag name
- `${UUID}` - Generated UUID for uniqueness (planned feature)

### Example Object Keys
- Input: `gcs_key_format = logs/%Y/%m/%d/${tag}_%H%M%S.json`
- Tag: `app.frontend`
- Timestamp: 2024-01-15 14:30:45
- Result: `logs/2024/01/15/app.frontend_143045.json`

## Authentication Methods

### 1. Service Account JSON Key (Recommended)

Create a service account in Google Cloud Console and download the JSON key file:

```bash
# Set the credentials file path
gcloud iam service-accounts create fluent-bit-gcs \
    --display-name="Fluent Bit GCS Writer"

gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="serviceAccount:fluent-bit-gcs@PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/storage.objectCreator"

gcloud iam service-accounts keys create /path/to/gcs-key.json \
    --iam-account=fluent-bit-gcs@PROJECT_ID.iam.gserviceaccount.com
```

Then configure Fluent Bit:
```conf
[OUTPUT]
    Name                gcs
    bucket              my-bucket
    credentials_file    /path/to/gcs-key.json
```

### 2. Application Default Credentials (ADC)

When running on Google Cloud Platform (Compute Engine, GKE, Cloud Run, etc.), you can use the default service account:

```conf
[OUTPUT]
    Name                gcs
    bucket              my-bucket
    # No credentials_file needed - will use metadata server
```

### 3. Workload Identity (GKE)

For Google Kubernetes Engine with Workload Identity enabled:

```conf
[OUTPUT]
    Name                gcs
    bucket              my-bucket
    service_account_email  fluent-bit-gcs@PROJECT_ID.iam.gserviceaccount.com
```

## Dependencies

### Core Dependencies (Included with Fluent Bit)
- HTTP client support
- OAuth2 authentication
- GZIP compression
- JSON processing
- File store (local buffering)

### Optional Dependencies

#### For Parquet Support
The plugin supports Apache Parquet format through Apache Arrow C++ library. To enable Parquet support:

##### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install libarrow-dev libparquet-dev
```

##### CentOS/RHEL/Fedora:
```bash
# CentOS/RHEL 8+
sudo dnf install arrow-devel parquet-devel

# Older versions
sudo yum install arrow-devel parquet-devel
```

##### macOS (Homebrew):
```bash
brew install apache-arrow
```

##### From Source:
```bash
git clone https://github.com/apache/arrow.git
cd arrow/cpp
mkdir build && cd build
cmake .. \
    -DARROW_PARQUET=ON \
    -DARROW_BUILD_SHARED=ON \
    -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo make install
```

## Build Instructions

### Standard Build (without Parquet)
```bash
cd fluent-bit
mkdir build && cd build
cmake .. -DFLB_OUT_GCS=ON
make -j$(nproc)
```

### Build with Parquet Support
```bash
cd fluent-bit
mkdir build && cd build
cmake .. \
    -DFLB_OUT_GCS=ON \
    -DFLB_OUT_GCS_PARQUET=ON
make -j$(nproc)
```

## File Formats

### Text Format
- Raw log messages with timestamps
- One log entry per line
- Format: `timestamp message\n`

### JSON Format  
- JSON Lines format (one JSON object per line)
- Configurable timestamp field and format
- Preserves all log metadata

### Parquet Format (Optional)
- Columnar storage format
- Efficient for analytics workloads
- Requires Apache Arrow C++ library
- Optimal compression and query performance

## Error Handling

The plugin implements comprehensive error handling:

1. **Authentication Errors**: Automatic token refresh
2. **Network Errors**: Retry with exponential backoff
3. **Upload Failures**: Configurable retry limits
4. **Storage Errors**: Graceful degradation with local buffering
5. **Format Errors**: Skip invalid records with warnings

## Performance Considerations

### Recommended Settings for High Volume

```conf
[OUTPUT]
    Name                gcs
    Match               *
    bucket              high-volume-logs
    total_file_size     100MB
    upload_chunk_size   10MB
    upload_timeout      5m
    compression         gzip
    workers             2
```

### Memory Usage
- Local buffering uses disk storage by default
- Memory usage scales with chunk size and concurrent uploads
- Compression reduces network bandwidth but increases CPU usage

## Monitoring and Troubleshooting

### Enable Debug Logging
```conf
[SERVICE]
    Log_Level   debug

[OUTPUT]
    Name        gcs
    # ... other settings
```

### Common Issues

1. **Authentication Failures**
   - Verify service account permissions
   - Check credentials file path and format
   - Ensure system clock is synchronized

2. **Upload Failures**
   - Verify bucket exists and is accessible
   - Check network connectivity to `storage.googleapis.com`
   - Review IAM permissions for storage.objectCreator role

3. **Performance Issues**
   - Adjust `upload_chunk_size` for your network
   - Enable compression for bandwidth-limited environments
   - Increase `total_file_size` to reduce API calls

## Security Best Practices

1. **Credentials Management**
   - Store service account keys securely
   - Use least-privilege IAM policies
   - Rotate keys regularly

2. **Network Security**
   - All communication uses HTTPS/TLS
   - Consider VPC Service Controls for additional isolation

3. **Data Protection**
   - Enable bucket encryption at rest
   - Use customer-managed encryption keys (CMEK) if required
   - Implement bucket lifecycle policies for data retention

## License

This plugin is licensed under the Apache License 2.0, same as Fluent Bit.