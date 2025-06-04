# GCS Plugin Testing Guide

This document provides comprehensive testing instructions for the Google Cloud Storage (GCS) output plugin for Fluent Bit.

## Test Structure

The GCS plugin includes comprehensive unit and integration tests:

### Runtime Tests (Integration)
**Location**: `tests/runtime/out_gcs.c`

These tests verify end-to-end functionality:
- **Basic upload functionality**: Authentication, data formatting, and upload
- **Multiple data formats**: Text, JSON, and Parquet format support
- **Compression**: GZIP compression testing
- **Authentication scenarios**: Service Account, ADC, and Workload Identity
- **Error handling**: Authentication failures, upload failures, network errors
- **Configuration validation**: Parameter validation and error cases
- **Key formatting**: Object key generation with time/tag placeholders
- **Large file handling**: Multipart upload scenarios

### Unit Tests (Internal)
**Location**: `tests/internal/gcs_*.c`

These tests verify specific functionality:

#### `gcs_config.c` - Configuration Testing
- Bucket name validation
- Upload chunk size validation
- Store directory validation
- Object key format validation
- Parameter parsing (size, time, boolean)
- Authentication type detection

#### `gcs_format.c` - Data Formatting Testing
- Timestamp formatting (epoch vs ISO 8601)
- JSON record formatting
- Text record formatting
- Log key extraction
- Chunk formatting with multiple records
- Format and compression validation
- Content type detection
- File extension generation

#### `gcs_auth.c` - Authentication Testing
- Service account credentials parsing
- JWT creation and signing
- OAuth2 token refresh
- Metadata server authentication (ADC)
- Authentication method detection
- Token validation and caching
- Error handling scenarios

## Building Tests

### Prerequisites

1. **Build Fluent Bit with GCS plugin enabled**:
```bash
cd fluent-bit
mkdir build && cd build
cmake .. -DFLB_OUT_GCS=ON
```

2. **Optional: Enable Parquet support**:
```bash
cmake .. -DFLB_OUT_GCS=ON -DFLB_OUT_GCS_PARQUET=ON
```

3. **Enable tests**:
```bash
cmake .. \
    -DFLB_OUT_GCS=ON \
    -DFLB_TESTS_RUNTIME=ON \
    -DFLB_TESTS_INTERNAL=ON
```

### Build Commands

```bash
# Build everything
make -j$(nproc)

# Build only GCS plugin
make flb-plugin-out_gcs

# Build only tests
make flb-rt-out_gcs      # Runtime tests
make flb-it-gcs_config   # Configuration unit tests
make flb-it-gcs_format   # Formatting unit tests
make flb-it-gcs_auth     # Authentication unit tests
```

## Running Tests

### Individual Test Execution

```bash
# Runtime integration tests
./bin/flb-rt-out_gcs

# Unit tests
./bin/flb-it-gcs_config
./bin/flb-it-gcs_format
./bin/flb-it-gcs_auth
```

### Using CTest

```bash
# Run all tests
ctest

# Run only GCS tests
ctest -R gcs

# Run with verbose output
ctest -V -R gcs

# Run specific test
ctest -R flb-rt-out_gcs
```

### Test Filtering

```bash
# Run specific test function
./bin/flb-rt-out_gcs basic_upload

# List available tests
./bin/flb-rt-out_gcs --list

# Run with debug output
./bin/flb-rt-out_gcs --verbose
```

## Test Data and Mocking

### Mock Environment

Tests use environment variables to control mock responses:

```bash
# Enable test mode
export FLB_GCS_PLUGIN_UNDER_TEST=true

# Mock OAuth2 success
export FLB_GCS_MOCK_TOKEN_RESPONSE='{"access_token":"test-token","expires_in":3600}'

# Mock upload success
export FLB_GCS_MOCK_UPLOAD_RESPONSE='{"name":"test-object","bucket":"test-bucket"}'

# Mock errors
export FLB_GCS_MOCK_ERROR_CODE=500
export FLB_GCS_MOCK_ERROR_RESPONSE='{"error":"Internal Server Error"}'
```

### Test Scenarios

The tests include several predefined scenarios:

1. **Success Scenario**: OAuth success + Upload success
2. **Authentication Failure**: Invalid credentials/JWT
3. **Upload Failure**: Network/server errors
4. **Permission Denied**: Insufficient IAM permissions
5. **Bucket Not Found**: Invalid bucket name
6. **Network Timeout**: Connection failures

### Test Data

Test data is provided in `tests/runtime/data/gcs/gcs_test_data.h`:
- Sample log entries (JSON, structured, metrics)
- Large log entries for size testing
- Binary and Unicode data
- Service account credentials (fake/test only)
- API response samples

## Test Coverage

### Functional Coverage

- ✅ **Authentication**: Service Account, ADC, Workload Identity
- ✅ **Data Formats**: Text, JSON, Parquet (structure)
- ✅ **Compression**: None, GZIP
- ✅ **Upload Methods**: Simple PUT, Resumable uploads
- ✅ **Error Handling**: Network, authentication, permission errors
- ✅ **Configuration**: All parameters and validation
- ✅ **Object Keys**: Time-based formatting and placeholders

### Error Coverage

- ✅ **Network Errors**: Timeouts, connection failures
- ✅ **Authentication Errors**: Invalid credentials, expired tokens
- ✅ **Authorization Errors**: Insufficient permissions
- ✅ **Client Errors**: Invalid parameters, malformed requests
- ✅ **Server Errors**: Internal server errors, service unavailable
- ✅ **Configuration Errors**: Missing parameters, invalid values

## Debugging Tests

### Common Issues

1. **Plugin not found**:
   - Ensure `-DFLB_OUT_GCS=ON` is set during cmake
   - Check that the plugin is registered in `plugins/CMakeLists.txt`

2. **Test build failures**:
   - Verify all source files exist
   - Check CMakeLists.txt entries for tests

3. **Test execution failures**:
   - Check environment variables for mock responses
   - Verify test data files are accessible
   - Review test output for specific error messages

### Debug Mode

Enable debug logging in tests:

```bash
# Set environment variable
export FLB_LOG_LEVEL=debug

# Run test with debug output
./bin/flb-rt-out_gcs --verbose
```

### Memory Debugging

Use Valgrind for memory leak detection:

```bash
valgrind --leak-check=full ./bin/flb-rt-out_gcs
```

## Continuous Integration

### Test Automation

The tests are designed for CI/CD environments:

```bash
#!/bin/bash
# CI script example

set -e

# Build with tests
cmake .. -DFLB_OUT_GCS=ON -DFLB_TESTS_RUNTIME=ON -DFLB_TESTS_INTERNAL=ON
make -j$(nproc)

# Run tests
ctest --output-on-failure -R gcs

echo "All GCS tests passed!"
```

### Test Results

Tests use the AcuTest framework which provides:
- **TAP output format** for CI integration
- **JUnit XML output** for test reporting
- **Detailed failure reporting** with line numbers
- **Test timing information**

## Manual Testing

For manual testing with real GCS:

### Setup

1. **Create service account**:
```bash
gcloud iam service-accounts create fluent-bit-test \
    --display-name="Fluent Bit Test"

gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="serviceAccount:fluent-bit-test@PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/storage.objectCreator"

gcloud iam service-accounts keys create gcs-test-key.json \
    --iam-account=fluent-bit-test@PROJECT_ID.iam.gserviceaccount.com
```

2. **Create test bucket**:
```bash
gsutil mb gs://fluent-bit-test-bucket
```

### Configuration

```conf
[INPUT]
    Name lib
    Tag  test.gcs

[OUTPUT]
    Name                gcs
    Match               *
    bucket              fluent-bit-test-bucket
    credentials_file    /path/to/gcs-test-key.json
    gcs_key_format      test-logs/%Y/%m/%d/${tag}_%H%M%S.json.gz
    format              json
    compression         gzip
    total_file_size     1MB
    upload_timeout      30s
```

### Verification

```bash
# Push test data
echo '{"message":"test log entry","level":"info"}' | \
    fluent-bit -c test-gcs.conf

# Verify upload
gsutil ls gs://fluent-bit-test-bucket/test-logs/
```

## Contributing Test Cases

When adding new features or fixing bugs:

1. **Add unit tests** for specific functionality
2. **Add integration tests** for end-to-end scenarios
3. **Update test data** if new formats are supported
4. **Document test cases** in this file
5. **Verify test coverage** using coverage tools

### Test Naming Convention

- **Test functions**: `test_gcs_<functionality>()`
- **Test files**: `gcs_<module>.c`
- **Mock helpers**: `gcs_mock_<purpose>()`
- **Test data**: `gcs_test_<type>_data`

### Test Documentation

Each test should include:
- Clear description of what is being tested
- Setup and teardown procedures
- Expected outcomes
- Error conditions being verified

This ensures maintainable and understandable test code for future contributors.