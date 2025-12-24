#!/bin/bash

echo "=== Fluent Bit S3 Comprehensive Test ==="
echo ""

# Create temporary directories
STORE_DIR="/tmp/fluent-bit-test"
mkdir -p "$STORE_DIR/parquet-gzip-simple"
mkdir -p "$STORE_DIR/json-snappy-complex-low"
mkdir -p "$STORE_DIR/json-gzip-complex-medium"
mkdir -p "$STORE_DIR/json-zstd-complex-high"
echo "✓ Created store directories"

echo ""
echo "Test Configuration:"
echo "-------------------"
echo "Formats:"
echo "  - Parquet (internal GZIP compression)"
echo "  - JSON (Snappy, GZIP, ZSTD)"
echo ""
echo "Data Complexity:"
echo "  - Simple: Basic key-value pairs"
echo "  - Complex: Nested objects, arrays, deep structures"
echo ""
echo "Traffic Levels:"
echo "  - Low: 1 event/sec"
echo "  - Medium: 10-20 events/sec"
echo "  - High: 50-100 events/sec"
echo ""
echo "Upload to: s3://s3-bucket-kafka-sink/tests/comprehensive/"
echo "Press Ctrl+C to stop"
echo ""

# Run Fluent Bit
./build/bin/fluent-bit -c fluent-bit-s3-parquet.conf

# Cleanup
echo ""
echo "Cleaning up..."
