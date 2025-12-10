# Fluent Bit Kafka Examples

This directory contains examples for using Fluent Bit with Apache Kafka, including support for AWS MSK (Managed Streaming for Apache Kafka) with IAM authentication.

## Examples

### 1. Basic Kafka Example (`kafka.conf`)

A simple example demonstrating Kafka input and output with a Lua filter.

**Features:**
- Kafka consumer input
- Lua filter for message transformation
- Kafka producer output

**Usage:**
```bash
docker-compose up
```

### 2. AWS MSK IAM Authentication (`kafka_msk_iam.conf`)

Comprehensive examples for AWS MSK with IAM authentication, covering various deployment scenarios.

**Scenarios covered:**
- Standard MSK cluster (auto-detected region)
- MSK via PrivateLink (explicit region)
- MSK Serverless (auto-detected region)
- VPC Endpoint (auto-detected region)

## AWS MSK IAM Authentication

### Overview

AWS MSK supports IAM authentication, which eliminates the need to manage separate credentials for Kafka. Fluent Bit seamlessly integrates with AWS MSK IAM authentication.

### Configuration

Enable MSK IAM authentication by setting:
```ini
rdkafka.sasl.mechanism aws_msk_iam
```

### Region Detection

Fluent Bit can automatically detect the AWS region from standard MSK broker hostnames:
- `b-1.example.kafka.us-east-1.amazonaws.com` → region: `us-east-1`
- `boot-abc.kafka-serverless.us-west-2.amazonaws.com` → region: `us-west-2`
- `vpce-123.kafka.eu-west-1.vpce.amazonaws.com` → region: `eu-west-1`

### Custom DNS / PrivateLink

When using PrivateLink aliases or custom DNS names that don't contain `.amazonaws.com`, you **must** explicitly specify the region:

```ini
[OUTPUT]
    Name kafka
    Match *
    brokers my-privatelink-alias.internal.example.com:9098
    topics my-topic
    rdkafka.sasl.mechanism aws_msk_iam
    aws_region us-east-1  # REQUIRED for custom DNS
```

### AWS Credentials

MSK IAM authentication uses the standard AWS credentials chain:

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. EC2 instance profile / ECS task role (recommended for production)
3. AWS credentials file (`~/.aws/credentials`)

### Required IAM Permissions

Your IAM role or user needs the following permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kafka-cluster:Connect",
        "kafka-cluster:DescribeCluster",
        "kafka-cluster:ReadData",
        "kafka-cluster:WriteData"
      ],
      "Resource": [
        "arn:aws:kafka:REGION:ACCOUNT:cluster/CLUSTER_NAME/*",
        "arn:aws:kafka:REGION:ACCOUNT:topic/CLUSTER_NAME/*",
        "arn:aws:kafka:REGION:ACCOUNT:group/CLUSTER_NAME/*"
      ]
    }
  ]
}
```

**Note:** Adjust permissions based on your use case:
- Consumers need: `Connect`, `DescribeCluster`, `ReadData`
- Producers need: `Connect`, `WriteData`

## Configuration Parameters

### Common Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `brokers` | Comma-separated list of Kafka brokers | Yes |
| `topics` | Topic name(s) for input or output | Yes |
| `rdkafka.sasl.mechanism` | Set to `aws_msk_iam` for MSK IAM auth | For MSK IAM |
| `aws_region` | AWS region (auto-detected if not set) | Only for custom DNS |
| `group_id` | Consumer group ID | For input |

### Additional librdkafka Parameters

You can pass any librdkafka configuration using the `rdkafka.` prefix:

```ini
rdkafka.socket.timeout.ms 60000
rdkafka.metadata.max.age.ms 180000
rdkafka.request.timeout.ms 30000
```

For a complete list of parameters, see the [librdkafka configuration documentation](https://github.com/confluentinc/librdkafka/blob/master/CONFIGURATION.md).

## Testing

### Local Kafka (Docker)

1. Start the Kafka stack:
   ```bash
   cd examples/kafka_filter
   docker-compose up -d
   ```

2. Run Fluent Bit:
   ```bash
   fluent-bit -c kafka.conf
   ```

3. Produce test messages:
   ```bash
   ./scripts/kafka-produce.sh
   ```

4. Consume messages:
   ```bash
   ./scripts/kafka-consume.sh
   ```

### AWS MSK

1. Update `kafka_msk_iam.conf` with your MSK cluster details
2. Ensure AWS credentials are configured
3. Run Fluent Bit:
   ```bash
   fluent-bit -c kafka_msk_iam.conf
   ```

## Troubleshooting

### Authentication Failures

**Error:** `failed to setup MSK IAM authentication OAuth callback`

**Solutions:**
- For custom DNS/PrivateLink: Add `aws_region` parameter
- Verify AWS credentials are available
- Check IAM permissions

### Region Detection Issues

**Error:** `failed to auto-detect region from broker address`

**Solution:**
Explicitly set the region:
```ini
aws_region us-east-1
```

### Connection Timeouts

**Solution:**
Increase timeout values:
```ini
rdkafka.socket.timeout.ms 60000
rdkafka.metadata.max.age.ms 180000
```

## Additional Resources

- [Fluent Bit Kafka Documentation](https://docs.fluentbit.io/)
- [AWS MSK IAM Access Control](https://docs.aws.amazon.com/msk/latest/developerguide/iam-access-control.html)
- [librdkafka Configuration](https://github.com/confluentinc/librdkafka/blob/master/CONFIGURATION.md)

## Support

For issues or questions:
- [Fluent Bit GitHub Issues](https://github.com/fluent/fluent-bit/issues)
- [Fluent Bit Slack Community](https://fluentbit.io/slack)
