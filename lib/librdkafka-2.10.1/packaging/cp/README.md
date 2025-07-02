# Confluent Platform package verification

This small set of scripts verifies the librdkafka packages that
are part of the Confluent Platform.

The base_url is the http S3 bucket path to the a PR job, or similar.
Pass the platform (e.g. linux/arm64) and the expected librdkafka version too.

## How to use

```
$ ./verify-packages.sh https://packages.confluent.io linux/amd64 2.8.0
```

Requires docker and patience.

