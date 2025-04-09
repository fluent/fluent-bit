# Confluent Platform package verification

This small set of scripts verifies the librdkafka packages that
are part of the Confluent Platform.

The base_url is the http S3 bucket path to the a PR job, or similar.

## How to use

    $ ./verify-packages.sh 7.6 https://packages.confluent.io

Requires docker and patience.

