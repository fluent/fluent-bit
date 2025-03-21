# Confluent Platform package verification

This small set of scripts verifies the librdkafka packages that
are part of the Confluent Platform.

The base_url is the http S3 bucket path to the a PR job, or similar.

## How to use

    $ ./verify-packages.sh 5.3 https://thes3bucketpath/X/Y


Requires docker and patience.

