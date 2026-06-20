# librdkafka examples

This directory contains example applications utilizing librdkafka.
The examples are built by running `make` and they will be be linked
statically or dynamically to librdkafka in the parent `../src` directory.

Begin with the following examples:

 * [consumer.c](consumer.c) - a typical C high-level consumer application.
 * [producer.c](producer.c) - a typical C producer application.
 * [producer.cpp](producer.cpp) - a typical C++ producer application.
 * [idempotent_producer.c](idempotent_producer.c) - Idempotent producer.
 * [transactions.c](transactions.c) - Full exactly once semantics (EOS)
                                      transactional consumer-producer exammple.
                                      Requires Apache Kafka 2.5 or later.
 * [transactions-older-broker.c](transactions-older-broker.c) - Same as
   `transactions.c` but for Apache Kafka versions 2.4.x and older which
   lack KIP-447 support.
 * [misc.c](misc.c) - a collection of miscellaneous usage examples.


For more complex uses, see:
 * [rdkafka_example.c](rdkafka_example.c) - simple consumer, producer, metadata listing, kitchen sink, etc.
 * [rdkafka_example.cpp](rdkafka_example.cpp) - simple consumer, producer, metadata listing in C++.
 * [rdkafka_complex_consumer_example.c](rdkafka_complex_consumer_example.c) - a more contrived high-level C consumer example.
 * [rdkafka_complex_consumer_example.cpp](rdkafka_complex_consumer_example.cpp) - a more contrived high-level C++ consumer example.
 * [rdkafka_consume_batch.cpp](rdkafka_consume_batch.cpp) - batching high-level C++ consumer example.
 * [rdkafka_performance.c](rdkafka_performance.c) - performance, benchmark, latency producer and consumer tool.
 * [kafkatest_verifiable_client.cpp](kafkatest_verifiable_client.cpp) - for use with the official Apache Kafka client system tests.
 * [openssl_engine_example.cpp](openssl_engine_example.cpp) - metadata listing in C++ over SSL channel established using OpenSSL engine.


 For Admin API examples see:
 * [delete_records.c](delete_records.c) - Delete records.
 * [list_consumer_groups.c](list_consumer_groups.c) - List consumer groups.
 * [describe_consumer_groups.c](describe_consumer_groups.c) - Describe consumer groups.
 * [describe_topics.c](describe_topics.c) - Describe topics.
 * [describe_cluster.c](describe_cluster.c) - Describe cluster.
 * [list_consumer_group_offsets.c](list_consumer_group_offsets.c) - List offsets of a consumer group.
 * [alter_consumer_group_offsets.c](alter_consumer_group_offsets.c) - Alter offsets of a consumer group.
 * [incremental_alter_configs.c](incremental_alter_configs.c) - Incrementally alter resource configurations.
 * [user_scram.c](user_scram.c) - Describe or alter user SCRAM credentials.
