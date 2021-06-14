# librdkafka v1.6.0

librdkafka v1.6.0 is feature release:

 * [KIP-429 Incremental rebalancing](https://cwiki.apache.org/confluence/display/KAFKA/KIP-429%3A+Kafka+Consumer+Incremental+Rebalance+Protocol) with sticky
   consumer group partition assignor (KIP-54) (by @mhowlett).
 * [KIP-480 Sticky producer partitioning](https://cwiki.apache.org/confluence/display/KAFKA/KIP-480%3A+Sticky+Partitioner) (`sticky.partitioning.linger.ms`) -
   achieves higher throughput and lower latency through sticky selection
   of random partition (by @abbycriswell).
 * AdminAPI: Add support for `DeleteRecords()`, `DeleteGroups()` and
   `DeleteConsumerGroupOffsets()` (by @gridaphobe)
 * [KIP-447 Producer scalability for exactly once semantics](https://cwiki.apache.org/confluence/display/KAFKA/KIP-447%3A+Producer+scalability+for+exactly+once+semantics) -
   allows a single transactional producer to be used for multiple input
   partitions. Requires Apache Kafka 2.5 or later.
 * Transactional producer fixes and improvements, see **Transactional Producer fixes** below.
 * The [librdkafka.redist](https://www.nuget.org/packages/librdkafka.redist/)
   NuGet package now supports Linux ARM64/Aarch64.


## Upgrade considerations

 * Sticky producer partitioning (`sticky.partitioning.linger.ms`) is
   enabled by default (10 milliseconds) which affects the distribution of
   randomly partitioned messages, where previously these messages would be
   evenly distributed over the available partitions they are now partitioned
   to a single partition for the duration of the sticky time
   (10 milliseconds by default) before a new random sticky partition
   is selected.
 * The new KIP-447 transactional producer scalability guarantees are only
   supported on Apache Kafka 2.5 or later, on earlier releases you will
   need to use one producer per input partition for EOS. This limitation
   is not enforced by the producer or broker.
 * Error handling for the transactional producer has been improved, see
   the **Transactional Producer fixes** below for more information.


## Known issues

 * The Transactional Producer's API timeout handling is inconsistent with the
   underlying protocol requests, it is therefore strongly recommended that
   applications call `rd_kafka_commit_transaction()` and
   `rd_kafka_abort_transaction()` with the `timeout_ms` parameter
   set to `-1`, which will use the remaining transaction timeout.


## Enhancements

 * KIP-107, KIP-204: AdminAPI: Added `DeleteRecords()` (by @gridaphobe).
 * KIP-229: AdminAPI: Added `DeleteGroups()` (by @gridaphobe).
 * KIP-496: AdminAPI: Added `DeleteConsumerGroupOffsets()`.
 * KIP-464: AdminAPI: Added support for broker-side default partition count
   and replication factor for `CreateTopics()`.
 * Windows: Added `ssl.ca.certificate.stores` to specify a list of
   Windows Certificate Stores to read CA certificates from, e.g.,
   `CA,Root`. `Root` remains the default store.
 * Use reentrant `rand_r()` on supporting platforms which decreases lock
   contention (@azat).
 * Added `assignor` debug context for troubleshooting consumer partition
   assignments.
 * Updated to OpenSSL v1.1.1i when building dependencies.
 * Update bundled lz4 (used when `./configure --disable-lz4-ext`) to v1.9.3
   which has vast performance improvements.
 * Added `rd_kafka_conf_get_default_topic_conf()` to retrieve the
   default topic configuration object from a global configuration object.
 * Added `conf` debugging context to `debug` - shows set configuration
   properties on client and topic instantiation. Sensitive properties
   are redacted.
 * Added `rd_kafka_queue_yield()` to cancel a blocking queue call.
 * Will now log a warning when multiple ClusterIds are seen, which is an
   indication that the client might be erroneously configured to connect to
   multiple clusters which is not supported.
 * Added `rd_kafka_seek_partitions()` to seek multiple partitions to
   per-partition specific offsets.


## Fixes

### General fixes

 * Fix a use-after-free crash when certain coordinator requests were retried.
 * The C++ `oauthbearer_set_token()` function would call `free()` on
   a `new`-created pointer, possibly leading to crashes or heap corruption (#3194)

### Consumer fixes

 * The consumer assignment and consumer group implementations have been
   decoupled, simplified and made more strict and robust. This will sort out
   a number of edge cases for the consumer where the behaviour was previously
   undefined.
 * Partition fetch state was not set to STOPPED if OffsetCommit failed.
 * The session timeout is now enforced locally also when the coordinator
   connection is down, which was not previously the case.


### Transactional Producer fixes

 * Transaction commit or abort failures on the broker, such as when the
   producer was fenced by a newer instance, were not propagated to the
   application resulting in failed commits seeming successful.
   This was a critical race condition for applications that had a delay after
   producing messages (or sendings offsets) before committing or
   aborting the transaction. This issue has now been fixed and test coverage
   improved.
 * The transactional producer API would return `RD_KAFKA_RESP_ERR__STATE`
   when API calls were attempted after the transaction had failed, we now
   try to return the error that caused the transaction to fail in the first
   place, such as `RD_KAFKA_RESP_ERR__FENCED` when the producer has
   been fenced, or `RD_KAFKA_RESP_ERR__TIMED_OUT` when the transaction
   has timed out.
 * Transactional producer retry count for transactional control protocol
   requests has been increased from 3 to infinite, retriable errors
   are now automatically retried by the producer until success or the
   transaction timeout is exceeded. This fixes the case where
   `rd_kafka_send_offsets_to_transaction()` would fail the current
   transaction into an abortable state when `CONCURRENT_TRANSACTIONS` was
   returned by the broker (which is a transient error) and the 3 retries
   were exhausted.


### Producer fixes

 * Calling `rd_kafka_topic_new()` with a topic config object with
   `message.timeout.ms` set could sometimes adjust the global `linger.ms`
   property (if not explicitly configured) which was not desired, this is now
   fixed and the auto adjustment is only done based on the
   `default_topic_conf` at producer creation.
 * `rd_kafka_flush()` could previously return `RD_KAFKA_RESP_ERR__TIMED_OUT`
   just as the timeout was reached if the messages had been flushed but
   there were now no more messages. This has been fixed.




# librdkafka v1.5.3

librdkafka v1.5.3 is a maintenance release.

## Upgrade considerations

 * CentOS 6 is now EOL and is no longer included in binary librdkafka packages,
   such as NuGet.

## Fixes

### General fixes

 * Fix a use-after-free crash when certain coordinator requests were retried.
 * Coordinator requests could be left uncollected on instance destroy which
   could lead to hang.
 * Fix rare 1 second stalls by forcing rdkafka main thread wakeup when a new
   next-timer-to-be-fired is scheduled.
 * Fix additional cases where broker-side automatic topic creation might be
   triggered unexpectedly.
 * AdminAPI: The operation_timeout (on-broker timeout) previously defaulted to 0,
   but now defaults to `socket.timeout.ms` (60s).
 * Fix possible crash for Admin API protocol requests that fail at the
   transport layer or prior to sending.


### Consumer fixes

 * Consumer would not filter out messages for aborted transactions
   if the messages were compressed (#3020).
 * Consumer destroy without prior `close()` could hang in certain
   cgrp states (@gridaphobe, #3127).
 * Fix possible null dereference in `Message::errstr()` (#3140).
 * The `roundrobin` partition assignment strategy could get stuck in an
   endless loop or generate uneven assignments in case the group members
   had asymmetric subscriptions (e.g., c1 subscribes to t1,t2 while c2
   subscribes to t2,t3).  (#3159)
 * Mixing committed and logical or absolute offsets in the partitions
   passed to `rd_kafka_assign()` would in previous released ignore the
   logical or absolute offsets and use the committed offsets for all partitions.
   This is now fixed. (#2938)




# librdkafka v1.5.2

librdkafka v1.5.2 is a maintenance release.


## Upgrade considerations

 * The default value for the producer configuration property `retries` has
   been increased from 2 to infinity, effectively limiting Produce retries to
   only `message.timeout.ms`.
   As the reasons for the automatic internal retries vary (various broker error
   codes as well as transport layer issues), it doesn't make much sense to limit
   the number of retries for retriable errors, but instead only limit the
   retries based on the allowed time to produce a message.
 * The default value for the producer configuration property
   `request.timeout.ms` has been increased from 5 to 30 seconds to match
   the Apache Kafka Java producer default.
   This change yields increased robustness for broker-side congestion.


## Enhancements

 * The generated `CONFIGURATION.md` (through `rd_kafka_conf_properties_show())`)
   now include all properties and values, regardless if they were included in
   the build, and setting a disabled property or value through
   `rd_kafka_conf_set()` now returns `RD_KAFKA_CONF_INVALID` and provides
   a more useful error string saying why the property can't be set.
 * Consumer configs on producers and vice versa will now be logged with
   warning messages on client instantiation.

## Fixes

### Security fixes

 * There was an incorrect call to zlib's `inflateGetHeader()` with
   unitialized memory pointers that could lead to the GZIP header of a fetched
   message batch to be copied to arbitrary memory.
   This function call has now been completely removed since the result was
   not used.
   Reported by Ilja van Sprundel.


### General fixes

 * `rd_kafka_topic_opaque()` (used by the C++ API) would cause object
   refcounting issues when used on light-weight (error-only) topic objects
   such as consumer errors (#2693).
 * Handle name resolution failures when formatting IP addresses in error logs,
   and increase printed hostname limit to ~256 bytes (was ~60).
 * Broker sockets would be closed twice (thus leading to potential race
   condition with fd-reuse in other threads) if a custom `socket_cb` would
   return error.

### Consumer fixes

 * The `roundrobin` `partition.assignment.strategy` could crash (assert)
   for certain combinations of members and partitions.
   This is a regression in v1.5.0. (#3024)
 * The C++ `KafkaConsumer` destructor did not destroy the underlying
   C `rd_kafka_t` instance, causing a leak if `close()` was not used.
 * Expose rich error strings for C++ Consumer `Message->errstr()`.
 * The consumer could get stuck if an outstanding commit failed during
   rebalancing (#2933).
 * Topic authorization errors during fetching are now reported only once (#3072).

### Producer fixes

 * Topic authorization errors are now properly propagated for produced messages,
   both through delivery reports and as `ERR_TOPIC_AUTHORIZATION_FAILED`
   return value from `produce*()` (#2215)
 * Treat cluster authentication failures as fatal in the transactional
   producer (#2994).
 * The transactional producer code did not properly reference-count partition
   objects which could in very rare circumstances lead to a use-after-free bug
   if a topic was deleted from the cluster when a transaction was using it.
 * `ERR_KAFKA_STORAGE_ERROR` is now correctly treated as a retriable
   produce error (#3026).
 * Messages that timed out locally would not fail the ongoing transaction.
   If the application did not take action on failed messages in its delivery
   report callback and went on to commit the transaction, the transaction would
   be successfully committed, simply omitting the failed messages.
 * EndTxnRequests (sent on commit/abort) are only retried in allowed
   states (#3041).
   Previously the transaction could hang on commit_transaction() if an abortable
   error was hit and the EndTxnRequest was to be retried.


*Note: there was no v1.5.1 librdkafka release*




# librdkafka v1.5.0

The v1.5.0 release brings usability improvements, enhancements and fixes to
librdkafka.

## Enhancements

 * Improved broker connection error reporting with more useful information and
   hints on the cause of the problem.
 * Consumer: Propagate errors when subscribing to unavailable topics (#1540)
 * Producer: Add `batch.size` producer configuration property (#638)
 * Add `topic.metadata.propagation.max.ms` to allow newly manually created
   topics to be propagated throughout the cluster before reporting them
   as non-existent. This fixes race issues where CreateTopics() is
   quickly followed by produce().
 * Prefer least idle connection for periodic metadata refreshes, et.al.,
   to allow truly idle connections to time out and to avoid load-balancer-killed
   idle connection errors (#2845)
 * Added `rd_kafka_event_debug_contexts()` to get the debug contexts for
   a debug log line (by @wolfchimneyrock).
 * Added Test scenarios which define the cluster configuration.
 * Added MinGW-w64 builds (@ed-alertedh, #2553)
 * `./configure --enable-XYZ` now requires the XYZ check to pass,
   and `--disable-XYZ` disables the feature altogether (@benesch)
 * Added `rd_kafka_produceva()` which takes an array of produce arguments
   for situations where the existing `rd_kafka_producev()` va-arg approach
   can't be used.
 * Added `rd_kafka_message_broker_id()` to see the broker that a message
   was produced or fetched from, or an error was associated with.
 * Added RTT/delay simulation to mock brokers.


## Upgrade considerations

 * Subscribing to non-existent and unauthorized topics will now propagate
   errors `RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART` and
   `RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED` to the application through
   the standard consumer error (the err field in the message object).
 * Consumer will no longer trigger auto creation of topics,
   `allow.auto.create.topics=true` may be used to re-enable the old deprecated
   functionality.
 * The default consumer pre-fetch queue threshold `queued.max.messages.kbytes`
   has been decreased from 1GB to 64MB to avoid excessive network usage for low
   and medium throughput consumer applications. High throughput consumer
   applications may need to manually set this property to a higher value.
 * The default consumer Fetch wait time has been increased from 100ms to 500ms
   to avoid excessive network usage for low throughput topics.
 * If OpenSSL is linked statically, or `ssl.ca.location=probe` is configured,
   librdkafka will probe known CA certificate paths and automatically use the
   first one found. This should alleviate the need to configure
   `ssl.ca.location` when the statically linked OpenSSL's OPENSSLDIR differs
   from the system's CA certificate path.
 * The heuristics for handling Apache Kafka < 0.10 brokers has been removed to
   improve connection error handling for modern Kafka versions.
   Users on Brokers 0.9.x or older should already be configuring
   `api.version.request=false` and `broker.version.fallback=...` so there
   should be no functional change.
 * The default producer batch accumulation time, `linger.ms`, has been changed
   from 0.5ms to 5ms to improve batch sizes and throughput while reducing
   the per-message protocol overhead.
   Applications that require lower produce latency than 5ms will need to
   manually set `linger.ms` to a lower value.
 * librdkafka's build tooling now requires Python 3.x (python3 interpreter).


## Fixes

### General fixes

 * The client could crash in rare circumstances on ApiVersion or
   SaslHandshake request timeouts (#2326)
 * `./configure --LDFLAGS='a=b, c=d'` with arguments containing = are now
   supported (by @sky92zwq).
 * `./configure` arguments now take precedence over cached `configure` variables
   from previous invocation.
 * Fix theoretical crash on coord request failure.
 * Unknown partition error could be triggered for existing partitions when
   additional partitions were added to a topic (@benesch, #2915)
 * Quickly refresh topic metadata for desired but non-existent partitions.
   This will speed up the initial discovery delay when new partitions are added
   to an existing topic (#2917).


### Consumer fixes

 * The roundrobin partition assignor could crash if subscriptions
   where asymmetrical (different sets from different members of the group).
   Thanks to @ankon and @wilmai for identifying the root cause (#2121).
 * The consumer assignors could ignore some topics if there were more subscribed
   topics than consumers in taking part in the assignment.
 * The consumer would connect to all partition leaders of a topic even
   for partitions that were not being consumed (#2826).
 * Initial consumer group joins should now be a couple of seconds quicker
   thanks expedited query intervals (@benesch).
 * Fix crash and/or inconsistent subscriptions when using multiple consumers
   (in the same process) with wildcard topics on Windows.
 * Don't propagate temporary offset lookup errors to application.
 * Immediately refresh topic metadata when partitions are reassigned to other
   brokers, avoiding a fetch stall of up to `topic.metadata.refresh.interval.ms`. (#2955)
 * Memory for batches containing control messages would not be freed when
   using the batch consume APIs (@pf-qiu, #2990).


### Producer fixes

 * Proper locking for transaction state in EndTxn handler.



# librdkafka v1.4.4

v1.4.4 is a maintenance release with the following fixes and enhancements:

 * Transactional producer could crash on request timeout due to dereferencing
   NULL pointer of non-existent response object.
 * Mark `rd_kafka_send_offsets_to_transaction()` CONCURRENT_TRANSACTION (et.al)
   errors as retriable.
 * Fix crash on transactional coordinator FindCoordinator request failure.
 * Minimize broker re-connect delay when broker's connection is needed to
   send requests.
 * Proper locking for transaction state in EndTxn handler.
 * `socket.timeout.ms` was ignored when `transactional.id` was set.
 * Added RTT/delay simulation to mock brokers.

*Note: there was no v1.4.3 librdkafka release*



# librdkafka v1.4.2

v1.4.2 is a maintenance release with the following fixes and enhancements:

 * Fix produce/consume hang after partition goes away and comes back,
   such as when a topic is deleted and re-created.
 * Consumer: Reset the stored offset when partitions are un-assign()ed (fixes #2782).
    This fixes the case where a manual offset-less commit() or the auto-committer
    would commit a stored offset from a previous assignment before
    a new message was consumed by the application.
 * Probe known CA cert paths and set default `ssl.ca.location` accordingly
   if OpenSSL is statically linked or `ssl.ca.location` is set to `probe`.
 * Per-partition OffsetCommit errors were unhandled (fixes #2791)
 * Seed the PRNG (random number generator) by default, allow application to
   override with `enable.random.seed=false` (#2795)
 * Fix stack overwrite (of 1 byte) when SaslHandshake MechCnt is zero
 * Align bundled c11 threads (tinycthreads) constants to glibc and musl (#2681)
 * Fix return value of rd_kafka_test_fatal_error() (by @ckb42)
 * Ensure CMake sets disabled defines to zero on Windows (@benesch)


*Note: there was no v1.4.1 librdkafka release*





# Older releases

See https://github.com/edenhill/librdkafka/releases
