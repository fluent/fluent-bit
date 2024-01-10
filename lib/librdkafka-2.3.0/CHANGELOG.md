# librdkafka v2.3.0

librdkafka v2.3.0 is a feature release:

 * [KIP-516](https://cwiki.apache.org/confluence/display/KAFKA/KIP-516%3A+Topic+Identifiers)
   Partial support of topic identifiers. Topic identifiers in metadata response
   available through the new `rd_kafka_DescribeTopics` function (#4300, #4451).
 * [KIP-117](https://cwiki.apache.org/confluence/display/KAFKA/KIP-117%3A+Add+a+public+AdminClient+API+for+Kafka+admin+operations) Add support for AdminAPI `DescribeCluster()` and `DescribeTopics()`
  (#4240, @jainruchir).
 * [KIP-430](https://cwiki.apache.org/confluence/display/KAFKA/KIP-430+-+Return+Authorized+Operations+in+Describe+Responses):
   Return authorized operations in Describe Responses.
   (#4240, @jainruchir).
 * [KIP-580](https://cwiki.apache.org/confluence/display/KAFKA/KIP-580%3A+Exponential+Backoff+for+Kafka+Clients): Added Exponential Backoff mechanism for
   retriable requests with `retry.backoff.ms` as minimum backoff and `retry.backoff.max.ms` as the
   maximum backoff, with 20% jitter (#4422).
 * [KIP-396](https://cwiki.apache.org/confluence/pages/viewpage.action?pageId=97551484): completed the implementation with
   the addition of ListOffsets (#4225).
 * Fixed ListConsumerGroupOffsets not fetching offsets for all the topics in a group with Apache Kafka version below 2.4.0.
 * Add missing destroy that leads to leaking partition structure memory when there
   are partition leader changes and a stale leader epoch is received (#4429).
 * Fix a segmentation fault when closing a consumer using the
   cooperative-sticky assignor before the first assignment (#4381).
 * Fix for insufficient buffer allocation when allocating rack information (@wolfchimneyrock, #4449).
 * Fix for infinite loop of OffsetForLeaderEpoch requests on quick leader changes. (#4433).
 * Fix to add leader epoch to control messages, to make sure they're stored
   for committing even without a subsequent fetch message (#4434).
 * Fix for stored offsets not being committed if they lacked the leader epoch (#4442).
 * Upgrade OpenSSL to v3.0.11 (while building from source) with various security fixes,
   check the [release notes](https://www.openssl.org/news/cl30.txt)
   (#4454, started by @migarc1).
 * Fix to ensure permanent errors during offset validation continue being retried and
   don't cause an offset reset (#4447).
 * Fix to ensure max.poll.interval.ms is reset when rd_kafka_poll is called with
   consume_cb (#4431).
 * Fix for idempotent producer fatal errors, triggered after a possibly persisted message state (#4438).
 * Fix `rd_kafka_query_watermark_offsets` continuing beyond timeout expiry (#4460).
 * Fix `rd_kafka_query_watermark_offsets` not refreshing the partition leader
   after a leader change and subsequent `NOT_LEADER_OR_FOLLOWER` error (#4225).


## Upgrade considerations

 * `retry.backoff.ms`:
   If it is set greater than `retry.backoff.max.ms` which has the default value of 1000 ms then it is assumes the value of `retry.backoff.max.ms`.
   To change this behaviour make sure that `retry.backoff.ms` is always less than `retry.backoff.max.ms`.
   If equal then the backoff will be linear instead of exponential.

 * `topic.metadata.refresh.fast.interval.ms`:
   If it is set greater than `retry.backoff.max.ms` which has the default value of 1000 ms then it is assumes the value of `retry.backoff.max.ms`.
   To change this behaviour make sure that `topic.metadata.refresh.fast.interval.ms` is always less than `retry.backoff.max.ms`.
   If equal then the backoff will be linear instead of exponential.


## Fixes

### General fixes

 * An assertion failed with insufficient buffer size when allocating
   rack information on 32bit architectures.
   Solved by aligning all allocations to the maximum allowed word size (#4449).
 * The timeout for `rd_kafka_query_watermark_offsets` was not enforced after
   making the necessary ListOffsets requests, and thus, it never timed out in
   case of broker/network issues. Fixed by setting an absolute timeout (#4460).

### Idempotent producer fixes

 * After a possibly persisted error, such as a disconnection or a timeout, next expected sequence
   used to increase, leading to a fatal error if the message wasn't persisted and
   the second one in queue failed with an `OUT_OF_ORDER_SEQUENCE_NUMBER`.
   The error could contain the message "sequence desynchronization" with
   just one possibly persisted error or "rewound sequence number" in case of
   multiple errored messages.
   Solved by treating the possible persisted message as _not_ persisted,
   and expecting a `DUPLICATE_SEQUENCE_NUMBER` error in case it was or
   `NO_ERROR` in case it wasn't, in both cases the message will be considered
   delivered (#4438).

### Consumer fixes

  * Stored offsets were excluded from the commit if the leader epoch was
    less than committed epoch, as it's possible if leader epoch is the default -1.
    This didn't happen in Python, Go and .NET bindings when stored position was
    taken from the message.
    Solved by checking only that the stored offset is greater
    than committed one, if either stored or committed leader epoch is -1 (#4442).
  * If an OffsetForLeaderEpoch request was being retried, and the leader changed
    while the retry was in-flight, an infinite loop of requests was triggered,
    because we weren't updating the leader epoch correctly.
    Fixed by updating the leader epoch before sending the request (#4433).
  * During offset validation a permanent error like host resolution failure
    would cause an offset reset.
    This isn't what's expected or what the Java implementation does.
    Solved by retrying even in case of permanent errors (#4447).
  * If using `rd_kafka_poll_set_consumer`, along with a consume callback, and then
    calling `rd_kafka_poll` to service the callbacks, would not reset
    `max.poll.interval.ms.` This was because we were only checking `rk_rep` for
    consumer messages, while the method to service the queue internally also
    services the queue forwarded to from `rk_rep`, which is `rkcg_q`.
    Solved by moving the `max.poll.interval.ms` check into `rd_kafka_q_serve` (#4431).
  * After a leader change a `rd_kafka_query_watermark_offsets` call would continue
    trying to call ListOffsets on the old leader, if the topic wasn't included in
    the subscription set, so it started querying the new leader only after
    `topic.metadata.refresh.interval.ms` (#4225).



# librdkafka v2.2.0

librdkafka v2.2.0 is a feature release:

 * Fix a segmentation fault when subscribing to non-existent topics and
   using the consume batch functions (#4273).
 * Store offset commit metadata in `rd_kafka_offsets_store` (@mathispesch, #4084).
 * Fix a bug that happens when skipping tags, causing buffer underflow in
   MetadataResponse (#4278).
 * Fix a bug where topic leader is not refreshed in the same metadata call even if the leader is
   present.
 * [KIP-881](https://cwiki.apache.org/confluence/display/KAFKA/KIP-881%3A+Rack-aware+Partition+Assignment+for+Kafka+Consumers):
   Add support for rack-aware partition assignment for consumers
   (#4184, #4291, #4252).
 * Fix several bugs with sticky assignor in case of partition ownership
   changing between members of the consumer group (#4252).
 * [KIP-368](https://cwiki.apache.org/confluence/display/KAFKA/KIP-368%3A+Allow+SASL+Connections+to+Periodically+Re-Authenticate):
   Allow SASL Connections to Periodically Re-Authenticate
   (#4301, started by @vctoriawu).
 * Avoid treating an OpenSSL error as a permanent error and treat unclean SSL
   closes as normal ones (#4294).
 * Added `fetch.queue.backoff.ms` to the consumer to control how long
   the consumer backs off next fetch attempt. (@bitemyapp, @edenhill, #2879)
 * [KIP-235](https://cwiki.apache.org/confluence/display/KAFKA/KIP-235%3A+Add+DNS+alias+support+for+secured+connection):
   Add DNS alias support for secured connection (#4292).
 * [KIP-339](https://cwiki.apache.org/confluence/display/KAFKA/KIP-339%3A+Create+a+new+IncrementalAlterConfigs+API):
   IncrementalAlterConfigs API (started by @PrasanthV454, #4110).
 * [KIP-554](https://cwiki.apache.org/confluence/display/KAFKA/KIP-554%3A+Add+Broker-side+SCRAM+Config+API): Add Broker-side SCRAM Config API (#4241).


## Enhancements

 * Added `fetch.queue.backoff.ms` to the consumer to control how long
   the consumer backs off next fetch attempt. When the pre-fetch queue
   has exceeded its queuing thresholds: `queued.min.messages` and
   `queued.max.messages.kbytes` it backs off for 1 seconds.
   If those parameters have to be set too high to hold 1 s of data,
   this new parameter allows to back off the fetch earlier, reducing memory
   requirements.


## Fixes

### General fixes

 * Fix a bug that happens when skipping tags, causing buffer underflow in
   MetadataResponse. This is triggered since RPC version 9 (v2.1.0),
   when using Confluent Platform, only when racks are set,
   observers are activated and there is more than one partition.
   Fixed by skipping the correct amount of bytes when tags are received.
 * Avoid treating an OpenSSL error as a permanent error and treat unclean SSL
   closes as normal ones. When SSL connections are closed without `close_notify`,
   in OpenSSL 3.x a new type of error is set and it was interpreted as permanent
   in librdkafka. It can cause a different issue depending on the RPC.
   If received when waiting for OffsetForLeaderEpoch response, it triggers
   an offset reset following the configured policy.
   Solved by treating SSL errors as transport errors and
   by setting an OpenSSL flag that allows to treat unclean SSL closes as normal
   ones. These types of errors can happen it the other side doesn't support `close_notify` or if there's a TCP connection reset.


### Consumer fixes

  * In case of multiple owners of a partition with different generations, the
    sticky assignor would pick the earliest (lowest generation) member as the
    current owner, which would lead to stickiness violations. Fixed by
    choosing the latest (highest generation) member.
  * In case where the same partition is owned by two members with the same
    generation, it indicates an issue. The sticky assignor had some code to
    handle this, but it was non-functional, and did not have parity with the
    Java assignor. Fixed by invalidating any such partition from the current
    assignment completely.



# librdkafka v2.1.1

librdkafka v2.1.1 is a maintenance release:

 * Avoid duplicate messages when a fetch response is received
   in the middle of an offset validation request (#4261).
 * Fix segmentation fault when subscribing to a non-existent topic and
   calling `rd_kafka_message_leader_epoch()` on the polled `rkmessage` (#4245).
 * Fix a segmentation fault when fetching from follower and the partition lease
   expires while waiting for the result of a list offsets operation (#4254).
 * Fix documentation for the admin request timeout, incorrectly stating -1 for infinite
   timeout. That timeout can't be infinite.
 * Fix CMake pkg-config cURL require and use
   pkg-config `Requires.private` field (@FantasqueX, @stertingen, #4180).
 * Fixes certain cases where polling would not keep the consumer
   in the group or make it rejoin it (#4256).
 * Fix to the C++ set_leader_epoch method of TopicPartitionImpl,
   that wasn't storing the passed value (@pavel-pimenov, #4267).

## Fixes

### Consumer fixes

 * Duplicate messages can be emitted when a fetch response is received
   in the middle of an offset validation request. Solved by avoiding
   a restart from last application offset when offset validation succeeds.
 * When fetching from follower, if the partition lease expires after 5 minutes,
   and a list offsets operation was requested to retrieve the earliest
   or latest offset, it resulted in segmentation fault. This was fixed by
   allowing threads different from the main one to call
   the `rd_kafka_toppar_set_fetch_state` function, given they hold
   the lock on the `rktp`.
 * In v2.1.0, a bug was fixed which caused polling any queue to reset the
   `max.poll.interval.ms`. Only certain functions were made to reset the timer,
   but it is possible for the user to obtain the queue with messages from
   the broker, skipping these functions. This was fixed by encoding information
   in a queue itself, that, whether polling, resets the timer.



# librdkafka v2.1.0

librdkafka v2.1.0 is a feature release:

* [KIP-320](https://cwiki.apache.org/confluence/display/KAFKA/KIP-320%3A+Allow+fetchers+to+detect+and+handle+log+truncation)
  Allow fetchers to detect and handle log truncation (#4122).
* Fix a reference count issue blocking the consumer from closing (#4187).
* Fix a protocol issue with ListGroups API, where an extra
  field was appended for API Versions greater than or equal to 3 (#4207).
* Fix an issue with `max.poll.interval.ms`, where polling any queue would cause
  the timeout to be reset (#4176).
* Fix seek partition timeout, was one thousand times lower than the passed
  value (#4230).
* Fix multiple inconsistent behaviour in batch APIs during **pause** or **resume** operations (#4208).
  See **Consumer fixes** section below for more information.
* Update lz4.c from upstream. Fixes [CVE-2021-3520](https://github.com/advisories/GHSA-gmc7-pqv9-966m)
  (by @filimonov, #4232).
* Upgrade OpenSSL to v3.0.8 with various security fixes,
  check the [release notes](https://www.openssl.org/news/cl30.txt) (#4215).

## Enhancements

 * Added `rd_kafka_topic_partition_get_leader_epoch()` (and `set..()`).
 * Added partition leader epoch APIs:
   - `rd_kafka_topic_partition_get_leader_epoch()` (and `set..()`)
   - `rd_kafka_message_leader_epoch()`
   - `rd_kafka_*assign()` and `rd_kafka_seek_partitions()` now supports
     partitions with a leader epoch set.
   - `rd_kafka_offsets_for_times()` will return per-partition leader-epochs.
   - `leader_epoch`, `stored_leader_epoch`, and `committed_leader_epoch`
     added to per-partition statistics.


## Fixes

### OpenSSL fixes

 * Fixed OpenSSL static build not able to use external modules like FIPS
   provider module.

### Consumer fixes

 * A reference count issue was blocking the consumer from closing.
   The problem would happen when a partition is lost, because forcibly
   unassigned from the consumer or if the corresponding topic is deleted.
 * When using `rd_kafka_seek_partitions`, the remaining timeout was
   converted from microseconds to milliseconds but the expected unit
   for that parameter is microseconds.
 * Fixed known issues related to Batch Consume APIs mentioned in v2.0.0
   release notes.
 * Fixed `rd_kafka_consume_batch()` and `rd_kafka_consume_batch_queue()`
   intermittently updating `app_offset` and `store_offset` incorrectly when
   **pause** or **resume** was being used for a partition.
 * Fixed `rd_kafka_consume_batch()` and `rd_kafka_consume_batch_queue()`
   intermittently skipping offsets when **pause** or **resume** was being
   used for a partition.


## Known Issues

### Consume Batch API

 * When `rd_kafka_consume_batch()` and `rd_kafka_consume_batch_queue()` APIs are used with
   any of the **seek**, **pause**, **resume** or **rebalancing** operation, `on_consume`
   interceptors might be called incorrectly (maybe multiple times) for not consumed messages.

### Consume API

 * Duplicate messages can be emitted when a fetch response is received
   in the middle of an offset validation request.
 * Segmentation fault when subscribing to a non-existent topic and
   calling `rd_kafka_message_leader_epoch()` on the polled `rkmessage`.



# librdkafka v2.0.2

librdkafka v2.0.2 is a maintenance release:

* Fix OpenSSL version in Win32 nuget package (#4152).



# librdkafka v2.0.1

librdkafka v2.0.1 is a maintenance release:

* Fixed nuget package for Linux ARM64 release (#4150).



# librdkafka v2.0.0

librdkafka v2.0.0 is a feature release:

 * [KIP-88](https://cwiki.apache.org/confluence/display/KAFKA/KIP-88%3A+OffsetFetch+Protocol+Update)
   OffsetFetch Protocol Update (#3995).
 * [KIP-222](https://cwiki.apache.org/confluence/display/KAFKA/KIP-222+-+Add+Consumer+Group+operations+to+Admin+API)
   Add Consumer Group operations to Admin API (started by @lesterfan, #3995).
 * [KIP-518](https://cwiki.apache.org/confluence/display/KAFKA/KIP-518%3A+Allow+listing+consumer+groups+per+state)
   Allow listing consumer groups per state (#3995).
 * [KIP-396](https://cwiki.apache.org/confluence/pages/viewpage.action?pageId=97551484)
   Partially implemented: support for AlterConsumerGroupOffsets
   (started by @lesterfan, #3995).
 * OpenSSL 3.0.x support - the maximum bundled OpenSSL version is now 3.0.7 (previously 1.1.1q).
 * Fixes to the transactional and idempotent producer.


## Upgrade considerations

### OpenSSL 3.0.x

#### OpenSSL default ciphers

The introduction of OpenSSL 3.0.x in the self-contained librdkafka bundles
changes the default set of available ciphers, in particular all obsolete
or insecure ciphers and algorithms as listed in the
OpenSSL [legacy](https://www.openssl.org/docs/man3.0/man7/OSSL_PROVIDER-legacy.html)
manual page are now disabled by default.

**WARNING**: These ciphers are disabled for security reasons and it is
highly recommended NOT to use them.

Should you need to use any of these old ciphers you'll need to explicitly
enable the `legacy` provider by configuring `ssl.providers=default,legacy`
on the librdkafka client.

#### OpenSSL engines and providers

OpenSSL 3.0.x deprecates the use of engines, which is being replaced by
providers. As such librdkafka will emit a deprecation warning if
`ssl.engine.location` is configured.

OpenSSL providers may be configured with the new `ssl.providers`
configuration property.

### Broker TLS certificate hostname verification

The default value for `ssl.endpoint.identification.algorithm` has been
changed from `none` (no hostname verification) to `https`, which enables
broker hostname verification (to counter man-in-the-middle
impersonation attacks) by default.

To restore the previous behaviour, set `ssl.endpoint.identification.algorithm` to `none`.

## Known Issues

### Poor Consumer batch API messaging guarantees

The Consumer Batch APIs `rd_kafka_consume_batch()` and `rd_kafka_consume_batch_queue()`
are not thread safe if `rkmessages_size` is greater than 1 and any of the **seek**,
**pause**, **resume** or **rebalancing** operation is performed in parallel with any of
the above APIs. Some of the messages might be lost, or erroneously returned to the
application, in the above scenario.

It is strongly recommended to use the Consumer Batch APIs and the mentioned
operations in sequential order in order to get consistent result.

For **rebalancing** operation to work in sequencial manner, please set `rebalance_cb`
configuration property (refer [examples/rdkafka_complex_consumer_example.c]
(examples/rdkafka_complex_consumer_example.c) for the help with the usage) for the consumer.

## Enhancements

 * Self-contained static libraries can now be built on Linux arm64 (#4005).
 * Updated to zlib 1.2.13, zstd 1.5.2, and curl 7.86.0 in self-contained
   librdkafka bundles.
 * Added `on_broker_state_change()` interceptor
 * The C++ API no longer returns strings by const value, which enables better move optimization in callers.
 * Added `rd_kafka_sasl_set_credentials()` API to update SASL credentials.
 * Setting `allow.auto.create.topics` will no longer give a warning if used by a producer, since that is an expected use case.
  Improvement in documentation for this property.
 * Added a `resolve_cb` configuration setting that permits using custom DNS resolution logic.
 * Added `rd_kafka_mock_broker_error_stack_cnt()`.
 * The librdkafka.redist NuGet package has been updated to have fewer external
   dependencies for its bundled librdkafka builds, as everything but cyrus-sasl
   is now built-in. There are bundled builds with and without linking to
   cyrus-sasl for maximum compatibility.
 * Admin API DescribeGroups() now provides the group instance id
   for static members [KIP-345](https://cwiki.apache.org/confluence/display/KAFKA/KIP-345%3A+Introduce+static+membership+protocol+to+reduce+consumer+rebalances) (#3995).


## Fixes

### General fixes

 * Windows: couldn't read a PKCS#12 keystore correctly because binary mode
   wasn't explicitly set and Windows defaults to text mode.
 * Fixed memory leak when loading SSL certificates (@Mekk, #3930)
 * Load all CA certificates from `ssl.ca.pem`, not just the first one.
 * Each HTTP request made when using OAUTHBEARER OIDC would leak a small
   amount of memory.

### Transactional producer fixes

 * When a PID epoch bump is requested and the producer is waiting
   to reconnect to the transaction coordinator, a failure in a find coordinator
   request could cause an assert to fail. This is fixed by retrying when the
   coordinator is known (#4020).
 * Transactional APIs (except `send_offsets_for_transaction()`) that
   timeout due to low timeout_ms may now be resumed by calling the same API
   again, as the operation continues in the background.
 * For fatal idempotent producer errors that may be recovered by bumping the
   epoch the current transaction must first be aborted prior to the epoch bump.
   This is now handled correctly, which fixes issues seen with fenced
   transactional producers on fatal idempotency errors.
 * Timeouts for EndTxn requests (transaction commits and aborts) are now
   automatically retried and the error raised to the application is also
   a retriable error.
 * TxnOffsetCommitRequests were retried immediately upon temporary errors in
   `send_offsets_to_transactions()`, causing excessive network requests.
   These retries are now delayed 500ms.
 * If `init_transactions()` is called with an infinite timeout (-1),
   the timeout will be limited to 2 * `transaction.timeout.ms`.
   The application may retry and resume the call if a retriable error is
   returned.


### Consumer fixes

 * Back-off and retry JoinGroup request if coordinator load is in progress.
 * Fix `rd_kafka_consume_batch()` and `rd_kafka_consume_batch_queue()` skipping
   other partitions' offsets intermittently when **seek**, **pause**, **resume**
   or **rebalancing** is used for a partition.
 * Fix `rd_kafka_consume_batch()` and `rd_kafka_consume_batch_queue()`
   intermittently returing incorrect partitions' messages if **rebalancing**
   happens during these operations.

# librdkafka v1.9.2

librdkafka v1.9.2 is a maintenance release:

 * The SASL OAUTHBEAR OIDC POST field was sometimes truncated by one byte (#3192).
 * The bundled version of OpenSSL has been upgraded to version 1.1.1q for non-Windows builds. Windows builds remain on OpenSSL 1.1.1n for the time being.
 * The bundled version of Curl has been upgraded to version 7.84.0.



# librdkafka v1.9.1

librdkafka v1.9.1 is a maintenance release:

 * The librdkafka.redist NuGet package now contains OSX M1/arm64 builds.
 * Self-contained static libraries can now be built on OSX M1 too, thanks to
   disabling curl's configure runtime check.



# librdkafka v1.9.0

librdkafka v1.9.0 is a feature release:

 * Added KIP-768 OUATHBEARER OIDC support (by @jliunyu, #3560)
 * Added KIP-140 Admin API ACL support (by @emasab, #2676)


## Upgrade considerations

 * Consumer:
   `rd_kafka_offsets_store()` (et.al) will now return an error for any
   partition that is not currently assigned (through `rd_kafka_*assign()`).
   This prevents a race condition where an application would store offsets
   after the assigned partitions had been revoked (which resets the stored
   offset), that could cause these old stored offsets to be committed later
   when the same partitions were assigned to this consumer again - effectively
   overwriting any committed offsets by any consumers that were assigned the
   same partitions previously. This would typically result in the offsets
   rewinding and messages to be reprocessed.
   As an extra effort to avoid this situation the stored offset is now
   also reset when partitions are assigned (through `rd_kafka_*assign()`).
   Applications that explicitly call `..offset*_store()` will now need
   to handle the case where `RD_KAFKA_RESP_ERR__STATE` is returned
   in the per-partition `.err` field - meaning the partition is no longer
   assigned to this consumer and the offset could not be stored for commit.


## Enhancements

 * Improved producer queue scheduling. Fixes the performance regression
   introduced in v1.7.0 for some produce patterns. (#3538, #2912)
 * Windows: Added native Win32 IO/Queue scheduling. This removes the
   internal TCP loopback connections that were previously used for timely
   queue wakeups.
 * Added `socket.connection.setup.timeout.ms` (default 30s).
   The maximum time allowed for broker connection setups (TCP connection as
   well as SSL and SASL handshakes) is now limited to this value.
   This fixes the issue with stalled broker connections in the case of network
   or load balancer problems.
   The Java clients has an exponential backoff to this timeout which is
   limited by `socket.connection.setup.timeout.max.ms` - this was not
   implemented in librdkafka due to differences in connection handling and
   `ERR__ALL_BROKERS_DOWN` error reporting. Having a lower initial connection
   setup timeout and then increase the timeout for the next attempt would
   yield possibly false-positive `ERR__ALL_BROKERS_DOWN` too early.
 * SASL OAUTHBEARER refresh callbacks can now be scheduled for execution
   on librdkafka's background thread. This solves the problem where an
   application has a custom SASL OAUTHBEARER refresh callback and thus needs to
   call `rd_kafka_poll()` (et.al.) at least once to trigger the
   refresh callback before being able to connect to brokers.
   With the new `rd_kafka_conf_enable_sasl_queue()` configuration API and
   `rd_kafka_sasl_background_callbacks_enable()` the refresh callbacks
   can now be triggered automatically on the librdkafka background thread.
 * `rd_kafka_queue_get_background()` now creates the background thread
   if not already created.
 * Added `rd_kafka_consumer_close_queue()` and `rd_kafka_consumer_closed()`.
   This allow applications and language bindings to implement asynchronous
   consumer close.
 * Bundled zlib upgraded to version 1.2.12.
 * Bundled OpenSSL upgraded to 1.1.1n.
 * Added `test.mock.broker.rtt` to simulate RTT/latency for mock brokers.


## Fixes

### General fixes

 * Fix various 1 second delays due to internal broker threads blocking on IO
   even though there are events to handle.
   These delays could be seen randomly in any of the non produce/consume
   request APIs, such as `commit_transaction()`, `list_groups()`, etc.
 * Windows: some applications would crash with an error message like
   `no OPENSSL_Applink()` written to the console if `ssl.keystore.location`
   was configured.
   This regression was introduced in v1.8.0 due to use of vcpkgs and how
   keystore file was read. #3554.
 * Windows 32-bit only: 64-bit atomic reads were in fact not atomic and could
   in rare circumstances yield incorrect values.
   One manifestation of this issue was the `max.poll.interval.ms` consumer
   timer expiring even though the application was polling according to profile.
   Fixed by @WhiteWind (#3815).
 * `rd_kafka_clusterid()` would previously fail with timeout if
   called on cluster with no visible topics (#3620).
   The clusterid is now returned as soon as metadata has been retrieved.
 * Fix hang in `rd_kafka_list_groups()` if there are no available brokers
   to connect to (#3705).
 * Millisecond timeouts (`timeout_ms`) in various APIs, such as `rd_kafka_poll()`,
   was limited to roughly 36 hours before wrapping. (#3034)
 * If a metadata request triggered by `rd_kafka_metadata()` or consumer group rebalancing
   encountered a non-retriable error it would not be propagated to the caller and thus
   cause a stall or timeout, this has now been fixed. (@aiquestion, #3625)
 * AdminAPI `DeleteGroups()` and `DeleteConsumerGroupOffsets()`:
   if the given coordinator connection was not up by the time these calls were
   initiated and the first connection attempt failed then no further connection
   attempts were performed, ulimately leading to the calls timing out.
   This is now fixed by keep retrying to connect to the group coordinator
   until the connection is successful or the call times out.
   Additionally, the coordinator will be now re-queried once per second until
   the coordinator comes up or the call times out, to detect change in
   coordinators.
 * Mock cluster `rd_kafka_mock_broker_set_down()` would previously
   accept and then disconnect new connections, it now refuses new connections.


### Consumer fixes

 * `rd_kafka_offsets_store()` (et.al) will now return an error for any
   partition that is not currently assigned (through `rd_kafka_*assign()`).
   See **Upgrade considerations** above for more information.
 * `rd_kafka_*assign()` will now reset/clear the stored offset.
   See **Upgrade considerations** above for more information.
 * `seek()` followed by `pause()` would overwrite the seeked offset when
   later calling `resume()`. This is now fixed. (#3471).
   **Note**: Avoid storing offsets (`offsets_store()`) after calling
   `seek()` as this may later interfere with resuming a paused partition,
   instead store offsets prior to calling seek.
 * A `ERR_MSG_SIZE_TOO_LARGE` consumer error would previously be raised
   if the consumer received a maximum sized FetchResponse only containing
   (transaction) aborted messages with no control messages. The fetching did
   not stop, but some applications would terminate upon receiving this error.
   No error is now raised in this case. (#2993)
   Thanks to @jacobmikesell for providing an application to reproduce the
   issue.
 * The consumer no longer backs off the next fetch request (default 500ms) when
   the parsed fetch response is truncated (which is a valid case).
   This should speed up the message fetch rate in case of maximum sized
   fetch responses.
 * Fix consumer crash (`assert: rkbuf->rkbuf_rkb`) when parsing
   malformed JoinGroupResponse consumer group metadata state.
 * Fix crash (`cant handle op type`) when using `consume_batch_queue()` (et.al)
   and an OAUTHBEARER refresh callback was set.
   The callback is now triggered by the consume call. (#3263)
 * Fix `partition.assignment.strategy` ordering when multiple strategies are configured.
   If there is more than one eligible strategy, preference is determined by the
   configured order of strategies. The partitions are assigned to group members according
   to the strategy order preference now. (#3818)
 * Any form of unassign*() (absolute or incremental) is now allowed during
   consumer close rebalancing and they're all treated as absolute unassigns.
   (@kevinconaway)


### Transactional producer fixes

 * Fix message loss in idempotent/transactional producer.
   A corner case has been identified that may cause idempotent/transactional
   messages to be lost despite being reported as successfully delivered:
   During cluster instability a restarting broker may report existing topics
   as non-existent for some time before it is able to acquire up to date
   cluster and topic metadata.
   If an idempotent/transactional producer updates its topic metadata cache
   from such a broker the producer will consider the topic to be removed from
   the cluster and thus remove its local partition objects for the given topic.
   This also removes the internal message sequence number counter for the given
   partitions.
   If the producer later receives proper topic metadata for the cluster the
   previously "removed" topics will be rediscovered and new partition objects
   will be created in the producer. These new partition objects, with no
   knowledge of previous incarnations, would start counting partition messages
   at zero again.
   If new messages were produced for these partitions by the same producer
   instance, the same message sequence numbers would be sent to the broker.
   If the broker still maintains state for the producer's PID and Epoch it could
   deem that these messages with reused sequence numbers had already been
   written to the log and treat them as legit duplicates.
   This would seem to the producer that these new messages were successfully
   written to the partition log by the broker when they were in fact discarded
   as duplicates, leading to silent message loss.
   The fix included in this release is to save the per-partition idempotency
   state when a partition is removed, and then recover and use that saved
   state if the partition comes back at a later time.
 * The transactional producer would retry (re)initializing its PID if a
   `PRODUCER_FENCED` error was returned from the
   broker (added in Apache Kafka 2.8), which could cause the producer to
   seemingly hang.
   This error code is now correctly handled by raising a fatal error.
 * If the given group coordinator connection was not up by the time
   `send_offsets_to_transactions()` was called, and the first connection
   attempt failed then no further connection attempts were performed, ulimately
   leading to `send_offsets_to_transactions()` timing out, and possibly
   also the transaction timing out on the transaction coordinator.
   This is now fixed by keep retrying to connect to the group coordinator
   until the connection is successful or the call times out.
   Additionally, the coordinator will be now re-queried once per second until
   the coordinator comes up or the call times out, to detect change in
   coordinators.


### Producer fixes

 * Improved producer queue wakeup scheduling. This should significantly
   decrease the number of wakeups and thus syscalls for high message rate
   producers. (#3538, #2912)
 * The logic for enforcing that `message.timeout.ms` is greather than
   an explicitly configured `linger.ms` was incorrect and instead of
   erroring out early the lingering time was automatically adjusted to the
   message timeout, ignoring the configured `linger.ms`.
   This has now been fixed so that an error is returned when instantiating the
   producer. Thanks to @larry-cdn77 for analysis and test-cases. (#3709)


# librdkafka v1.8.2

librdkafka v1.8.2 is a maintenance release.

## Enhancements

 * Added `ssl.ca.pem` to add CA certificate by PEM string. (#2380)
 * Prebuilt binaries for Mac OSX now contain statically linked OpenSSL v1.1.1l.
   Previously the OpenSSL version was either v1.1.1 or v1.0.2 depending on
   build type.

## Fixes

 * The `librdkafka.redist` 1.8.0 package had two flaws:
   - the linux-arm64 .so build was a linux-x64 build.
   - the included Windows MSVC 140 runtimes for x64 were infact x86.
   The release script has been updated to verify the architectures of
   provided artifacts to avoid this happening in the future.
 * Prebuilt binaries for Mac OSX Sierra (10.12) and older are no longer provided.
   This affects [confluent-kafka-go](https://github.com/confluentinc/confluent-kafka-go).
 * Some of the prebuilt binaries for Linux were built on Ubuntu 14.04,
   these builds are now performed on Ubuntu 16.04 instead.
   This may affect users on ancient Linux distributions.
 * It was not possible to configure `ssl.ca.location` on OSX, the property
   would automatically revert back to `probe` (default value).
   This regression was introduced in v1.8.0. (#3566)
 * librdkafka's internal timers would not start if the timeout was set to 0,
   which would result in some timeout operations not being enforced correctly,
   e.g., the transactional producer API timeouts.
   These timers are now started with a timeout of 1 microsecond.

### Transactional producer fixes

 * Upon quick repeated leader changes the transactional producer could receive
   an `OUT_OF_ORDER_SEQUENCE` error from the broker, which triggered an
   Epoch bump on the producer resulting in an InitProducerIdRequest being sent
   to the transaction coordinator in the middle of a transaction.
   This request would start a new transaction on the coordinator, but the
   producer would still think (erroneously) it was in current transaction.
   Any messages produced in the current transaction prior to this event would
   be silently lost when the application committed the transaction, leading
   to message loss.
   This has been fixed by setting the Abortable transaction error state
   in the producer. #3575.
 * The transactional producer could stall during a transaction if the transaction
   coordinator changed while adding offsets to the transaction (send_offsets_to_transaction()).
   This stall lasted until the coordinator connection went down, the
   transaction timed out, transaction was aborted, or messages were produced
   to a new partition, whichever came first. #3571.



*Note: there was no v1.8.1 librdkafka release*


# librdkafka v1.8.0

librdkafka v1.8.0 is a security release:

 * Upgrade bundled zlib version from 1.2.8 to 1.2.11 in the `librdkafka.redist`
   NuGet package. The updated zlib version fixes CVEs:
   CVE-2016-9840, CVE-2016-9841, CVE-2016-9842, CVE-2016-9843
   See https://github.com/confluentinc/librdkafka/issues/2934 for more information.
 * librdkafka now uses [vcpkg](https://vcpkg.io/) for up-to-date Windows
   dependencies in the `librdkafka.redist` NuGet package:
   OpenSSL 1.1.1l, zlib 1.2.11, zstd 1.5.0.
 * The upstream dependency (OpenSSL, zstd, zlib) source archive checksums are
   now verified when building with `./configure --install-deps`.
   These builds are used by the librdkafka builds bundled with
   confluent-kafka-go, confluent-kafka-python and confluent-kafka-dotnet.


## Enhancements

 * Producer `flush()` now overrides the `linger.ms` setting for the duration
   of the `flush()` call, effectively triggering immediate transmission of
   queued messages. (#3489)

## Fixes

### General fixes

 * Correctly detect presence of zlib via compilation check. (Chris Novakovic)
 * `ERR__ALL_BROKERS_DOWN` is no longer emitted when the coordinator
   connection goes down, only when all standard named brokers have been tried.
   This fixes the issue with `ERR__ALL_BROKERS_DOWN` being triggered on
   `consumer_close()`. It is also now only emitted if the connection was fully
   up (past handshake), and not just connected.
 * `rd_kafka_query_watermark_offsets()`, `rd_kafka_offsets_for_times()`,
   `consumer_lag` metric, and `auto.offset.reset` now honour
   `isolation.level` and will return the Last Stable Offset (LSO)
   when `isolation.level` is set to `read_committed` (default), rather than
   the uncommitted high-watermark when it is set to `read_uncommitted`. (#3423)
 * SASL GSSAPI is now usable when `sasl.kerberos.min.time.before.relogin`
   is set to 0 - which disables ticket refreshes (by @mpekalski, #3431).
 * Rename internal crc32c() symbol to rd_crc32c() to avoid conflict with
   other static libraries (#3421).
 * `txidle` and `rxidle` in the statistics object was emitted as 18446744073709551615 when no idle was known. -1 is now emitted instead. (#3519)


### Consumer fixes

 * Automatically retry offset commits on `ERR_REQUEST_TIMED_OUT`,
   `ERR_COORDINATOR_NOT_AVAILABLE`, and `ERR_NOT_COORDINATOR` (#3398).
   Offset commits will be retried twice.
 * Timed auto commits did not work when only using assign() and not subscribe().
   This regression was introduced in v1.7.0.
 * If the topics matching the current subscription changed (or the application
   updated the subscription) while there was an outstanding JoinGroup or
   SyncGroup request, an additional request would sometimes be sent before
   handling the response of the first. This in turn lead to internal state
   issues that could cause a crash or malbehaviour.
   The consumer will now wait for any outstanding JoinGroup or SyncGroup
   responses before re-joining the group.
 * `auto.offset.reset` could previously be triggered by temporary errors,
   such as disconnects and timeouts (after the two retries are exhausted).
   This is now fixed so that the auto offset reset policy is only triggered
   for permanent errors.
 * The error that triggers `auto.offset.reset` is now logged to help the
   application owner identify the reason of the reset.
 * If a rebalance takes longer than a consumer's `session.timeout.ms`, the
   consumer will remain in the group as long as it receives heartbeat responses
   from the broker.


### Admin fixes

 * `DeleteRecords()` could crash if one of the underlying requests
   (for a given partition leader) failed at the transport level (e.g., timeout).
   (#3476).



# librdkafka v1.7.0

librdkafka v1.7.0 is feature release:

 * [KIP-360](https://cwiki.apache.org/confluence/pages/viewpage.action?pageId=89068820) - Improve reliability of transactional producer.
   Requires Apache Kafka 2.5 or later.
 * OpenSSL Engine support (`ssl.engine.location`) by @adinigam and @ajbarb.


## Enhancements

 * Added `connections.max.idle.ms` to automatically close idle broker
   connections.
   This feature is disabled by default unless `bootstrap.servers` contains
   the string `azure` in which case the default is set to <4 minutes to improve
   connection reliability and circumvent limitations with the Azure load
   balancers (see #3109 for more information).
 * Bumped to OpenSSL 1.1.1k in binary librdkafka artifacts.
 * The binary librdkafka artifacts for Alpine are now using Alpine 3.12.
   OpenSSL 1.1.1k.
 * Improved static librdkafka Windows builds using MinGW (@neptoess, #3130).
 * The `librdkafka.redist` NuGet package now has updated zlib, zstd and
   OpenSSL versions (from vcpkg).


## Security considerations

 * The zlib version bundled with the `librdkafka.redist` NuGet package has now been upgraded
   from zlib 1.2.8 to 1.2.11, fixing the following CVEs:
   * CVE-2016-9840: undefined behaviour (compiler dependent) in inflate (decompression) code: this is used by the librdkafka consumer. Risk of successfully exploitation through consumed messages is eastimated very low.
   * CVE-2016-9841: undefined behaviour (compiler dependent) in inflate code: this is used by the librdkafka consumer. Risk of successfully exploitation through consumed messages is eastimated very low.
   * CVE-2016-9842: undefined behaviour in inflateMark(): this API is not used by librdkafka.
   * CVE-2016-9843: issue in crc32_big() which is called from crc32_z(): this API is not used by librdkafka.

## Upgrade considerations

 * The C++ `oauthbearer_token_refresh_cb()` was missing a `Handle *`
   argument that has now been added. This is a breaking change but the original
   function signature is considered a bug.
   This change only affects C++ OAuth developers.
 * [KIP-735](https://cwiki.apache.org/confluence/display/KAFKA/KIP-735%3A+Increase+default+consumer+session+timeout) The consumer `session.timeout.ms`
   default was changed from 10 to 45 seconds to make consumer groups more
   robust and less sensitive to temporary network and cluster issues.
 * Statistics: `consumer_lag` is now using the `committed_offset`,
   while the new `consumer_lag_stored` is using `stored_offset`
   (offset to be committed).
   This is more correct than the previous `consumer_lag` which was using
   either `committed_offset` or `app_offset` (last message passed
   to application).
 * The `librdkafka.redist` NuGet package is now built with MSVC runtime v140
   (VS 2015). Previous versions were built with MSVC runtime v120 (VS 2013).


## Fixes

### General fixes

 * Fix accesses to freed metadata cache mutexes on client termination (#3279)
 * There was a race condition on receiving updated metadata where a broker id
   update (such as bootstrap to proper broker transformation) could finish after
   the topic metadata cache was updated, leading to existing brokers seemingly
   being not available.
   One occurrence of this issue was query_watermark_offsets() that could return
   `ERR__UNKNOWN_PARTITION` for existing partitions shortly after the
   client instance was created.
 * The OpenSSL context is now initialized with `TLS_client_method()`
   (on OpenSSL >= 1.1.0) instead of the deprecated and outdated
   `SSLv23_client_method()`.
 * The initial cluster connection on client instance creation could sometimes
   be delayed up to 1 second if a `group.id` or `transactional.id`
   was configured (#3305).
 * Speed up triggering of new broker connections in certain cases by exiting
   the broker thread io/op poll loop when a wakeup op is received.
 * SASL GSSAPI: The Kerberos kinit refresh command was triggered from
   `rd_kafka_new()` which made this call blocking if the refresh command
   was taking long. The refresh is now performed by the background rdkafka
   main thread.
 * Fix busy-loop (100% CPU on the broker threads) during the handshake phase
   of an SSL connection.
 * Disconnects during SSL handshake are now propagated as transport errors
   rather than SSL errors, since these disconnects are at the transport level
   (e.g., incorrect listener, flaky load balancer, etc) and not due to SSL
   issues.
 * Increment metadata fast refresh interval backoff exponentially (@ajbarb, #3237).
 * Unthrottled requests are no longer counted in the `brokers[].throttle`
   statistics object.
 * Log CONFWARN warning when global topic configuration properties
   are overwritten by explicitly setting a `default_topic_conf`.

### Consumer fixes

 * If a rebalance happened during a `consume_batch..()` call the already
   accumulated messages for revoked partitions were not purged, which would
   pass messages to the application for partitions that were no longer owned
   by the consumer. Fixed by @jliunyu. #3340.
 * Fix balancing and reassignment issues with the cooperative-sticky assignor.
   #3306.
 * Fix incorrect detection of first rebalance in sticky assignor (@hallfox).
 * Aborted transactions with no messages produced to a partition could
   cause further successfully committed messages in the same Fetch response to
   be ignored, resulting in consumer-side message loss.
   A log message along the lines `Abort txn ctrl msg bad order at offset
   7501: expected before or at 7702: messages in aborted transactions may be delivered to the application`
   would be seen.
   This is a rare occurrence where a transactional producer would register with
   the partition but not produce any messages before aborting the transaction.
 * The consumer group deemed cached metadata up to date by checking
   `topic.metadata.refresh.interval.ms`: if this property was set too low
   it would cause cached metadata to be unusable and new metadata to be fetched,
   which could delay the time it took for a rebalance to settle.
   It now correctly uses `metadata.max.age.ms` instead.
 * The consumer group timed auto commit would attempt commits during rebalances,
   which could result in "Illegal generation" errors. This is now fixed, the
   timed auto committer is only employed in the steady state when no rebalances
   are taking places. Offsets are still auto committed when partitions are
   revoked.
 * Retriable FindCoordinatorRequest errors are no longer propagated to
   the application as they are retried automatically.
 * Fix rare crash (assert `rktp_started`) on consumer termination
   (introduced in v1.6.0).
 * Fix unaligned access and possibly corrupted snappy decompression when
   building with MSVC (@azat)
 * A consumer configured with the `cooperative-sticky` assignor did
   not actively Leave the group on unsubscribe(). This delayed the
   rebalance for the remaining group members by up to `session.timeout.ms`.
 * The current subscription list was sometimes leaked when unsubscribing.

### Producer fixes

 * The timeout value of `flush()` was not respected when delivery reports
   were scheduled as events (such as for confluent-kafka-go) rather than
   callbacks.
 * There was a race conditition in `purge()` which could cause newly
   created partition objects, or partitions that were changing leaders, to
   not have their message queues purged. This could cause
   `abort_transaction()` to time out. This issue is now fixed.
 * In certain high-thruput produce rate patterns producing could stall for
   1 second, regardless of `linger.ms`, due to rate-limiting of internal
   queue wakeups. This is now fixed by not rate-limiting queue wakeups but
   instead limiting them to one wakeup per queue reader poll. #2912.

### Transactional Producer fixes

 * KIP-360: Fatal Idempotent producer errors are now recoverable by the
   transactional producer and will raise a `txn_requires_abort()` error.
 * If the cluster went down between `produce()` and `commit_transaction()`
   and before any partitions had been registered with the coordinator, the
   messages would time out but the commit would succeed because nothing
   had been sent to the coordinator. This is now fixed.
 * If the current transaction failed while `commit_transaction()` was
   checking the current transaction state an invalid state transaction could
   occur which in turn would trigger a assertion crash.
   This issue showed up as "Invalid txn state transition: .." crashes, and is
   now fixed by properly synchronizing both checking and transition of state.



# librdkafka v1.6.1

librdkafka v1.6.1 is a maintenance release.

## Upgrade considerations

 * Fatal idempotent producer errors are now also fatal to the transactional
   producer. This is a necessary step to maintain data integrity prior to
   librdkafka supporting KIP-360. Applications should check any transactional
   API errors for the is_fatal flag and decommission the transactional producer
   if the flag is set.
 * The consumer error raised by `auto.offset.reset=error` now has error-code
   set to `ERR__AUTO_OFFSET_RESET` to allow an application to differentiate
   between auto offset resets and other consumer errors.


## Fixes

### General fixes

 * Admin API and transactional `send_offsets_to_transaction()` coordinator
   requests, such as TxnOffsetCommitRequest, could in rare cases be sent
   multiple times which could cause a crash.
 * `ssl.ca.location=probe` is now enabled by default on Mac OSX since the
   librdkafka-bundled OpenSSL might not have the same default CA search paths
   as the system or brew installed OpenSSL. Probing scans all known locations.

### Transactional Producer fixes

 * Fatal idempotent producer errors are now also fatal to the transactional
   producer.
 * The transactional producer could crash if the transaction failed while
   `send_offsets_to_transaction()` was called.
 * Group coordinator requests for transactional
   `send_offsets_to_transaction()` calls would leak memory if the
   underlying request was attempted to be sent after the transaction had
   failed.
 * When gradually producing to multiple partitions (resulting in multiple
   underlying AddPartitionsToTxnRequests) subsequent partitions could get
   stuck in pending state under certain conditions. These pending partitions
   would not send queued messages to the broker and eventually trigger
   message timeouts, failing the current transaction. This is now fixed.
 * Committing an empty transaction (no messages were produced and no
   offsets were sent) would previously raise a fatal error due to invalid state
   on the transaction coordinator. We now allow empty/no-op transactions to
   be committed.

### Consumer fixes

 * The consumer will now retry indefinitely (or until the assignment is changed)
   to retrieve committed offsets. This fixes the issue where only two retries
   were attempted when outstanding transactions were blocking OffsetFetch
   requests with `ERR_UNSTABLE_OFFSET_COMMIT`. #3265





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

See https://github.com/confluentinc/librdkafka/releases
