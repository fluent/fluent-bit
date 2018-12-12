//@file INTRODUCTION.md
# Introduction to librdkafka - the Apache Kafka C/C++ client library


librdkafka is a high performance C implementation of the Apache
Kafka client, providing a reliable and performant client for production use.
librdkafka also provides a native C++ interface.

## Contents

The following chapters are available in this document

  * [Performance](#performance)
    * [Performance numbers](#performance-numbers)
    * [High throughput](#high-throughput)
    * [Low latency](#low-latency)
    * [Compression](#compression)
  * [Message reliability](#message-reliability)
  * [Usage](#usage)
    * [Documentation](#documentation)
    * [Initialization](#initialization)
    * [Configuration](#configuration)
    * [Threads and callbacks](#threads-and-callbacks)
    * [Brokers](#brokers)
    * [Producer API](#producer-api)
    * [Consumer API](#simple-consumer-api-legacy)
  * [Appendix](#appendix)
    * [Test details](#test-details)
  



## Performance

librdkafka is a multi-threaded library designed for use on modern hardware and
it attempts to keep memory copying at a minimal. The payload of produced or
consumed messages may pass through without any copying
(if so desired by the application) putting no limit on message sizes.

librdkafka allows you to decide if high throughput is the name of the game,
or if a low latency service is required, all through the configuration
property interface.

The two most important configuration properties for performance tuning are:

  * `batch.num.messages` - the maximum number of messages to wait for to
	  accumulate in the local queue before sending off a message set.
  * `queue.buffering.max.ms` - how long to wait for batch.num.messages to
	  fill up in the local queue. A lower value improves latency at the
          cost of lower throughput and higher per-message overhead.
          A higher value improves throughput at the expense of latency.
          The recommended value for high throughput is > 50ms.


### Performance numbers

The following performance numbers stem from tests using the following setup:

  * Intel Quad Core i7 at 3.4GHz, 8GB of memory
  * Disk performance has been shortcut by setting the brokers' flush
	configuration properties as so:
	* `log.flush.interval.messages=10000000`
	* `log.flush.interval.ms=100000`
  * Two brokers running on the same machine as librdkafka.
  * One topic with two partitions.
  * Each broker is leader for one partition each.
  * Using `rdkafka_performance` program available in the `examples` subdir.



	

**Test results**

  * **Test1**: 2 brokers, 2 partitions, required.acks=2, 100 byte messages: 
	  **850000 messages/second**, **85 MB/second**

  * **Test2**: 1 broker, 1 partition, required.acks=0, 100 byte messages: 
	  **710000 messages/second**, **71 MB/second**
	  
  * **Test3**: 2 broker2, 2 partitions, required.acks=2, 100 byte messages,
	  snappy compression:
	  **300000 messages/second**, **30 MB/second**

  * **Test4**: 2 broker2, 2 partitions, required.acks=2, 100 byte messages,
	  gzip compression:
	  **230000 messages/second**, **23 MB/second**



**Note**: See the *Test details* chapter at the end of this document for
	information about the commands executed, etc.

**Note**: Consumer performance tests will be announced soon.


### High throughput

The key to high throughput is message batching - waiting for a certain amount
of messages to accumulate in the local queue before sending them off in
one large message set or batch to the peer. This amortizes the messaging
overhead and eliminates the adverse effect of the round trip time (rtt).

`queue.buffering.max.ms` (also called `linger.ms`) allows librdkafka to
wait up to the specified amount of time to accumulate up to
`batch.num.messages` in a single batch (MessageSet) before sending
to the broker. The larger the batch the higher the throughput.
Enabling `msg` debugging (set `debug` property to `msg`) will emit log
messages for the accumulation process which lets you see what batch sizes
are being produced.

Example using `queue.buffering.max.ms=1`:

```
... test [0]: MessageSet with 1514 message(s) delivered
... test [3]: MessageSet with 1690 message(s) delivered
... test [0]: MessageSet with 1720 message(s) delivered
... test [3]: MessageSet with 2 message(s) delivered
... test [3]: MessageSet with 4 message(s) delivered
... test [0]: MessageSet with 4 message(s) delivered
... test [3]: MessageSet with 11 message(s) delivered
```

Example using `queue.buffering.max.ms=1000`:
```
... test [0]: MessageSet with 10000 message(s) delivered
... test [0]: MessageSet with 10000 message(s) delivered
... test [0]: MessageSet with 4667 message(s) delivered
... test [3]: MessageSet with 10000 message(s) delivered
... test [3]: MessageSet with 10000 message(s) delivered
... test [3]: MessageSet with 4476 message(s) delivered

```


The default setting of `queue.buffering.max.ms=1` is not suitable for
high throughput, it is recommended to set this value to >50ms, with
throughput leveling out somewhere around 100-1000ms depending on
message produce pattern and sizes.

These setting are set globally (`rd_kafka_conf_t`) but applies on a
per topic+partition basis.


### Low latency

When low latency messaging is required the `queue.buffering.max.ms` should be
tuned to the maximum permitted producer-side latency.
Setting queue.buffering.max.ms to 1 will make sure messages are sent as
soon as possible. You could check out [How to decrease message latency](https://github.com/edenhill/librdkafka/wiki/How-to-decrease-message-latency)
to find more details.
Lower buffering time leads to smaller batches and larger per-message overheads,
increasing network, memory and CPU usage for producers, brokers and consumers.

#### Latency measurement

End-to-end latency is preferably measured by synchronizing clocks on producers
and consumers and using the message timestamp on the consumer to calculate
the full latency. Make sure the topic's `log.message.timestamp.type` is set to
the default `CreateTime` (Kafka topic configuration, not librdkafka topic).

Latencies are typically incurred by the producer, network and broker, the
consumer effect on end-to-end latency is minimal.

To break down the end-to-end latencies and find where latencies are adding up
there are a number of metrics available through librdkafka statistics
on the producer:

 * `brokers[].int_latency` is the time, per message, between produce()
   and the message being written to a MessageSet and ProduceRequest.
   High `int_latency` indicates CPU core contention: check CPU load and,
   involuntary context switches (`/proc/<..>/status`).
   Consider using a machine/instance with more CPU cores.
   This metric is only relevant on the producer.

 * `brokers[].outbuf_latency` is the time, per protocol request
   (such as ProduceRequest), between the request being enqueued (which happens
   right after int_latency) and the time the request is written to the
   TCP socket connected to the broker.
   High `outbuf_latency` indicates CPU core contention or network congestion:
   check CPU load and socket SendQ (`netstat -anp | grep :9092`).

 * `brokers[].rtt` is the time, per protocol request, between the request being
   written to the TCP socket and the time the response is received from
   the broker.
   High `rtt` indicates broker load or network congestion:
   check broker metrics, local socket SendQ, network performance, etc.

 * `brokers[].throttle` is the time, per throttled protocol request, the
   broker throttled/delayed handling of a request due to usage quotas.
   The throttle time will also be reflected in `rtt`.

 * `topics[].batchsize` is the size of individual Producer MessageSet batches.
   See below.

 * `topics[].batchcnt` is the number of messages in individual Producer
   MessageSet batches. Due to Kafka protocol overhead a batch with few messages
   will have a higher relative processing and size overhead than a batch
   with many messages.
   Use the `linger.ms` client configuration property to set the maximum
   amount of time allowed for accumulating a single batch, the larger the
   value the larger the batches will grow, thus increasing efficiency.
   When producing messages at a high rate it is recommended to increase
   linger.ms, which will improve throughput and in some cases also latency.


See [STATISTICS.md](STATISTICS.md) for the full definition of metrics.
A JSON schema for the statistics is available in
[statistics-schema.json](src/statistics-schema.json).


### Compression

Producer message compression is enabled through the `compression.codec`
configuration property.

Compression is performed on the batch of messages in the local queue, the
larger the batch the higher likelyhood of a higher compression ratio.
The local batch queue size is controlled through the `batch.num.messages` and
`queue.buffering.max.ms` configuration properties as described in the
**High throughput** chapter above.



## Message reliability

Message reliability is an important factor of librdkafka - an application
can rely fully on librdkafka to deliver a message according to the specified
configuration (`request.required.acks` and `message.send.max.retries`, etc).

If the topic configuration property `request.required.acks` is set to wait
for message commit acknowledgements from brokers (any value but 0, see
[`CONFIGURATION.md`](https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md)
for specifics) then librdkafka will hold on to the message until
all expected acks have been received, gracefully handling the following events:

  * Broker connection failure
  * Topic leader change
  * Produce errors signaled by the broker
  * Network problems

This is handled automatically by librdkafka and the application does not need
to take any action at any of the above events.
The message will be resent up to `message.send.max.retries` times before
reporting a failure back to the application.

The delivery report callback is used by librdkafka to signal the status of
a message back to the application, it will be called once for each message
to report the status of message delivery:

  * If `error_code` is non-zero the message delivery failed and the error_code
    indicates the nature of the failure (`rd_kafka_resp_err_t` enum).
  * If `error_code` is zero the message has been successfully delivered.

See Producer API chapter for more details on delivery report callback usage.

The delivery report callback is optional but highly recommended.


### Producer message delivery success

When a ProduceRequest is successfully handled by the broker and a
ProduceResponse is received (also called the ack) without an error code
the messages from the ProduceRequest are enqueued on the delivery report
queue (if a delivery report callback has been set) and will be passed to
the application on the next invocation rd_kafka_poll().


### Producer message delivery failure

The following sub-chapters explains how different produce errors
are handled.

If the error is retryable and there are remaining retry attempts for
the given message(s), an automatic retry will be scheduled by librdkafka,
these retries are not visible to the application.

Only permanent errors and temporary errors that have reached their maximum
retry count will generate a delivery report event to the application with an
error code set.

The application should typically not attempt to retry producing the message
on failure, but instead configure librdkafka to perform these retries
using the `retries` and `retry.backoff.ms` configuration properties.


#### Error: Timed out in transmission queue

Internal error ERR__TIMED_OUT_QUEUE.

The connectivity to the broker may be stalled due to networking contention,
local or remote system issues, etc, and the request has not yet been sent.

The producer can be certain that the message has not been sent to the broker.

This is a retryable error, but is not counted as a retry attempt
since the message was never actually transmitted.

A retry by librdkafka at this point will not cause duplicate messages.


#### Error: Timed out in flight to/from broker

Internal error ERR__TIMED_OUT, ERR__TRANSPORT.

Same reasons as for `Timed out in transmission queue` above, with the
difference that the message may have been sent to the broker and might
be stalling waiting for broker replicas to ack the message, or the response
could be stalled due to networking issues.
At this point the producer can't know if the message reached the broker,
nor if the broker wrote the message to disk and replicas.

This is a retryable error.

A retry by librdkafka at this point may cause duplicate messages.


#### Error: Temporary broker-side error

Broker errors ERR_REQUEST_TIMED_OUT, ERR_NOT_ENOUGH_REPLICAS,
ERR_NOT_ENOUGH_REPLICAS_AFTER_APPEND.

These errors are considered temporary and librdkafka is will retry them
if permitted by configuration.


#### Error: Temporary errors due to stale metadata

Broker errors ERR_LEADER_NOT_AVAILABLE, ERR_NOT_LEADER_FOR_PARTITION.

These errors are considered temporary and a retry is warranted, a metadata
request is automatically sent to find a new leader for the partition.

A retry by librdkafka at this point will not cause duplicate messages.


#### Error: Local time out

Internal error ERR__MSG_TIMED_OUT.

The message could not be successfully transmitted before `message.timeout.ms`
expired, typically due to no leader being available or no broker connection.
The message may have been retried due to other errors but
those error messages are abstracted by the ERR__MSG_TIMED_OUT error code.

Since the `message.timeout.ms` has passed there will be no more retries
by librdkafka.


#### Error: Permanent errors

Any other error is considered a permanent error and the message
will fail immediately, generating a delivery report event with the
distinctive error code.

The full list of permanent errors depend on the broker version and
will likely grow in the future.

Typical permanent broker errors are:
 * ERR_CORRUPT_MESSAGE
 * ERR_MSG_SIZE_TOO_LARGE  - adjust client's or broker's `message.max.bytes`.
 * ERR_UNKNOWN_TOPIC_OR_PART - topic or partition does not exist,
                               automatic topic creation is disabled on the
                               broker or the application is specifying a
                               partition that does not exist.
 * ERR_RECORD_LIST_TOO_LARGE
 * ERR_INVALID_REQUIRED_ACKS
 * ERR_TOPIC_AUTHORIZATION_FAILED
 * ERR_UNSUPPORTED_FOR_MESSAGE_FORMAT
 * ERR_CLUSTER_AUTHORIZATION_FAILED


### Producer retries

The ProduceRequest itself is not retried, instead the messages
are put back on the internal partition queue by an insert sort
that maintains their original position (the message order is defined
at the time a message is initially appended to a partition queue, i.e., after
partitioning).
A backoff time (`retry.backoff.ms`) is set on the retried messages which
effectively blocks retry attempts until the backoff time has expired.


### Reordering

As for all retries, if `max.in.flight` > 1 and `retries` > 0, retried messages
may be produced out of order, since a sub-sequent message in a sub-sequent
ProduceRequest may already be in-flight (and accepted by the broker)
by the time the retry for the failing message is sent.




## Usage

### Documentation

The librdkafka API is documented in the
[`rdkafka.h`](https://github.com/edenhill/librdkafka/blob/master/src/rdkafka.h)
header file, the configuration properties are documented in
[`CONFIGURATION.md`](https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md)

### Initialization

The application needs to instantiate a top-level object `rd_kafka_t` which is
the base container, providing global configuration and shared state.
It is created by calling `rd_kafka_new()`.

It also needs to instantiate one or more topics (`rd_kafka_topic_t`) to be used
for producing to or consuming from. The topic object holds topic-specific
configuration and will be internally populated with a mapping of all available
partitions and their leader brokers.
It is created by calling `rd_kafka_topic_new()`.

Both `rd_kafka_t` and `rd_kafka_topic_t` comes with a configuration API which
is optional.
Not using the API will cause librdkafka to use its default values which are
documented in [`CONFIGURATION.md`](https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md).

**Note**: An application may create multiple `rd_kafka_t` objects and
	they share no state.

**Note**: An `rd_kafka_topic_t` object may only be used with the `rd_kafka_t`
	object it was created from.



### Configuration

To ease integration with the official Apache Kafka software and lower
the learning curve, librdkafka implements identical configuration
properties as found in the official clients of Apache Kafka.

Configuration is applied prior to object creation using the
`rd_kafka_conf_set()` and `rd_kafka_topic_conf_set()` APIs.

**Note**: The `rd_kafka.._conf_t` objects are not reusable after they have been
	passed to `rd_kafka.._new()`.
	The application does not need to free any config resources after a
	`rd_kafka.._new()` call.

#### Example

    rd_kafka_conf_t *conf;
    char errstr[512];
    
    conf = rd_kafka_conf_new();
    rd_kafka_conf_set(conf, "compression.codec", "snappy", errstr, sizeof(errstr));
    rd_kafka_conf_set(conf, "batch.num.messages", "100", errstr, sizeof(errstr));
    
    rd_kafka_new(RD_KAFKA_PRODUCER, conf);


### Threads and callbacks

librdkafka uses multiple threads internally to fully utilize modern hardware.
The API is completely thread-safe and the calling application may call any
of the API functions from any of its own threads at any time.

A poll-based API is used to provide signaling back to the application,
the application should call rd_kafka_poll() at regular intervals.
The poll API will call the following configured callbacks (optional):

  * message delivery report callback - signals that a message has been
    delivered or failed delivery, allowing the application to take action
    and to release any application resources used in the message.
  * error callback - signals an error. These errors are usually of an
    informational nature, i.e., failure to connect to a broker, and the
    application usually does not need to take any action.
    The type of error is passed as a rd_kafka_resp_err_t enum value,
    including both remote broker errors as well as local failures.


Optional callbacks not triggered by poll, these may be called from any thread:

  * Logging callback - allows the application to output log messages
	  generated by librdkafka.
  * partitioner callback - application provided message partitioner.
	  The partitioner may be called in any thread at any time, it may be
	  called multiple times for the same key.
	  Partitioner function contraints:
	  * MUST NOT call any rd_kafka_*() functions
      * MUST NOT block or execute for prolonged periods of time.
      * MUST return a value between 0 and partition_cnt-1, or the
          special RD_KAFKA_PARTITION_UA value if partitioning
              could not be performed.



### Brokers

librdkafka only needs an initial list of brokers (at least one), called the
bootstrap brokers.
It will connect to all the bootstrap brokers, specified by the
`metadata.broker.list` configuration property or by `rd_kafka_brokers_add()`,
and query each one for Metadata information which contains the full list of
brokers, topic, partitions and their leaders in the Kafka cluster.

Broker names are specified as `host[:port]` where the port is optional 
(default 9092) and the host is either a resolvable hostname or an IPv4 or IPv6
address.
If host resolves to multiple addresses librdkafka will round-robin the
addresses for each connection attempt.
A DNS record containing all broker address can thus be used to provide a
reliable bootstrap broker.

#### Connection close

A broker connection may be closed by the broker, intermediary network gear,
due to network errors, timeouts, etc.
When a broker connection is closed, librdkafka will wait for
`reconnect.backoff.jitter.ms` +-50% before reconnecting.

The broker will disconnect clients that have not sent any protocol requests
within `connections.max.idle.ms` (broker configuration propertion, defaults
to 10 minutes), but there is no fool proof way for the client to know that it
was a deliberate close by the broker and not an error. To avoid logging these
deliberate idle disconnects as errors the client employs some logic to try to
classify a disconnect as an idle disconnect if no requests have been sent in
the last `socket.timeout.ms` or there are no outstanding, or
queued, requests waiting to be sent. In this case the standard "Disconnect"
error log is silenced (will only be seen with debug enabled).

`log.connection.close=false` may be used to silence all disconnect logs,
but it is recommended to instead rely on the above heuristics.



### Feature discovery

Apache Kafka broker version 0.10.0 added support for the ApiVersionRequest API
which allows a client to query a broker for its range of supported API versions.

librdkafka supports this functionality and will query each broker on connect
for this information (if `api.version.request=true`) and use it to enable or disable
various protocol features, such as MessageVersion 1 (timestamps), KafkaConsumer, etc.

If the broker fails to respond to the ApiVersionRequest librdkafka will
assume the broker is too old to support the API and fall back to an older
broker version's API. These fallback versions are hardcoded in librdkafka
and is controlled by the `broker.version.fallback` configuration property.



### Producer API

After setting up the `rd_kafka_t` object with type `RD_KAFKA_PRODUCER` and one
or more `rd_kafka_topic_t` objects librdkafka is ready for accepting messages
to be produced and sent to brokers.

The `rd_kafka_produce()` function takes the following arguments:

  * `rkt` - the topic to produce to, previously created with
	  `rd_kafka_topic_new()`
  * `partition` - partition to produce to. If this is set to
	  `RD_KAFKA_PARTITION_UA` (UnAssigned) then the configured partitioner
		  function will be used to select a target partition.
  * `msgflags` - 0, or one of:
	  * `RD_KAFKA_MSG_F_COPY` - librdkafka will immediately make a copy of
	    the payload. Use this when the payload is in non-persistent
	    memory, such as the stack.
	  * `RD_KAFKA_MSG_F_FREE` - let librdkafka free the payload using
	    `free(3)` when it is done with it.
	
	These two flags are mutually exclusive and neither need to be set in
	which case the payload is neither copied nor freed by librdkafka.
		
	If `RD_KAFKA_MSG_F_COPY` flag is not set no data copying will be
	performed and librdkafka will hold on the payload pointer until
	the message	has been delivered or fails.
	The delivery report callback will be called when librdkafka is done
	with the message to let the application regain ownership of the
	payload memory.
	The application must not free the payload in the delivery report
	callback if `RD_KAFKA_MSG_F_FREE is set`.
  * `payload`,`len` - the message payload
  * `key`,`keylen` - an optional message key which can be used for partitioning.
	  It will be passed to the topic partitioner callback, if any, and
	  will be attached to the message when sending to the broker.
  * `msg_opaque` - an optional application-provided per-message opaque pointer
	  that will be provided in the message delivery callback to let
	  the application reference a specific message.


`rd_kafka_produce()` is a non-blocking API, it will enqueue the message
on an internal queue and return immediately.
If the number of queued messages would exceed the `queue.buffering.max.messages`
configuration property then `rd_kafka_produce()` returns -1 and sets errno
to `ENOBUFS` and last_error to `RD_KAFKA_RESP_ERR__QUEUE_FULL`, thus
providing a backpressure mechanism.


**Note**: See `examples/rdkafka_performance.c` for a producer implementation.


### Simple Consumer API (legacy)

NOTE: For the high-level KafkaConsumer interface see rd_kafka_subscribe (rdkafka.h) or KafkaConsumer (rdkafkacpp.h)

The consumer API is a bit more stateful than the producer API.
After creating `rd_kafka_t` with type `RD_KAFKA_CONSUMER` and
`rd_kafka_topic_t` instances the application must also start the consumer
for a given partition by calling `rd_kafka_consume_start()`.

`rd_kafka_consume_start()` arguments:

  * `rkt` - the topic to start consuming from, previously created with
    	  `rd_kafka_topic_new()`.
  * `partition` - partition to consume from.
  * `offset` - message offset to start consuming from. This may either be an
    	     absolute message offset or one of the two special offsets:
	     `RD_KAFKA_OFFSET_BEGINNING` to start consuming from the beginning
	     of the partition's queue (oldest message), or
	     `RD_KAFKA_OFFSET_END` to start consuming at the next message to be
	     produced to the partition, or
	     `RD_KAFKA_OFFSET_STORED` to use the offset store.

After a topic+partition consumer has been started librdkafka will attempt
to keep `queued.min.messages` messages in the local queue by repeatedly
fetching batches of messages from the broker. librdkafka will fetch all
consumed partitions for which that broker is a leader, through a single
request.

This local message queue is then served to the application through three
different consume APIs:

  * `rd_kafka_consume()` - consumes a single message
  * `rd_kafka_consume_batch()` - consumes one or more messages
  * `rd_kafka_consume_callback()` - consumes all messages in the local
    queue and calls a callback function for each one.

These three APIs are listed above the ascending order of performance,
`rd_kafka_consume()` being the slowest and `rd_kafka_consume_callback()` being
the fastest. The different consume variants are provided to cater for different
application needs.

A consumed message, as provided or returned by each of the consume functions,
is represented by the `rd_kafka_message_t` type.

`rd_kafka_message_t` members:

  * `err` - Error signaling back to the application. If this field is non-zero
    	  the `payload` field should be considered an error message and
	  `err` is an error code (`rd_kafka_resp_err_t`).
	  If `err` is zero then the message is a proper fetched message
	  and `payload` et.al contains message payload data.
  * `rkt`,`partition` - Topic and partition for this message or error.
  * `payload`,`len` - Message payload data or error message (err!=0).
  * `key`,`key_len` - Optional message key as specified by the producer
  * `offset` - Message offset

Both the `payload` and `key` memory, as well as the message as a whole, is
owned by librdkafka and must not be used after an `rd_kafka_message_destroy()`
call. librdkafka will share the same messageset receive buffer memory for all
message payloads of that messageset to avoid excessive copying which means
that if the application decides to hang on to a single `rd_kafka_message_t`
it will hinder the backing memory to be released for all other messages
from the same messageset.

When the application is done consuming messages from a topic+partition it
should call `rd_kafka_consume_stop()` to stop the consumer. This will also
purge any messages currently in the local queue.


**Note**: See `examples/rdkafka_performance.c` for a consumer implementation.


#### Offset management

Broker based offset management is available for broker version >= 0.9.0
in conjunction with using the high-level KafkaConsumer interface (see
rdkafka.h or rdkafkacpp.h)

Offset management is also available through a local offset file store, where the
offset is periodically written to a local file for each topic+partition
according to the following topic configuration properties:

  * `auto.commit.enable`
  * `auto.commit.interval.ms`
  * `offset.store.path`
  * `offset.store.sync.interval.ms`

There is currently no support for offset management with ZooKeeper.



#### Consumer groups

Broker based consumer groups (requires Apache Kafka broker >=0.9) are supported,
see KafkaConsumer in rdkafka.h or rdkafkacpp.h


### Topics

#### Topic auto creation

Topic auto creation is supported by librdkafka.
The broker needs to be configured with `auto.create.topics.enable=true`.



### Metadata

#### < 0.9.3
Previous to the 0.9.3 release librdkafka's metadata handling
was chatty and excessive, which usually isn't a problem in small
to medium-sized clusters, but in large clusters with a large amount
of librdkafka clients the metadata requests could hog broker CPU and bandwidth.

#### > 0.9.3

The remaining Metadata sections describe the current behaviour.

**Note:** "Known topics" in the following section means topics for
          locally created `rd_kafka_topic_t` objects.


#### Query reasons

There are four reasons to query metadata:

 * brokers - update/populate cluster broker list, so the client can
             find and connect to any new brokers added.

 * specific topic - find leader or partition count for specific topic

 * known topics - same, but for all locally known topics.

 * all topics - get topic names for consumer group wildcard subscription
                matching

The above list is sorted so that the sub-sequent entries contain the
information above, e.g., 'known topics' contains enough information to
also satisfy 'specific topic' and 'brokers'.


#### Caching strategy

The prevalent cache timeout is `metadata.max.age.ms`, any cached entry
will remain authoritative for this long or until a relevant broker error
is returned.


 * brokers - eternally cached, the broker list is additative.

 * topics - cached for `metadata.max.age.ms`




## Appendix

### Test details

#### Test1: Produce to two brokers, two partitions, required.acks=2, 100 byte messages

Each broker is leader for one of the two partitions.
The random partitioner is used (default) and each broker and partition is
assigned approximately 250000 messages each.

**Command:**

    # examples/rdkafka_performance -P -t test2 -s 100 -c 500000 -m "_____________Test1:TwoBrokers:500kmsgs:100bytes" -S 1 -a 2
	....
    % 500000 messages and 50000000 bytes sent in 587ms: 851531 msgs/s and 85.15 Mb/s, 0 messages failed, no compression

**Result:**

Message transfer rate is approximately **850000 messages per second**,
**85 megabytes per second**.



#### Test2: Produce to one broker, one partition, required.acks=0, 100 byte messages

**Command:**

    # examples/rdkafka_performance -P -t test2 -s 100 -c 500000 -m "_____________Test2:OneBrokers:500kmsgs:100bytes" -S 1 -a 0 -p 1
	....
	% 500000 messages and 50000000 bytes sent in 698ms: 715994 msgs/s and 71.60 Mb/s, 0 messages failed, no compression

**Result:**

Message transfer rate is approximately **710000 messages per second**,
**71 megabytes per second**.



#### Test3: Produce to two brokers, two partitions, required.acks=2, 100 byte messages, snappy compression

**Command:**

	# examples/rdkafka_performance -P -t test2 -s 100 -c 500000 -m "_____________Test3:TwoBrokers:500kmsgs:100bytes:snappy" -S 1 -a 2 -z snappy
	....
	% 500000 messages and 50000000 bytes sent in 1672ms: 298915 msgs/s and 29.89 Mb/s, 0 messages failed, snappy compression

**Result:**

Message transfer rate is approximately **300000 messages per second**,
**30 megabytes per second**.


#### Test4: Produce to two brokers, two partitions, required.acks=2, 100 byte messages, gzip compression

**Command:**

	# examples/rdkafka_performance -P -t test2 -s 100 -c 500000 -m "_____________Test3:TwoBrokers:500kmsgs:100bytes:gzip" -S 1 -a 2 -z gzip
	....
	% 500000 messages and 50000000 bytes sent in 2111ms: 236812 msgs/s and 23.68 Mb/s, 0 messages failed, gzip compression

**Result:**

Message transfer rate is approximately **230000 messages per second**,
**23 megabytes per second**.

