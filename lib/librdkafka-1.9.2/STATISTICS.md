# Statistics

librdkafka may be configured to emit internal metrics at a fixed interval
by setting the `statistics.interval.ms` configuration property to a value > 0
and registering a `stats_cb` (or similar, depending on language).

The stats are provided as a JSON object string.

**Note**: The metrics returned may not be completely consistent between
          brokers, toppars and totals, due to the internal asynchronous
          nature of librdkafka.
          E.g., the top level `tx` total may be less than the sum of
          the broker `tx` values which it represents.


## General structure

All fields that contain sizes are in bytes unless otherwise noted.

```
{
 <Top-level fields>
 "brokers": {
    <brokers fields>,
    "toppars": { <toppars fields> }
 },
 "topics": {
   <topic fields>,
   "partitions": {
     <partitions fields>
   }
 }
[, "cgrp": { <cgrp fields> } ]
[, "eos": { <eos fields> } ]
}
```

## Field type

Fields are represented as follows:
 * string - UTF8 string.
 * int - Integer counter (64 bits wide). Ever increasing.
 * int gauge - Integer gauge (64 bits wide). Will be reset to 0 on each stats emit.
 * object - Nested JSON object.
 * bool - `true` or `false`.


## Top-level

Field | Type | Example | Description
----- | ---- | ------- | -----------
name | string | `"rdkafka#producer-1"` | Handle instance name
client_id | string | `"rdkafka"` | The configured (or default) `client.id`
type | string | `"producer"` | Instance type (producer or consumer)
ts | int | 12345678912345 | librdkafka's internal monotonic clock (microseconds)
time | int | | Wall clock time in seconds since the epoch
age | int | | Time since this client instance was created (microseconds)
replyq | int gauge | | Number of ops (callbacks, events, etc) waiting in queue for application to serve with rd_kafka_poll()
msg_cnt | int gauge | | Current number of messages in producer queues
msg_size | int gauge | | Current total size of messages in producer queues
msg_max | int | | Threshold: maximum number of messages allowed allowed on the producer queues
msg_size_max | int | | Threshold: maximum total size of messages allowed on the producer queues
tx | int | | Total number of requests sent to Kafka brokers
tx_bytes | int | | Total number of bytes transmitted to Kafka brokers
rx | int | | Total number of responses received from Kafka brokers
rx_bytes | int | | Total number of bytes received from Kafka brokers
txmsgs | int | | Total number of messages transmitted (produced) to Kafka brokers
txmsg_bytes | int | | Total number of message bytes (including framing, such as per-Message framing and MessageSet/batch framing) transmitted to Kafka brokers
rxmsgs | int | | Total number of messages consumed, not including ignored messages (due to offset, etc), from Kafka brokers.
rxmsg_bytes | int | | Total number of message bytes (including framing) received from Kafka brokers
simple_cnt | int gauge | | Internal tracking of legacy vs new consumer API state
metadata_cache_cnt | int gauge | | Number of topics in the metadata cache.
brokers | object | | Dict of brokers, key is broker name, value is object. See **brokers** below
topics | object | | Dict of topics, key is topic name, value is object. See **topics** below
cgrp | object | | Consumer group metrics. See **cgrp** below
eos | object | | EOS / Idempotent producer state and metrics. See **eos** below

## brokers

Per broker statistics.

Field | Type | Example | Description
----- | ---- | ------- | -----------
name | string | `"example.com:9092/13"` | Broker hostname, port and broker id
nodeid | int | 13 | Broker id (-1 for bootstraps)
nodename | string | `"example.com:9092"` | Broker hostname
source | string | `"configured"` | Broker source (learned, configured, internal, logical)
state | string | `"UP"` | Broker state (INIT, DOWN, CONNECT, AUTH, APIVERSION_QUERY, AUTH_HANDSHAKE, UP, UPDATE)
stateage | int gauge | | Time since last broker state change (microseconds)
outbuf_cnt | int gauge | | Number of requests awaiting transmission to broker
outbuf_msg_cnt | int gauge | | Number of messages awaiting transmission to broker
waitresp_cnt | int gauge | | Number of requests in-flight to broker awaiting response
waitresp_msg_cnt | int gauge | | Number of messages in-flight to broker awaiting response
tx | int | | Total number of requests sent
txbytes | int | | Total number of bytes sent
txerrs | int | | Total number of transmission errors
txretries | int | | Total number of request retries
txidle | int | | Microseconds since last socket send (or -1 if no sends yet for current connection).
req_timeouts | int | | Total number of requests timed out
rx | int | | Total number of responses received
rxbytes | int | | Total number of bytes received
rxerrs | int | | Total number of receive errors
rxcorriderrs | int | | Total number of unmatched correlation ids in response (typically for timed out requests)
rxpartial | int | | Total number of partial MessageSets received. The broker may return partial responses if the full MessageSet could not fit in the remaining Fetch response size.
rxidle | int | | Microseconds since last socket receive (or -1 if no receives yet for current connection).
req | object | | Request type counters. Object key is the request name, value is the number of requests sent.
zbuf_grow | int | | Total number of decompression buffer size increases
buf_grow | int | | Total number of buffer size increases (deprecated, unused)
wakeups | int | | Broker thread poll loop wakeups
connects | int | | Number of connection attempts, including successful and failed, and name resolution failures.
disconnects | int | | Number of disconnects (triggered by broker, network, load-balancer, etc.).
int_latency | object | | Internal producer queue latency in microseconds. See *Window stats* below
outbuf_latency | object | | Internal request queue latency in microseconds. This is the time between a request is enqueued on the transmit (outbuf) queue and the time the request is written to the TCP socket. Additional buffering and latency may be incurred by the TCP stack and network. See *Window stats* below
rtt | object | | Broker latency / round-trip time in microseconds. See *Window stats* below
throttle | object | | Broker throttling time in milliseconds. See *Window stats* below
toppars | object | | Partitions handled by this broker handle. Key is "topic-partition". See *brokers.toppars* below


## Window stats

Rolling window statistics. The values are in microseconds unless otherwise stated.

Field | Type | Example | Description
----- | ---- | ------- | -----------
min | int gauge | | Smallest value
max | int gauge | | Largest value
avg | int gauge | | Average value
sum | int gauge | | Sum of values
cnt | int gauge | | Number of values sampled
stddev | int gauge | | Standard deviation (based on histogram)
hdrsize | int gauge | | Memory size of Hdr Histogram
p50 | int gauge | | 50th percentile
p75 | int gauge | | 75th percentile
p90 | int gauge | | 90th percentile
p95 | int gauge | | 95th percentile
p99 | int gauge | | 99th percentile
p99_99 | int gauge | | 99.99th percentile
outofrange | int gauge | | Values skipped due to out of histogram range


## brokers.toppars

Topic partition assigned to broker.

Field | Type | Example | Description
----- | ---- | ------- | -----------
topic | string | `"mytopic"` | Topic name
partition | int | 3 | Partition id

## topics

Field | Type | Example | Description
----- | ---- | ------- | -----------
topic | string | `"myatopic"` | Topic name
age   | int gauge | | Age of client's topic object (milliseconds)
metadata_age | int gauge | | Age of metadata from broker for this topic (milliseconds)
batchsize | object | | Batch sizes in bytes. See *Window stats*·
batchcnt | object | | Batch message counts. See *Window stats*·
partitions | object | | Partitions dict, key is partition id. See **partitions** below.


## partitions

Field | Type | Example | Description
----- | ---- | ------- | -----------
partition | int | 3 | Partition Id (-1 for internal UA/UnAssigned partition)
broker | int | | The id of the broker that messages are currently being fetched from
leader | int | | Current leader broker id
desired | bool | | Partition is explicitly desired by application
unknown | bool | | Partition not seen in topic metadata from broker
msgq_cnt | int gauge | | Number of messages waiting to be produced in first-level queue
msgq_bytes | int gauge | | Number of bytes in msgq_cnt
xmit_msgq_cnt | int gauge | | Number of messages ready to be produced in transmit queue
xmit_msgq_bytes | int gauge | | Number of bytes in xmit_msgq
fetchq_cnt | int gauge | | Number of pre-fetched messages in fetch queue
fetchq_size | int gauge | | Bytes in fetchq
fetch_state | string | `"active"` | Consumer fetch state for this partition (none, stopping, stopped, offset-query, offset-wait, active).
query_offset | int gauge | | Current/Last logical offset query
next_offset | int gauge | | Next offset to fetch
app_offset | int gauge | | Offset of last message passed to application + 1
stored_offset | int gauge | | Offset to be committed
committed_offset | int gauge | | Last committed offset
eof_offset | int gauge | | Last PARTITION_EOF signaled offset
lo_offset | int gauge | | Partition's low watermark offset on broker
hi_offset | int gauge | | Partition's high watermark offset on broker
ls_offset | int gauge | | Partition's last stable offset on broker, or same as hi_offset is broker version is less than 0.11.0.0.
consumer_lag | int gauge | | Difference between (hi_offset or ls_offset) and committed_offset). hi_offset is used when isolation.level=read_uncommitted, otherwise ls_offset.
consumer_lag_stored | int gauge | | Difference between (hi_offset or ls_offset) and stored_offset. See consumer_lag and stored_offset.
txmsgs | int | | Total number of messages transmitted (produced)
txbytes | int | | Total number of bytes transmitted for txmsgs
rxmsgs | int | | Total number of messages consumed, not including ignored messages (due to offset, etc).
rxbytes | int | | Total number of bytes received for rxmsgs
msgs | int | | Total number of messages received (consumer, same as rxmsgs), or total number of messages produced (possibly not yet transmitted) (producer).
rx_ver_drops | int | | Dropped outdated messages
msgs_inflight | int gauge | | Current number of messages in-flight to/from broker
next_ack_seq | int gauge | | Next expected acked sequence (idempotent producer)
next_err_seq | int gauge | | Next expected errored sequence (idempotent producer)
acked_msgid | int | | Last acked internal message id (idempotent producer)

## cgrp

Field | Type | Example | Description
----- | ---- | ------- | -----------
state | string | "up"    | Local consumer group handler's state.
stateage | int gauge | | Time elapsed since last state change (milliseconds).
join_state | string | "assigned" | Local consumer group handler's join state.
rebalance_age | int gauge | | Time elapsed since last rebalance (assign or revoke) (milliseconds).
rebalance_cnt | int | | Total number of rebalances (assign or revoke).
rebalance_reason | string | | Last rebalance reason, or empty string.
assignment_size | int gauge | | Current assignment's partition count.


## eos

Field | Type | Example | Description
----- | ---- | ------- | -----------
idemp_state | string | "Assigned" | Current idempotent producer id state.
idemp_stateage | int gauge | | Time elapsed since last idemp_state change (milliseconds).
txn_state | string | "InTransaction" | Current transactional producer state.
txn_stateage | int gauge | | Time elapsed since last txn_state change (milliseconds).
txn_may_enq | bool | | Transactional state allows enqueuing (producing) new messages.
producer_id | int gauge | | The currently assigned Producer ID (or -1).
producer_epoch | int gauge | | The current epoch (or -1).
epoch_cnt | int | | The number of Producer ID assignments since start.


# Example output

This (prettified) example output is from a short-lived producer using the following command:
`rdkafka_performance -b localhost -P -t test -T 1000 -Y 'cat >> stats.json'`.

Note: this output is prettified using `jq .`, the JSON object emitted by librdkafka does not contain line breaks.

```json
{
  "name": "rdkafka#producer-1",
  "client_id": "rdkafka",
  "type": "producer",
  "ts": 5016483227792,
  "time": 1527060869,
  "replyq": 0,
  "msg_cnt": 22710,
  "msg_size": 704010,
  "msg_max": 500000,
  "msg_size_max": 1073741824,
  "simple_cnt": 0,
  "metadata_cache_cnt": 1,
  "brokers": {
    "localhost:9092/2": {
      "name": "localhost:9092/2",
      "nodeid": 2,
      "nodename": "localhost:9092",
      "source": "learned",
      "state": "UP",
      "stateage": 9057234,
      "outbuf_cnt": 0,
      "outbuf_msg_cnt": 0,
      "waitresp_cnt": 0,
      "waitresp_msg_cnt": 0,
      "tx": 320,
      "txbytes": 84283332,
      "txerrs": 0,
      "txretries": 0,
      "req_timeouts": 0,
      "rx": 320,
      "rxbytes": 15708,
      "rxerrs": 0,
      "rxcorriderrs": 0,
      "rxpartial": 0,
      "zbuf_grow": 0,
      "buf_grow": 0,
      "wakeups": 591067,
      "int_latency": {
        "min": 86,
        "max": 59375,
        "avg": 23726,
        "sum": 5694616664,
        "stddev": 13982,
        "p50": 28031,
        "p75": 36095,
        "p90": 39679,
        "p95": 43263,
        "p99": 48639,
        "p99_99": 59391,
        "outofrange": 0,
        "hdrsize": 11376,
        "cnt": 240012
      },
      "rtt": {
        "min": 1580,
        "max": 3389,
        "avg": 2349,
        "sum": 79868,
        "stddev": 474,
        "p50": 2319,
        "p75": 2543,
        "p90": 3183,
        "p95": 3199,
        "p99": 3391,
        "p99_99": 3391,
        "outofrange": 0,
        "hdrsize": 13424,
        "cnt": 34
      },
      "throttle": {
        "min": 0,
        "max": 0,
        "avg": 0,
        "sum": 0,
        "stddev": 0,
        "p50": 0,
        "p75": 0,
        "p90": 0,
        "p95": 0,
        "p99": 0,
        "p99_99": 0,
        "outofrange": 0,
        "hdrsize": 17520,
        "cnt": 34
      },
      "toppars": {
        "test-1": {
          "topic": "test",
          "partition": 1
        }
      }
    },
    "localhost:9093/3": {
      "name": "localhost:9093/3",
      "nodeid": 3,
      "nodename": "localhost:9093",
      "source": "learned",
      "state": "UP",
      "stateage": 9057209,
      "outbuf_cnt": 0,
      "outbuf_msg_cnt": 0,
      "waitresp_cnt": 0,
      "waitresp_msg_cnt": 0,
      "tx": 310,
      "txbytes": 84301122,
      "txerrs": 0,
      "txretries": 0,
      "req_timeouts": 0,
      "rx": 310,
      "rxbytes": 15104,
      "rxerrs": 0,
      "rxcorriderrs": 0,
      "rxpartial": 0,
      "zbuf_grow": 0,
      "buf_grow": 0,
      "wakeups": 607956,
      "int_latency": {
        "min": 82,
        "max": 58069,
        "avg": 23404,
        "sum": 5617432101,
        "stddev": 14021,
        "p50": 27391,
        "p75": 35839,
        "p90": 39679,
        "p95": 42751,
        "p99": 48639,
        "p99_99": 58111,
        "outofrange": 0,
        "hdrsize": 11376,
        "cnt": 240016
      },
      "rtt": {
        "min": 1704,
        "max": 3572,
        "avg": 2493,
        "sum": 87289,
        "stddev": 559,
        "p50": 2447,
        "p75": 2895,
        "p90": 3375,
        "p95": 3407,
        "p99": 3583,
        "p99_99": 3583,
        "outofrange": 0,
        "hdrsize": 13424,
        "cnt": 35
      },
      "throttle": {
        "min": 0,
        "max": 0,
        "avg": 0,
        "sum": 0,
        "stddev": 0,
        "p50": 0,
        "p75": 0,
        "p90": 0,
        "p95": 0,
        "p99": 0,
        "p99_99": 0,
        "outofrange": 0,
        "hdrsize": 17520,
        "cnt": 35
      },
      "toppars": {
        "test-0": {
          "topic": "test",
          "partition": 0
        }
      }
    },
    "localhost:9094/4": {
      "name": "localhost:9094/4",
      "nodeid": 4,
      "nodename": "localhost:9094",
      "source": "learned",
      "state": "UP",
      "stateage": 9057207,
      "outbuf_cnt": 0,
      "outbuf_msg_cnt": 0,
      "waitresp_cnt": 0,
      "waitresp_msg_cnt": 0,
      "tx": 1,
      "txbytes": 25,
      "txerrs": 0,
      "txretries": 0,
      "req_timeouts": 0,
      "rx": 1,
      "rxbytes": 272,
      "rxerrs": 0,
      "rxcorriderrs": 0,
      "rxpartial": 0,
      "zbuf_grow": 0,
      "buf_grow": 0,
      "wakeups": 4,
      "int_latency": {
        "min": 0,
        "max": 0,
        "avg": 0,
        "sum": 0,
        "stddev": 0,
        "p50": 0,
        "p75": 0,
        "p90": 0,
        "p95": 0,
        "p99": 0,
        "p99_99": 0,
        "outofrange": 0,
        "hdrsize": 11376,
        "cnt": 0
      },
      "rtt": {
        "min": 0,
        "max": 0,
        "avg": 0,
        "sum": 0,
        "stddev": 0,
        "p50": 0,
        "p75": 0,
        "p90": 0,
        "p95": 0,
        "p99": 0,
        "p99_99": 0,
        "outofrange": 0,
        "hdrsize": 13424,
        "cnt": 0
      },
      "throttle": {
        "min": 0,
        "max": 0,
        "avg": 0,
        "sum": 0,
        "stddev": 0,
        "p50": 0,
        "p75": 0,
        "p90": 0,
        "p95": 0,
        "p99": 0,
        "p99_99": 0,
        "outofrange": 0,
        "hdrsize": 17520,
        "cnt": 0
      },
      "toppars": {}
    }
  },
  "topics": {
    "test": {
      "topic": "test",
      "metadata_age": 9060,
      "batchsize": {
        "min": 99,
        "max": 391805,
        "avg": 272593,
        "sum": 18808985,
        "stddev": 180408,
        "p50": 393215,
        "p75": 393215,
        "p90": 393215,
        "p95": 393215,
        "p99": 393215,
        "p99_99": 393215,
        "outofrange": 0,
        "hdrsize": 14448,
        "cnt": 69
      },
      "batchcnt": {
        "min": 1,
        "max": 10000,
        "avg": 6956,
        "sum": 480028,
        "stddev": 4608,
        "p50": 10047,
        "p75": 10047,
        "p90": 10047,
        "p95": 10047,
        "p99": 10047,
        "p99_99": 10047,
        "outofrange": 0,
        "hdrsize": 8304,
        "cnt": 69
      },
      "partitions": {
        "0": {
          "partition": 0,
          "broker": 3,
          "leader": 3,
          "desired": false,
          "unknown": false,
          "msgq_cnt": 1,
          "msgq_bytes": 31,
          "xmit_msgq_cnt": 0,
          "xmit_msgq_bytes": 0,
          "fetchq_cnt": 0,
          "fetchq_size": 0,
          "fetch_state": "none",
          "query_offset": 0,
          "next_offset": 0,
          "app_offset": -1001,
          "stored_offset": -1001,
          "commited_offset": -1001,
          "committed_offset": -1001,
          "eof_offset": -1001,
          "lo_offset": -1001,
          "hi_offset": -1001,
          "consumer_lag": -1,
          "txmsgs": 2150617,
          "txbytes": 66669127,
          "rxmsgs": 0,
          "rxbytes": 0,
          "msgs": 2160510,
          "rx_ver_drops": 0
        },
        "1": {
          "partition": 1,
          "broker": 2,
          "leader": 2,
          "desired": false,
          "unknown": false,
          "msgq_cnt": 0,
          "msgq_bytes": 0,
          "xmit_msgq_cnt": 0,
          "xmit_msgq_bytes": 0,
          "fetchq_cnt": 0,
          "fetchq_size": 0,
          "fetch_state": "none",
          "query_offset": 0,
          "next_offset": 0,
          "app_offset": -1001,
          "stored_offset": -1001,
          "commited_offset": -1001,
          "committed_offset": -1001,
          "eof_offset": -1001,
          "lo_offset": -1001,
          "hi_offset": -1001,
          "consumer_lag": -1,
          "txmsgs": 2150136,
          "txbytes": 66654216,
          "rxmsgs": 0,
          "rxbytes": 0,
          "msgs": 2159735,
          "rx_ver_drops": 0
        },
        "-1": {
          "partition": -1,
          "broker": -1,
          "leader": -1,
          "desired": false,
          "unknown": false,
          "msgq_cnt": 0,
          "msgq_bytes": 0,
          "xmit_msgq_cnt": 0,
          "xmit_msgq_bytes": 0,
          "fetchq_cnt": 0,
          "fetchq_size": 0,
          "fetch_state": "none",
          "query_offset": 0,
          "next_offset": 0,
          "app_offset": -1001,
          "stored_offset": -1001,
          "commited_offset": -1001,
          "committed_offset": -1001,
          "eof_offset": -1001,
          "lo_offset": -1001,
          "hi_offset": -1001,
          "consumer_lag": -1,
          "txmsgs": 0,
          "txbytes": 0,
          "rxmsgs": 0,
          "rxbytes": 0,
          "msgs": 1177,
          "rx_ver_drops": 0
        }
      }
    }
  },
  "tx": 631,
  "tx_bytes": 168584479,
  "rx": 631,
  "rx_bytes": 31084,
  "txmsgs": 4300753,
  "txmsg_bytes": 133323343,
  "rxmsgs": 0,
  "rxmsg_bytes": 0
}
```
