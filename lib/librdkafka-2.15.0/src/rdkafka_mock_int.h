/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019-2022, Magnus Edenhill
 *               2023, Confluent Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RDKAFKA_MOCK_INT_H_
#define _RDKAFKA_MOCK_INT_H_

#include "rdkafka_request.h"

/**
 * @name Mock cluster - internal data types
 *
 */


/**
 * @struct Response error and/or RTT-delay to return to client.
 */
typedef struct rd_kafka_mock_error_rtt_s {
        rd_kafka_resp_err_t err; /**< Error response (or 0) */
        rd_ts_t rtt;             /**< RTT/delay in microseconds (or 0) */
} rd_kafka_mock_error_rtt_t;

/**
 * @struct A stack of errors or rtt latencies to return to the client,
 *         one by one until the stack is depleted.
 */
typedef struct rd_kafka_mock_error_stack_s {
        TAILQ_ENTRY(rd_kafka_mock_error_stack_s) link;
        int16_t ApiKey; /**< Optional ApiKey for which this stack
                         *   applies to, else -1. */
        size_t cnt;     /**< Current number of errors in .errs */
        size_t size;    /**< Current allocated size for .errs (in elements) */
        rd_kafka_mock_error_rtt_t *errs; /**< Array of errors/rtts */
} rd_kafka_mock_error_stack_t;

typedef TAILQ_HEAD(rd_kafka_mock_error_stack_head_s,
                   rd_kafka_mock_error_stack_s)
    rd_kafka_mock_error_stack_head_t;


/**
 * @struct Consumer group protocol name and metadata.
 */
typedef struct rd_kafka_mock_cgrp_classic_proto_s {
        rd_kafkap_str_t *name;
        rd_kafkap_bytes_t *metadata;
} rd_kafka_mock_cgrp_classic_proto_t;

/**
 * @struct Consumer group member
 */
typedef struct rd_kafka_mock_cgrp_classic_member_s {
        TAILQ_ENTRY(rd_kafka_mock_cgrp_classic_member_s) link;
        char *id;                 /**< MemberId */
        char *group_instance_id;  /**< Group instance id */
        rd_ts_t ts_last_activity; /**< Last activity, e.g., Heartbeat */
        rd_kafka_mock_cgrp_classic_proto_t *protos; /**< Protocol names */
        int proto_cnt;                              /**< Number of protocols */
        rd_kafkap_bytes_t *assignment;              /**< Current assignment */
        rd_kafka_buf_t *resp;                    /**< Current response buffer */
        struct rd_kafka_mock_connection_s *conn; /**< Connection, may be NULL
                                                  *   if there is no ongoing
                                                  *   request. */
} rd_kafka_mock_cgrp_classic_member_t;

/**
 * @struct Classic consumer group.
 */
typedef struct rd_kafka_mock_cgrp_classic_s {
        TAILQ_ENTRY(rd_kafka_mock_cgrp_classic_s) link;
        struct rd_kafka_mock_cluster_s *cluster; /**< Cluster */
        struct rd_kafka_mock_connection_s *conn; /**< Connection */
        char *id;                                /**< Group Id */
        char *protocol_type;                     /**< Protocol type */
        char *protocol_name;                     /**< Elected protocol name */
        int32_t generation_id;                   /**< Generation Id */
        int session_timeout_ms;                  /**< Session timeout */
        enum {
                RD_KAFKA_MOCK_CGRP_STATE_EMPTY,       /* No members */
                RD_KAFKA_MOCK_CGRP_STATE_JOINING,     /* Members are joining */
                RD_KAFKA_MOCK_CGRP_STATE_SYNCING,     /* Syncing assignments */
                RD_KAFKA_MOCK_CGRP_STATE_REBALANCING, /* Rebalance triggered */
                RD_KAFKA_MOCK_CGRP_STATE_UP,          /* Group is operational */
        } state;                        /**< Consumer group state */
        rd_kafka_timer_t session_tmr;   /**< Session timeout timer */
        rd_kafka_timer_t rebalance_tmr; /**< Rebalance state timer */
        TAILQ_HEAD(, rd_kafka_mock_cgrp_classic_member_s)
        members;             /**< Group members */
        int member_cnt;      /**< Number of group members */
        int last_member_cnt; /**< Mumber of group members at last election */
        int assignment_cnt;  /**< Number of member assignments in last Sync */
        rd_kafka_mock_cgrp_classic_member_t *leader; /**< Elected leader */
} rd_kafka_mock_cgrp_classic_t;


/**
 * @struct "Consumer" Consumer group (KIP-848).
 */
typedef struct rd_kafka_mock_cgrp_consumer_s {
        TAILQ_ENTRY(rd_kafka_mock_cgrp_consumer_s) link;
        struct rd_kafka_mock_cluster_s *cluster; /**< Cluster */
        char *id;                                /**< Group Id */
        int32_t group_epoch;                     /**< Group epoch */
        int session_timeout_ms;                  /**< Session timeout */
        rd_kafka_timer_t session_tmr;            /**< Session timeout timer */
        int heartbeat_interval_ms;               /**< Heartbeat interval */
        TAILQ_HEAD(, rd_kafka_mock_cgrp_consumer_member_s)
        members;                     /**< Group members */
        int member_cnt;              /**< Number of group members */
        rd_bool_t manual_assignment; /**< Use manual assignment */
} rd_kafka_mock_cgrp_consumer_t;


/**
 * @struct "Consumer" Consumer group member (KIP-848).
 */
typedef struct rd_kafka_mock_cgrp_consumer_member_s {
        TAILQ_ENTRY(rd_kafka_mock_cgrp_consumer_member_s) link;
        char *id;                     /**< MemberId */
        char *instance_id;            /**< Group instance id */
        rd_ts_t ts_last_activity;     /**< Last activity, e.g.,
                                       *   ConsumerGroupHeartbeat */
        int32_t current_member_epoch; /**< Current member epoch,
                                       *   updated only on heartbeat. */
        int32_t
            target_member_epoch; /**< Target member epoch,
                                  *   updated only when calling
                                  *   rd_kafka_mock_cgrp_consumer_target_assignment.
                                  */
        rd_kafka_topic_partition_list_t
            *current_assignment; /**< Current assignment,
                                  *   only updated when reported by the client.
                                  */
        rd_kafka_topic_partition_list_t *
            target_assignment; /**< Target assignment,
                                *   only updated when calling
                                *   rd_kafka_mock_cgrp_consumer_target_assignment.
                                */
        rd_kafka_topic_partition_list_t
            *returned_assignment; /**< Returned assignment */

        rd_list_t *subscribed_topics; /**< Final list of Subscribed topics after
                                         considering regex as well*/
        rd_list_t *subscribed_topic_names; /**< Subscribed topic names received
                                              in the heartbeat */
        char *subscribed_topic_regex;      /**< Subscribed regex */

        rd_bool_t left_static_membership;        /**< Member left the group
                                                  *   with static membership. */
        struct rd_kafka_mock_connection_s *conn; /**< Connection, may be NULL
                                                  *   if there is no ongoing
                                                  *   request. */
        rd_kafka_mock_cgrp_consumer_t *mcgrp;    /**< Consumer group */
} rd_kafka_mock_cgrp_consumer_member_t;

/**
 * @brief Share record state.
 */
enum rd_kafka_mock_sgrp_record_state_e {
        RD_KAFKA_MOCK_SGRP_RECORD_AVAILABLE    = 0,
        RD_KAFKA_MOCK_SGRP_RECORD_ACQUIRED     = 1,
        RD_KAFKA_MOCK_SGRP_RECORD_ACKNOWLEDGED = 2,
        RD_KAFKA_MOCK_SGRP_RECORD_ARCHIVED     = 3
};

typedef struct rd_kafka_mock_sgrp_record_state_s {
        TAILQ_ENTRY(rd_kafka_mock_sgrp_record_state_s) link;
        int64_t offset;
        char *owner_member_id;
        rd_ts_t lock_expiry_ts;
        int32_t delivery_count;
        enum rd_kafka_mock_sgrp_record_state_e state;
} rd_kafka_mock_sgrp_record_state_t;

/**
 * @brief Share partition metadata.
 */
typedef struct rd_kafka_mock_sgrp_partmeta_s {
        TAILQ_ENTRY(rd_kafka_mock_sgrp_partmeta_s) link;
        rd_kafka_Uuid_t topic_id;
        int32_t partition;
        int64_t spso;
        int64_t speo;
        TAILQ_HEAD(, rd_kafka_mock_sgrp_record_state_s) inflight;
        int inflight_cnt;
        int acquired_cnt; /**< Number of records in ACQUIRED state */
} rd_kafka_mock_sgrp_partmeta_t;

/**
 * @brief Share fetch session.
 */
typedef struct rd_kafka_mock_sgrp_fetch_session_s {
        TAILQ_ENTRY(rd_kafka_mock_sgrp_fetch_session_s) link;
        char *member_id;
        int32_t node_id; /**< Node ID of the broker owning this session */
        int32_t session_id;
        int32_t session_epoch;
        rd_ts_t ts_last_activity;
        rd_kafka_topic_partition_list_t *partitions;
        int partition_start_idx; /**< Rotation index for starvation prevention
                                  */
} rd_kafka_mock_sgrp_fetch_session_t;

/**
 * @struct Share group.
 */
typedef struct rd_kafka_mock_sharegroup_s {
        TAILQ_ENTRY(rd_kafka_mock_sharegroup_s) link;
        struct rd_kafka_mock_cluster_s *cluster; /**< Cluster */
        char *id;                                /**< Share group Id */
        int32_t group_epoch;                     /**< Group epoch */
        int session_timeout_ms;                  /**< Session timeout */
        rd_kafka_timer_t session_tmr;            /**< Session timeout timer */
        int heartbeat_interval_ms;               /**< Heartbeat interval */
        TAILQ_HEAD(, rd_kafka_mock_sharegroup_member_s)
        members;                     /**< Share group members */
        int member_cnt;              /**< Number of share group members */
        rd_bool_t manual_assignment; /**< Use manual assignment */

        /* ShareFetch state */
        TAILQ_HEAD(, rd_kafka_mock_sgrp_partmeta_s)
        partitions;        /**< Share partition metadata */
        int partition_cnt; /**< Number of partitions */
        TAILQ_HEAD(, rd_kafka_mock_sgrp_fetch_session_s)
        fetch_sessions;                     /**< Active fetch sessions */
        int fetch_session_cnt;              /**< Number of fetch sessions */
        rd_kafka_timer_t fetch_session_tmr; /**< Fetch session expiry timer */

        /* Per-record limits */
        int max_delivery_attempts;   /**< Max times a record can be
                                      *   acquired before being archived.
                                      *   0 = unlimited (default 5). */
        int record_lock_duration_ms; /**< Per-record lock duration in ms.
                                      *   0 = use session_timeout_ms
                                      *   as fallback (default 0). */
        int isolation_level;         /**< Share isolation level */
        int max_size;                /**< Max members allowed.
                                      *   0 = unlimited (default). */
        int max_fetch_sessions;      /**< Max fetch sessions per broker.
                                      *   0 = unlimited (default 2000). */
        int max_record_locks;        /**< Max acquired record locks per
                                      *   share-partition.
                                      *   0 = unlimited (default 2000). */
        int auto_offset_reset;       /**< 0 = latest (default),
                                      *   1 = earliest. */
} rd_kafka_mock_sharegroup_t;

/**
 * @struct Share group member.
 */
typedef struct rd_kafka_mock_sharegroup_member_s {
        TAILQ_ENTRY(rd_kafka_mock_sharegroup_member_s) link;
        char *id;                          /**< MemberId */
        rd_ts_t ts_last_activity;          /**< Last heartbeat timestamp */
        int32_t member_epoch;              /**< Current member epoch */
        int32_t previous_member_epoch;     /**< Previous member epoch (allows
                                            *   client to catch up if response
                                            *   with bumped epoch was lost) */
        rd_list_t *subscribed_topic_names; /**< Subscribed topic names */
        rd_kafka_topic_partition_list_t *assignment; /**< Current assignment */
        struct rd_kafka_mock_connection_s *conn;     /**< Connection */
        rd_kafka_mock_sharegroup_t *mshgrp;          /**< Share group */
} rd_kafka_mock_sharegroup_member_t;


/**
 * @struct TransactionalId + PID (+ optional sequence state)
 */
typedef struct rd_kafka_mock_pid_s {
        rd_kafka_pid_t pid;

        /* BaseSequence tracking (partition) */
        int8_t window;  /**< increases up to 5 */
        int8_t lo;      /**< Window low bucket: oldest */
        int8_t hi;      /**< Window high bucket: most recent */
        int32_t seq[5]; /**< Next expected BaseSequence for each bucket */

        char TransactionalId[1]; /**< Allocated after this structure */
} rd_kafka_mock_pid_t;

/**
 * @brief Transaction state enum.
 */
typedef enum {
        RD_KAFKA_MOCK_TXN_NONE,    /**< No active transaction */
        RD_KAFKA_MOCK_TXN_ONGOING, /**< Transaction in progress */
} rd_kafka_mock_txn_state_t;

/**
 * @struct A partition that is part of an active transaction.
 *
 * Linked from rd_kafka_mock_txn_t.partitions.
 */
typedef struct rd_kafka_mock_txn_partition_s {
        TAILQ_ENTRY(rd_kafka_mock_txn_partition_s) link;
        char *topic_name;
        int32_t partition;
        int64_t first_offset; /**< First offset produced in this txn,
                               *   -1 if no data produced yet. */
} rd_kafka_mock_txn_partition_t;

/**
 * @brief Active transaction state for a transactional producer.
 *
 * One per TransactionalId, stored in mcluster->transactions.
 */
typedef struct rd_kafka_mock_txn_s {
        TAILQ_ENTRY(rd_kafka_mock_txn_s) link;
        char *transactional_id;
        rd_kafka_pid_t pid; /**< Current PID for this txn */
        rd_kafka_mock_txn_state_t state;

        /** Partitions registered via AddPartitionsToTxn */
        TAILQ_HEAD(, rd_kafka_mock_txn_partition_s) partitions;
        int partition_cnt;
} rd_kafka_mock_txn_t;

/**
 * @brief A completed (aborted) transaction range on a partition.
 *
 * Stored in rd_kafka_mock_partition_t.aborted_txns.
 * Used during read_committed ShareFetch to filter out aborted data.
 */
typedef struct rd_kafka_mock_aborted_txn_s {
        TAILQ_ENTRY(rd_kafka_mock_aborted_txn_s) link;
        int64_t pid_id;       /**< Producer ID */
        int64_t first_offset; /**< First offset of aborted txn on this part */
        int64_t last_offset;  /**< Last data offset (before control record) */
} rd_kafka_mock_aborted_txn_t;

/**
 * @brief rd_kafka_mock_pid_t.pid Pid (not epoch) comparator
 */
static RD_UNUSED int rd_kafka_mock_pid_cmp_pid(const void *_a, const void *_b) {
        const rd_kafka_mock_pid_t *a = _a, *b = _b;

        if (a->pid.id < b->pid.id)
                return -1;
        else if (a->pid.id > b->pid.id)
                return 1;

        return 0;
}

/**
 * @brief rd_kafka_mock_pid_t.pid TransactionalId,Pid,epoch comparator
 */
static RD_UNUSED int rd_kafka_mock_pid_cmp(const void *_a, const void *_b) {
        const rd_kafka_mock_pid_t *a = _a, *b = _b;
        int r;

        r = strcmp(a->TransactionalId, b->TransactionalId);
        if (r)
                return r;

        if (a->pid.id < b->pid.id)
                return -1;
        else if (a->pid.id > b->pid.id)
                return 1;

        if (a->pid.epoch < b->pid.epoch)
                return -1;
        if (a->pid.epoch > b->pid.epoch)
                return 1;

        return 0;
}



/**
 * @struct A real TCP connection from the client to a mock broker.
 */
typedef struct rd_kafka_mock_connection_s {
        TAILQ_ENTRY(rd_kafka_mock_connection_s) link;
        rd_kafka_transport_t *transport; /**< Socket transport */
        rd_kafka_buf_t *rxbuf;           /**< Receive buffer */
        rd_kafka_bufq_t outbufs;         /**< Send buffers */
        short *poll_events;              /**< Events to poll, points to
                                          *   the broker's pfd array */
        struct sockaddr_in peer;         /**< Peer address */
        struct rd_kafka_mock_broker_s *broker;
        rd_kafka_timer_t write_tmr; /**< Socket write delay timer */
} rd_kafka_mock_connection_t;


/**
 * @struct Mock broker
 */
typedef struct rd_kafka_mock_broker_s {
        TAILQ_ENTRY(rd_kafka_mock_broker_s) link;
        int32_t id;
        char advertised_listener[128];
        struct sockaddr_in sin; /**< Bound address:port */
        uint16_t port;
        char *rack;
        rd_bool_t up;
        /**< If false, broker is hidden from Metadata responses and skipped
         *   when assigning partition replicas, but its TCP connections and
         *   listen socket remain active so in-flight requests can still
         *   complete. Used by rd_kafka_mock_broker_remove_from_metadata to
         *   simulate a KIP-932 broker decommission seen via metadata
         *   refresh, decoupled from the connection drop. Default: rd_true. */
        rd_bool_t in_metadata;
        rd_ts_t rtt; /**< RTT in microseconds */

        rd_socket_t listen_s; /**< listen() socket */

        TAILQ_HEAD(, rd_kafka_mock_connection_s) connections;

        /**< Per-protocol request error stack.
         *   @locks mcluster->lock */
        rd_kafka_mock_error_stack_head_t errstacks;

        struct rd_kafka_mock_cluster_s *cluster;
} rd_kafka_mock_broker_t;


/**
 * @struct A Kafka-serialized MessageSet
 */
typedef struct rd_kafka_mock_msgset_s {
        TAILQ_ENTRY(rd_kafka_mock_msgset_s) link;
        int64_t first_offset; /**< First offset in batch */
        int64_t last_offset;  /**< Last offset in batch */
        int32_t leader_epoch; /**< Msgset leader epoch */
        rd_kafkap_bytes_t bytes;
        /* Space for bytes.data is allocated after the msgset_t */
} rd_kafka_mock_msgset_t;


/**
 * @struct Committed offset for a group and partition.
 */
typedef struct rd_kafka_mock_committed_offset_s {
        /**< mpart.committed_offsets */
        TAILQ_ENTRY(rd_kafka_mock_committed_offset_s) link;
        char *group;               /**< Allocated along with the struct */
        int64_t offset;            /**< Committed offset */
        rd_kafkap_str_t *metadata; /**< Metadata, allocated separately */
} rd_kafka_mock_committed_offset_t;

/**
 * @struct Leader id and epoch to return in a Metadata call.
 */
typedef struct rd_kafka_mock_partition_leader_s {
        /**< Link to prev/next entries */
        TAILQ_ENTRY(rd_kafka_mock_partition_leader_s) link;
        int32_t leader_id;    /**< Leader id */
        int32_t leader_epoch; /**< Leader epoch */
} rd_kafka_mock_partition_leader_t;


TAILQ_HEAD(rd_kafka_mock_msgset_tailq_s, rd_kafka_mock_msgset_s);

/**
 * @struct Mock partition
 */
typedef struct rd_kafka_mock_partition_s {
        TAILQ_ENTRY(rd_kafka_mock_partition_s) leader_link;
        int32_t id;

        int32_t leader_epoch;          /**< Leader epoch, bumped on each
                                        *   partition leader change. */
        int64_t start_offset;          /**< Actual/leader start offset */
        int64_t end_offset;            /**< Actual/leader end offset */
        int64_t follower_start_offset; /**< Follower's start offset */
        int64_t follower_end_offset;   /**< Follower's end offset */
        rd_bool_t update_follower_start_offset; /**< Keep follower_start_offset
                                                 *   in synch with start_offset
                                                 */
        rd_bool_t update_follower_end_offset;   /**< Keep follower_end_offset
                                                 *   in synch with end_offset
                                                 */

        struct rd_kafka_mock_msgset_tailq_s msgsets;
        size_t size;     /**< Total size of all .msgsets */
        size_t cnt;      /**< Total count of .msgsets */
        size_t max_size; /**< Maximum size of all .msgsets, may be overshot. */
        size_t max_cnt;  /**< Maximum number of .msgsets */

        /**< Committed offsets */
        TAILQ_HEAD(, rd_kafka_mock_committed_offset_s) committed_offsets;

        rd_kafka_mock_broker_t *leader;
        rd_kafka_mock_broker_t **replicas;
        int replica_cnt;

        rd_list_t pidstates; /**< PID states */

        /** Aborted transaction ranges for read_committed filtering */
        TAILQ_HEAD(, rd_kafka_mock_aborted_txn_s) aborted_txns;

        /** Last Stable Offset: offset of first open transaction.
         *  If no open transactions, lso == end_offset. */
        int64_t lso;

        int32_t follower_id; /**< Preferred replica/follower */

        struct rd_kafka_mock_topic_s *topic;

        /**< Leader responses */
        TAILQ_HEAD(, rd_kafka_mock_partition_leader_s)
        leader_responses;

        /**< Per-ApiKey request error stack.
         *   Pushed via RD_KAFKA_MOCK_CMD_PART_PUSH_REQUEST_ERRORS and
         *   popped by the protocol request handlers.
         *   Only accessed from the mock cluster thread, no locks needed. */
        rd_kafka_mock_error_stack_head_t errstacks;
} rd_kafka_mock_partition_t;


/**
 * @struct Mock topic
 */
typedef struct rd_kafka_mock_topic_s {
        TAILQ_ENTRY(rd_kafka_mock_topic_s) link;
        char *name;
        rd_kafka_Uuid_t id;

        rd_kafka_mock_partition_t *partitions;
        int partition_cnt;

        rd_kafka_resp_err_t err; /**< Error to return in protocol requests
                                  *   for this topic. */

        struct rd_kafka_mock_cluster_s *cluster;
} rd_kafka_mock_topic_t;

/**
 * @struct Explicitly set coordinator.
 */
typedef struct rd_kafka_mock_coord_s {
        TAILQ_ENTRY(rd_kafka_mock_coord_s) link;
        rd_kafka_coordtype_t type;
        char *key;
        int32_t broker_id;
} rd_kafka_mock_coord_t;


typedef void(rd_kafka_mock_io_handler_t)(
    struct rd_kafka_mock_cluster_s *mcluster,
    rd_socket_t fd,
    int events,
    void *opaque);

struct rd_kafka_mock_api_handler {
        int16_t MinVersion;
        int16_t MaxVersion;
        int16_t FlexVersion; /**< First Flexible version */
        int (*cb)(rd_kafka_mock_connection_t *mconn, rd_kafka_buf_t *rkbuf);
};

extern const struct rd_kafka_mock_api_handler
    rd_kafka_mock_api_handlers[RD_KAFKAP__NUM];



/**
 * @struct Mock cluster.
 *
 * The cluster IO loop runs in a separate thread where all
 * broker IO is handled.
 *
 * No locking is needed.
 */
struct rd_kafka_mock_cluster_s {
        char id[32]; /**< Generated cluster id */

        rd_kafka_t *rk;

        int32_t controller_id; /**< Current controller */

        TAILQ_HEAD(, rd_kafka_mock_broker_s) brokers;
        int broker_cnt;

        TAILQ_HEAD(, rd_kafka_mock_topic_s) topics;
        int topic_cnt;

        TAILQ_HEAD(, rd_kafka_mock_cgrp_classic_s) cgrps_classic;

        TAILQ_HEAD(, rd_kafka_mock_cgrp_consumer_s) cgrps_consumer;

        TAILQ_HEAD(, rd_kafka_mock_sharegroup_s) sharegrps;

        /** Explicit coordinators (set with mock_set_coordinator()) */
        TAILQ_HEAD(, rd_kafka_mock_coord_s) coords;

        /** Current transactional producer PIDs.
         *  Element type is a malloced rd_kafka_mock_pid_t*. */
        rd_list_t pids;

        /** Active transactions by TransactionalId. */
        TAILQ_HEAD(, rd_kafka_mock_txn_s) transactions;

        char *bootstraps; /**< bootstrap.servers */

        thrd_t thread; /**< Mock thread */

        rd_kafka_q_t *ops; /**< Control ops queue for interacting with the
                            *   cluster. */

        rd_socket_t wakeup_fds[2]; /**< Wake-up fds for use with .ops */

        rd_bool_t run; /**< Cluster will run while this value is true */

        int fd_cnt;         /**< Number of file descriptors */
        int fd_size;        /**< Allocated size of .fds
                             *   and .handlers */
        struct pollfd *fds; /**< Dynamic array */

        rd_kafka_broker_t *dummy_rkb; /**< Some internal librdkafka APIs
                                       *   that we are reusing requires a
                                       *   broker object, we use the
                                       *   internal broker and store it
                                       *   here for convenient access. */

        struct {
                int partition_cnt;      /**< Auto topic create part cnt */
                int replication_factor; /**< Auto topic create repl factor */
                /** Group initial rebalance delay */
                int32_t group_initial_rebalance_delay_ms;
                /** Session timeout (KIP 848) */
                int group_consumer_session_timeout_ms;
                /** Heartbeat interval (KIP 848) */
                int group_consumer_heartbeat_interval_ms;
                /** Session timeout */
                int sharegroup_session_timeout_ms;
                /** Heartbeat interval */
                int sharegroup_heartbeat_interval_ms;
                /** Max delivery attempts per record.
                 *  0 = unlimited. */
                int sharegroup_max_delivery_attempts;
                /** Per-record lock duration in ms.
                 *  0 = use session_timeout_ms. */
                int sharegroup_record_lock_duration_ms;
                /** Share isolation level.
                 *  0 = read_uncommitted, 1 = read_committed. */
                int sharegroup_isolation_level;
                /** Max members allowed in share group.
                 *  0 = unlimited. */
                int sharegroup_max_size;
                /** Max fetch sessions per broker.
                 *  0 = unlimited. */
                int sharegroup_max_fetch_sessions;
                /** Max acquired record locks per share-partition.
                 *  0 = unlimited. */
                int sharegroup_max_record_locks;
                /** Auto offset reset.
                 *  0 = latest (default), 1 = earliest. */
                int sharegroup_auto_offset_reset;
        } defaults;

        /**< Dynamic array of IO handlers for corresponding fd in .fds */
        struct {
                rd_kafka_mock_io_handler_t *cb; /**< Callback */
                void *opaque;                   /**< Callbacks' opaque */
        } *handlers;

        /**< Per-protocol request error stack. */
        rd_kafka_mock_error_stack_head_t errstacks;

        /**< Request handlers */
        struct rd_kafka_mock_api_handler api_handlers[RD_KAFKAP__NUM];

        /** Requested metrics. */
        char **metrics;

        /** Requested metric count. */
        size_t metrics_cnt;

        /** Telemetry push interval ms. Default is 5 min */
        int64_t telemetry_push_interval_ms;

        /**< Appends the requests received to mock cluster if set to true,
         *   defaulted to false for less memory usage. */
        rd_bool_t track_requests;
        /**< List of API requests for this broker. Type:
         *   rd_kafka_mock_request_t*
         */
        rd_list_t request_list;

        /**< Mutex for:
         *   .errstacks
         *   .apiversions
         *   .track_requests
         *   .request_list
         */
        mtx_t lock;

        rd_kafka_timers_t timers; /**< Timers */
};



rd_kafka_buf_t *rd_kafka_mock_buf_new_response(const rd_kafka_buf_t *request);

#define rd_kafka_mock_connection_send_response(mconn, resp)                    \
        rd_kafka_mock_connection_send_response0(mconn, resp, rd_false)

void rd_kafka_mock_connection_send_response0(rd_kafka_mock_connection_t *mconn,
                                             rd_kafka_buf_t *resp,
                                             rd_bool_t tags_written);
void rd_kafka_mock_connection_set_blocking(rd_kafka_mock_connection_t *mconn,
                                           rd_bool_t blocking);

rd_kafka_mock_partition_t *
rd_kafka_mock_partition_find(const rd_kafka_mock_topic_t *mtopic,
                             int32_t partition);
rd_kafka_mock_topic_t *
rd_kafka_mock_topic_auto_create(rd_kafka_mock_cluster_t *mcluster,
                                const char *topic,
                                int partition_cnt,
                                rd_kafka_resp_err_t *errp);
rd_kafka_mock_topic_t *
rd_kafka_mock_topic_find(const rd_kafka_mock_cluster_t *mcluster,
                         const char *name);
rd_kafka_mock_topic_t *
rd_kafka_mock_topic_find_by_kstr(const rd_kafka_mock_cluster_t *mcluster,
                                 const rd_kafkap_str_t *kname);

rd_kafka_mock_topic_t *
rd_kafka_mock_topic_find_by_id(const rd_kafka_mock_cluster_t *mcluster,
                               rd_kafka_Uuid_t id);

void rd_kafka_mock_sgrp_fetch_session_destroy(
    rd_kafka_mock_sgrp_fetch_session_t *session);
rd_kafka_resp_err_t rd_kafka_mock_sgrp_session_validate(
    rd_kafka_mock_sharegroup_t *sgrp,
    const rd_kafkap_str_t *MemberId,
    int32_t NodeId,
    int32_t SessionEpoch,
    rd_kafka_mock_sgrp_fetch_session_t **sessionp,
    const char *api_name);
void rd_kafka_mock_sgrp_record_release(
    rd_kafka_mock_sharegroup_t *mshgrp,
    rd_kafka_mock_sgrp_partmeta_t *pmeta,
    rd_kafka_mock_sgrp_record_state_t *state);
void rd_kafka_mock_sgrp_release_session_locks(
    rd_kafka_mock_sharegroup_t *mshgrp,
    const rd_kafka_mock_sgrp_fetch_session_t *session);
void rd_kafka_mock_sgrp_fetch_session_tmr_cb(rd_kafka_timers_t *rkts,
                                             void *arg);

rd_kafka_mock_broker_t *
rd_kafka_mock_cluster_get_coord(rd_kafka_mock_cluster_t *mcluster,
                                rd_kafka_coordtype_t KeyType,
                                const rd_kafkap_str_t *Key);

rd_kafka_mock_committed_offset_t *
rd_kafka_mock_committed_offset_find(const rd_kafka_mock_partition_t *mpart,
                                    const rd_kafkap_str_t *group);
rd_kafka_mock_committed_offset_t *
rd_kafka_mock_commit_offset(rd_kafka_mock_partition_t *mpart,
                            const rd_kafkap_str_t *group,
                            int64_t offset,
                            const rd_kafkap_str_t *metadata);

const rd_kafka_mock_msgset_t *
rd_kafka_mock_msgset_find(const rd_kafka_mock_partition_t *mpart,
                          int64_t offset,
                          rd_bool_t on_follower);

rd_kafka_resp_err_t
rd_kafka_mock_next_request_error(rd_kafka_mock_connection_t *mconn,
                                 rd_kafka_buf_t *resp);

rd_kafka_resp_err_t
rd_kafka_mock_partition_next_request_error(rd_kafka_mock_partition_t *mpart,
                                           int16_t ApiKey);

rd_kafka_resp_err_t
rd_kafka_mock_partition_log_append(rd_kafka_mock_partition_t *mpart,
                                   const rd_kafkap_bytes_t *records,
                                   const rd_kafkap_str_t *TransactionalId,
                                   int64_t *BaseOffset);

rd_kafka_resp_err_t rd_kafka_mock_partition_leader_epoch_check(
    const rd_kafka_mock_partition_t *mpart,
    int32_t leader_epoch);

/* Transaction helpers */
rd_kafka_mock_txn_t *
rd_kafka_mock_txn_get(rd_kafka_mock_cluster_t *mcluster,
                      const rd_kafkap_str_t *TransactionalId);
void rd_kafka_mock_txn_partition_add(rd_kafka_mock_txn_t *mtxn,
                                     const char *topic,
                                     int32_t partition);
void rd_kafka_mock_txn_partitions_clear(rd_kafka_mock_txn_t *mtxn);
void rd_kafka_mock_partition_update_lso(rd_kafka_mock_partition_t *mpart,
                                        rd_kafka_mock_cluster_t *mcluster);
void rd_kafka_mock_partition_write_control_batch(
    rd_kafka_mock_partition_t *mpart,
    rd_kafka_pid_t pid,
    rd_bool_t committed);

int64_t rd_kafka_mock_partition_offset_for_leader_epoch(
    const rd_kafka_mock_partition_t *mpart,
    int32_t leader_epoch);

rd_kafka_mock_partition_leader_t *
rd_kafka_mock_partition_next_leader_response(rd_kafka_mock_partition_t *mpart);

void rd_kafka_mock_partition_leader_destroy(
    rd_kafka_mock_partition_t *mpart,
    rd_kafka_mock_partition_leader_t *mpart_leader);


/**
 * @returns true if the ApiVersion is supported, else false.
 */
static RD_UNUSED rd_bool_t
rd_kafka_mock_cluster_ApiVersion_check(const rd_kafka_mock_cluster_t *mcluster,
                                       int16_t ApiKey,
                                       int16_t ApiVersion) {
        return (ApiVersion >= mcluster->api_handlers[ApiKey].MinVersion &&
                ApiVersion <= mcluster->api_handlers[ApiKey].MaxVersion);
}


rd_kafka_resp_err_t
rd_kafka_mock_pid_find(rd_kafka_mock_cluster_t *mcluster,
                       const rd_kafkap_str_t *TransactionalId,
                       const rd_kafka_pid_t pid,
                       rd_kafka_mock_pid_t **mpidp);


/**
 * @name Mock consumer group (rdkafka_mock_cgrp.c)
 * @{
 */
void rd_kafka_mock_cgrp_classic_member_active(
    rd_kafka_mock_cgrp_classic_t *mcgrp,
    rd_kafka_mock_cgrp_classic_member_t *member);
void rd_kafka_mock_cgrp_classic_member_assignment_set(
    rd_kafka_mock_cgrp_classic_t *mcgrp,
    rd_kafka_mock_cgrp_classic_member_t *member,
    const rd_kafkap_bytes_t *Metadata);
rd_kafka_resp_err_t rd_kafka_mock_cgrp_classic_member_sync_set(
    rd_kafka_mock_cgrp_classic_t *mcgrp,
    rd_kafka_mock_cgrp_classic_member_t *member,
    rd_kafka_mock_connection_t *mconn,
    rd_kafka_buf_t *resp);
rd_kafka_resp_err_t rd_kafka_mock_cgrp_classic_member_leave(
    rd_kafka_mock_cgrp_classic_t *mcgrp,
    rd_kafka_mock_cgrp_classic_member_t *member);
void rd_kafka_mock_cgrp_classic_protos_destroy(
    rd_kafka_mock_cgrp_classic_proto_t *protos,
    int proto_cnt);
rd_kafka_resp_err_t rd_kafka_mock_cgrp_classic_member_add(
    rd_kafka_mock_cgrp_classic_t *mcgrp,
    rd_kafka_mock_connection_t *mconn,
    rd_kafka_buf_t *resp,
    const rd_kafkap_str_t *MemberId,
    const rd_kafkap_str_t *GroupInstanceId,
    const rd_kafkap_str_t *ProtocolType,
    rd_kafka_mock_cgrp_classic_proto_t *protos,
    int proto_cnt,
    int session_timeout_ms);
rd_kafka_resp_err_t rd_kafka_mock_cgrp_classic_check_state(
    rd_kafka_mock_cgrp_classic_t *mcgrp,
    rd_kafka_mock_cgrp_classic_member_t *member,
    const rd_kafka_buf_t *request,
    int32_t generation_id);
rd_kafka_mock_cgrp_classic_member_t *rd_kafka_mock_cgrp_classic_member_find(
    const rd_kafka_mock_cgrp_classic_t *mcgrp,
    const rd_kafkap_str_t *MemberId);
void rd_kafka_mock_cgrp_classic_destroy(rd_kafka_mock_cgrp_classic_t *mcgrp);
rd_kafka_mock_cgrp_classic_t *
rd_kafka_mock_cgrp_classic_find(rd_kafka_mock_cluster_t *mcluster,
                                const rd_kafkap_str_t *GroupId);
rd_kafka_mock_cgrp_classic_t *
rd_kafka_mock_cgrp_classic_get(rd_kafka_mock_cluster_t *mcluster,
                               const rd_kafkap_str_t *GroupId,
                               const rd_kafkap_str_t *ProtocolType);

/* "consumer" consumer group (KIP-848) */

rd_kafka_topic_partition_list_t *
rd_kafka_mock_cgrp_consumer_member_next_assignment(
    rd_kafka_mock_cgrp_consumer_member_t *member,
    rd_kafka_topic_partition_list_t *current_assignment,
    int *member_epoch);

void rd_kafka_mock_cgrp_consumer_member_active(
    rd_kafka_mock_cgrp_consumer_t *mcgrp,
    rd_kafka_mock_cgrp_consumer_member_t *member);

void rd_kafka_mock_cgrp_consumer_destroy(rd_kafka_mock_cgrp_consumer_t *mcgrp);

rd_kafka_mock_cgrp_consumer_t *
rd_kafka_mock_cgrp_consumer_find(const rd_kafka_mock_cluster_t *mcluster,
                                 const rd_kafkap_str_t *GroupId);

rd_kafka_mock_cgrp_consumer_t *
rd_kafka_mock_cgrp_consumer_get(rd_kafka_mock_cluster_t *mcluster,
                                const rd_kafkap_str_t *GroupId);

void rd_kafka_mock_cgrp_consumer_member_leave(
    rd_kafka_mock_cgrp_consumer_t *mcgrp,
    rd_kafka_mock_cgrp_consumer_member_t *member,
    rd_bool_t static_leave);

void rd_kafka_mock_cgrp_consumer_member_fenced(
    rd_kafka_mock_cgrp_consumer_t *mcgrp,
    rd_kafka_mock_cgrp_consumer_member_t *member);

rd_kafka_mock_cgrp_consumer_member_t *rd_kafka_mock_cgrp_consumer_member_find(
    const rd_kafka_mock_cgrp_consumer_t *mcgrp,
    const rd_kafkap_str_t *MemberId);

rd_kafka_mock_cgrp_consumer_member_t *rd_kafka_mock_cgrp_consumer_member_add(
    rd_kafka_mock_cgrp_consumer_t *mcgrp,
    struct rd_kafka_mock_connection_s *conn,
    const rd_kafkap_str_t *MemberId,
    const rd_kafkap_str_t *InstanceId,
    rd_kafkap_str_t *SubscribedTopicNames,
    int32_t SubscribedTopicNamesCnt,
    const rd_kafkap_str_t *SubscribedTopicRegex);

void rd_kafka_mock_cgrps_connection_closed(rd_kafka_mock_cluster_t *mcluster,
                                           rd_kafka_mock_connection_t *mconn);

/* Share group */

void rd_kafka_mock_sharegrps_init(rd_kafka_mock_cluster_t *mcluster);

rd_kafka_mock_sharegroup_t *
rd_kafka_mock_sharegroup_find(rd_kafka_mock_cluster_t *mcluster,
                              const rd_kafkap_str_t *GroupId);

rd_kafka_mock_sharegroup_t *
rd_kafka_mock_sharegroup_get(rd_kafka_mock_cluster_t *mcluster,
                             const rd_kafkap_str_t *GroupId);

void rd_kafka_mock_sharegroup_destroy(rd_kafka_mock_sharegroup_t *mshgrp);

rd_kafka_mock_sharegroup_member_t *
rd_kafka_mock_sharegroup_member_find(rd_kafka_mock_sharegroup_t *mshgrp,
                                     const rd_kafkap_str_t *MemberId);

void rd_kafka_mock_sharegroup_member_destroy(
    rd_kafka_mock_sharegroup_t *mshgrp,
    rd_kafka_mock_sharegroup_member_t *member);

void rd_kafka_mock_sharegroup_member_active(
    rd_kafka_mock_sharegroup_t *mshgrp,
    rd_kafka_mock_sharegroup_member_t *member);

rd_kafka_mock_sharegroup_member_t *
rd_kafka_mock_sharegroup_member_get(rd_kafka_mock_sharegroup_t *mshgrp,
                                    const rd_kafkap_str_t *MemberID,
                                    int32_t MemberEpoch,
                                    rd_kafka_mock_connection_t *mconn);

rd_bool_t rd_kafka_mock_sharegroup_member_subscribed_topic_names_set(
    rd_kafka_mock_sharegroup_member_t *member,
    const rd_kafkap_str_t *SubscribedTopicNames,
    int32_t SubscribedTopicNamesCnt);

void rd_kafka_mock_sharegroup_assignment_recalculate(
    rd_kafka_mock_sharegroup_t *mshgrp);

void rd_kafka_mock_sharegrps_connection_closed(
    rd_kafka_mock_cluster_t *mcluster,
    rd_kafka_mock_connection_t *mconn);
void rd_kafka_mock_sharegrps_node_connection_closed(
    rd_kafka_mock_cluster_t *mcluster,
    int32_t node_id);

/**
 *@}
 */


#include "rdkafka_mock.h"

#endif /* _RDKAFKA_MOCK_INT_H_ */
