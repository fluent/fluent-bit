/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2015 Magnus Edenhill
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
#ifndef _RDKAFKA_PARTITION_H_
#define _RDKAFKA_PARTITION_H_

#include "rdkafka_topic.h"
#include "rdkafka_cgrp.h"
#include "rdkafka_broker.h"

extern const char *rd_kafka_fetch_states[];


/**
 * @brief Offset statistics
 */
struct offset_stats {
        int64_t fetch_offset; /**< Next offset to fetch */
        int64_t eof_offset;   /**< Last offset we reported EOF for */
        int64_t hi_offset;    /**< Current broker hi offset */
};

/**
 * @brief Reset offset_stats struct to default values
 */
static RD_UNUSED void rd_kafka_offset_stats_reset (struct offset_stats *offs) {
        offs->fetch_offset = 0;
        offs->eof_offset = RD_KAFKA_OFFSET_INVALID;
        offs->hi_offset = RD_KAFKA_OFFSET_INVALID;
}



/**
 * Topic + Partition combination
 */
struct rd_kafka_toppar_s { /* rd_kafka_toppar_t */
	TAILQ_ENTRY(rd_kafka_toppar_s) rktp_rklink;  /* rd_kafka_t link */
	TAILQ_ENTRY(rd_kafka_toppar_s) rktp_rkblink; /* rd_kafka_broker_t link*/
        CIRCLEQ_ENTRY(rd_kafka_toppar_s) rktp_activelink; /* rkb_active_toppars */
	TAILQ_ENTRY(rd_kafka_toppar_s) rktp_rktlink; /* rd_kafka_itopic_t link*/
        TAILQ_ENTRY(rd_kafka_toppar_s) rktp_cgrplink;/* rd_kafka_cgrp_t link */
        rd_kafka_itopic_t       *rktp_rkt;
        shptr_rd_kafka_itopic_t *rktp_s_rkt;  /* shared pointer for rktp_rkt */
	int32_t            rktp_partition;
        //LOCK: toppar_lock() + topic_wrlock()
        //LOCK: .. in partition_available()
        int32_t            rktp_leader_id;   /**< Current leader broker id.
                                              *   This is updated directly
                                              *   from metadata. */
	rd_kafka_broker_t *rktp_leader;      /**< Current leader broker
                                              *   This updated asynchronously
                                              *   by issuing JOIN op to
                                              *   broker thread, so be careful
                                              *   in using this since it
                                              *   may lag. */
        rd_kafka_broker_t *rktp_next_leader; /**< Next leader broker after
                                              *   async migration op. */
	rd_refcnt_t        rktp_refcnt;
	mtx_t              rktp_lock;

        //LOCK: toppar_lock. toppar_insert_msg(), concat_msgq()
        //LOCK: toppar_lock. toppar_enq_msg(), deq_msg(), toppar_retry_msgq()
        int                rktp_msgq_wakeup_fd; /* Wake-up fd */
	rd_kafka_msgq_t    rktp_msgq;      /* application->rdkafka queue.
					    * protected by rktp_lock */
        rd_kafka_msgq_t    rktp_xmit_msgq; /* internal broker xmit queue.
                                            * local to broker thread. */

        int                rktp_fetch;     /* On rkb_active_toppars list */

	/* Consumer */
	rd_kafka_q_t      *rktp_fetchq;          /* Queue of fetched messages
						  * from broker.
                                                  * Broker thread -> App */
        rd_kafka_q_t      *rktp_ops;             /* * -> Main thread */

        uint64_t           rktp_msgseq;     /* Current message sequence number.
                                             * Each message enqueued on a
                                             * non-UA partition will get a
                                             * unique sequencial number assigned.
                                             * This number is used to
                                             * re-enqueue the message
                                             * on resends but making sure
                                             * the input ordering is still
                                             * maintained.
                                             * Starts at 1. */

	/**
	 * rktp version barriers
	 *
	 * rktp_version is the application/controller side's
	 * authoritative version, it depicts the most up to date state.
	 * This is what q_filter() matches an rko_version to.
	 *
	 * rktp_op_version is the last/current received state handled
	 * by the toppar in the broker thread. It is updated to rktp_version
	 * when receiving a new op.
	 *
	 * rktp_fetch_version is the current fetcher decision version.
	 * It is used in fetch_decide() to see if the fetch decision
	 * needs to be updated by comparing to rktp_op_version.
	 *
	 * Example:
	 *   App thread   : Send OP_START (v1 bump): rktp_version=1
	 *   Broker thread: Recv OP_START (v1): rktp_op_version=1
	 *   Broker thread: fetch_decide() detects that
	 *                  rktp_op_version != rktp_fetch_version and
	 *                  sets rktp_fetch_version=1.
	 *   Broker thread: next Fetch request has it's tver state set to
	 *                  rktp_fetch_verison (v1).
	 *
	 *   App thread   : Send OP_SEEK (v2 bump): rktp_version=2
	 *   Broker thread: Recv OP_SEEK (v2): rktp_op_version=2
	 *   Broker thread: Recv IO FetchResponse with tver=1,
	 *                  when enqueued on rktp_fetchq they're discarded
	 *                  due to old version (tver<rktp_version).
	 *   Broker thread: fetch_decide() detects version change and
	 *                  sets rktp_fetch_version=2.
	 *   Broker thread: next Fetch request has tver=2
	 *   Broker thread: Recv IO FetchResponse with tver=2 which
	 *                  is same as rktp_version so message is forwarded
	 *                  to app.
	 */
        rd_atomic32_t      rktp_version;         /* Latest op version.
                                                  * Authoritative (app thread)*/
	int32_t            rktp_op_version;      /* Op version of curr command
						  * state from.
						  * (broker thread) */
        int32_t            rktp_fetch_version;   /* Op version of curr fetch.
                                                    (broker thread) */

	enum {
		RD_KAFKA_TOPPAR_FETCH_NONE = 0,
                RD_KAFKA_TOPPAR_FETCH_STOPPING,
                RD_KAFKA_TOPPAR_FETCH_STOPPED,
		RD_KAFKA_TOPPAR_FETCH_OFFSET_QUERY,
		RD_KAFKA_TOPPAR_FETCH_OFFSET_WAIT,
		RD_KAFKA_TOPPAR_FETCH_ACTIVE,
	} rktp_fetch_state;           /* Broker thread's state */

#define RD_KAFKA_TOPPAR_FETCH_IS_STARTED(fetch_state) \
        ((fetch_state) >= RD_KAFKA_TOPPAR_FETCH_OFFSET_QUERY)

	int32_t            rktp_fetch_msg_max_bytes; /* Max number of bytes to
                                                      * fetch.
                                                      * Locality: broker thread
                                                      */

        rd_ts_t            rktp_ts_fetch_backoff; /* Back off fetcher for
                                                   * this partition until this
                                                   * absolute timestamp
                                                   * expires. */

	int64_t            rktp_query_offset;    /* Offset to query broker for*/
	int64_t            rktp_next_offset;     /* Next offset to start
                                                  * fetching from.
                                                  * Locality: toppar thread */
	int64_t            rktp_last_next_offset; /* Last next_offset handled
						   * by fetch_decide().
						   * Locality: broker thread */
        int64_t            rktp_app_offset;      /* Last offset delivered to
                                                  * application + 1.
                                                  * Is reset to INVALID_OFFSET
                                                  * when partition is
                                                  * unassigned/stopped. */
	int64_t            rktp_stored_offset;   /* Last stored offset, but
						  * maybe not committed yet. */
        int64_t            rktp_committing_offset; /* Offset currently being
                                                    * committed */
	int64_t            rktp_committed_offset; /* Last committed offset */
	rd_ts_t            rktp_ts_committed_offset; /* Timestamp of last
                                                      * commit */

        struct offset_stats rktp_offsets; /* Current offsets.
                                           * Locality: broker thread*/
        struct offset_stats rktp_offsets_fin; /* Finalized offset for stats.
                                               * Updated periodically
                                               * by broker thread.
                                               * Locks: toppar_lock */

	int64_t rktp_hi_offset;              /* Current high offset.
					      * Locks: toppar_lock */
        int64_t rktp_lo_offset;              /* Current broker low offset.
                                              * This is outside of the stats
                                              * struct due to this field
                                              * being populated by the
                                              * toppar thread rather than
                                              * the broker thread.
                                              * Locality: toppar thread
                                              * Locks: toppar_lock */

        rd_ts_t            rktp_ts_offset_lag;

	char              *rktp_offset_path;     /* Path to offset file */
	FILE              *rktp_offset_fp;       /* Offset file pointer */
        rd_kafka_cgrp_t   *rktp_cgrp;            /* Belongs to this cgrp */

        int                rktp_assigned;   /* Partition in cgrp assignment */

        rd_kafka_replyq_t  rktp_replyq; /* Current replyq+version
					 * for propagating
					 * major operations, e.g.,
					 * FETCH_STOP. */
        //LOCK: toppar_lock().  RD_KAFKA_TOPPAR_F_DESIRED
        //LOCK: toppar_lock().  RD_KAFKA_TOPPAR_F_UNKNOWN
	int                rktp_flags;
#define RD_KAFKA_TOPPAR_F_DESIRED  0x1      /* This partition is desired
					     * by a consumer. */
#define RD_KAFKA_TOPPAR_F_UNKNOWN  0x2      /* Topic is not yet or no longer
                                             * seen on a broker. */
#define RD_KAFKA_TOPPAR_F_OFFSET_STORE 0x4  /* Offset store is active */
#define RD_KAFKA_TOPPAR_F_OFFSET_STORE_STOPPING 0x8 /* Offset store stopping */
#define RD_KAFKA_TOPPAR_F_APP_PAUSE  0x10   /* App pause()d consumption */
#define RD_KAFKA_TOPPAR_F_LIB_PAUSE  0x20   /* librdkafka paused consumption */
#define RD_KAFKA_TOPPAR_F_REMOVE     0x40   /* partition removed from cluster */
#define RD_KAFKA_TOPPAR_F_LEADER_ERR 0x80   /* Operation failed:
                                             * leader might be missing.
                                             * Typically set from
                                             * ProduceResponse failure. */

        shptr_rd_kafka_toppar_t *rktp_s_for_desp; /* Shared pointer for
                                                   * rkt_desp list */
        shptr_rd_kafka_toppar_t *rktp_s_for_cgrp; /* Shared pointer for
                                                   * rkcg_toppars list */
        shptr_rd_kafka_toppar_t *rktp_s_for_rkb;  /* Shared pointer for
                                                   * rkb_toppars list */

	/*
	 * Timers
	 */
	rd_kafka_timer_t rktp_offset_query_tmr;  /* Offset query timer */
	rd_kafka_timer_t rktp_offset_commit_tmr; /* Offset commit timer */
	rd_kafka_timer_t rktp_offset_sync_tmr;   /* Offset file sync timer */
        rd_kafka_timer_t rktp_consumer_lag_tmr;  /* Consumer lag monitoring
						  * timer */

        int rktp_wait_consumer_lag_resp;         /* Waiting for consumer lag
                                                  * response. */

        struct {
                rd_atomic64_t tx_msgs;       /**< Producer: sent messages */
                rd_atomic64_t tx_msg_bytes;  /**<  .. bytes */
                rd_atomic64_t rx_msgs;       /**< Consumer: received messages */
                rd_atomic64_t rx_msg_bytes;  /**<  .. bytes */
                rd_atomic64_t producer_enq_msgs; /**< Producer: enqueued msgs */
                rd_atomic64_t rx_ver_drops;  /**< Consumer: outdated message
                                              *             drops. */
        } rktp_c;

};


/**
 * Check if toppar is paused (consumer).
 * Locks: toppar_lock() MUST be held.
 */
#define RD_KAFKA_TOPPAR_IS_PAUSED(rktp)				\
	((rktp)->rktp_flags & (RD_KAFKA_TOPPAR_F_APP_PAUSE |	\
			       RD_KAFKA_TOPPAR_F_LIB_PAUSE))




/* Converts a shptr..toppar_t to a toppar_t */
#define rd_kafka_toppar_s2i(s_rktp) rd_shared_ptr_obj(s_rktp)


/**
 * Returns a shared pointer for the topic.
 */
#define rd_kafka_toppar_keep(rktp)                                      \
        rd_shared_ptr_get(rktp, &(rktp)->rktp_refcnt, shptr_rd_kafka_toppar_t)

#define rd_kafka_toppar_keep_src(func,line,rktp)			\
        rd_shared_ptr_get_src(func, line, rktp,				\
			      &(rktp)->rktp_refcnt, shptr_rd_kafka_toppar_t)


/**
 * Frees a shared pointer previously returned by ..toppar_keep()
 */
#define rd_kafka_toppar_destroy(s_rktp)                                 \
        rd_shared_ptr_put(s_rktp,                                       \
                          &rd_kafka_toppar_s2i(s_rktp)->rktp_refcnt,    \
                          rd_kafka_toppar_destroy_final(                \
                                  rd_kafka_toppar_s2i(s_rktp)))




#define rd_kafka_toppar_lock(rktp)     mtx_lock(&(rktp)->rktp_lock)
#define rd_kafka_toppar_unlock(rktp)   mtx_unlock(&(rktp)->rktp_lock)

static const char *rd_kafka_toppar_name (const rd_kafka_toppar_t *rktp)
	RD_UNUSED;
static const char *rd_kafka_toppar_name (const rd_kafka_toppar_t *rktp) {
	static RD_TLS char ret[256];

	rd_snprintf(ret, sizeof(ret), "%.*s [%"PRId32"]",
		    RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
		    rktp->rktp_partition);

	return ret;
}
shptr_rd_kafka_toppar_t *rd_kafka_toppar_new0 (rd_kafka_itopic_t *rkt,
					       int32_t partition,
					       const char *func, int line);
#define rd_kafka_toppar_new(rkt,partition) \
	rd_kafka_toppar_new0(rkt, partition, __FUNCTION__, __LINE__)
void rd_kafka_toppar_destroy_final (rd_kafka_toppar_t *rktp);
void rd_kafka_toppar_purge_queues (rd_kafka_toppar_t *rktp);
void rd_kafka_toppar_set_fetch_state (rd_kafka_toppar_t *rktp,
                                      int fetch_state);
void rd_kafka_toppar_insert_msg (rd_kafka_toppar_t *rktp, rd_kafka_msg_t *rkm);
void rd_kafka_toppar_enq_msg (rd_kafka_toppar_t *rktp, rd_kafka_msg_t *rkm);
void rd_kafka_toppar_deq_msg (rd_kafka_toppar_t *rktp, rd_kafka_msg_t *rkm);
int rd_kafka_retry_msgq (rd_kafka_msgq_t *destq,
                         rd_kafka_msgq_t *srcq,
                         int incr_retry, int max_retries, rd_ts_t backoff,
                         int (*cmp) (const void *a, const void *b));
void rd_kafka_msgq_insert_msgq (rd_kafka_msgq_t *destq,
                                rd_kafka_msgq_t *srcq,
                                int (*cmp) (const void *a, const void *b));
int  rd_kafka_toppar_retry_msgq (rd_kafka_toppar_t *rktp,
                                 rd_kafka_msgq_t *rkmq,
                                 int incr_retry);
void rd_kafka_toppar_insert_msgq (rd_kafka_toppar_t *rktp,
                                  rd_kafka_msgq_t *rkmq);
void rd_kafka_toppar_enq_error (rd_kafka_toppar_t *rktp,
                                rd_kafka_resp_err_t err,
                                const char *reason);
shptr_rd_kafka_toppar_t *rd_kafka_toppar_get0 (const char *func, int line,
                                               const rd_kafka_itopic_t *rkt,
                                               int32_t partition,
                                               int ua_on_miss);
#define rd_kafka_toppar_get(rkt,partition,ua_on_miss) \
        rd_kafka_toppar_get0(__FUNCTION__,__LINE__,rkt,partition,ua_on_miss)
shptr_rd_kafka_toppar_t *rd_kafka_toppar_get2 (rd_kafka_t *rk,
                                               const char *topic,
                                               int32_t partition,
                                               int ua_on_miss,
                                               int create_on_miss);
shptr_rd_kafka_toppar_t *
rd_kafka_toppar_get_avail (const rd_kafka_itopic_t *rkt,
                           int32_t partition,
                           int ua_on_miss,
                           rd_kafka_resp_err_t *errp);

shptr_rd_kafka_toppar_t *rd_kafka_toppar_desired_get (rd_kafka_itopic_t *rkt,
                                                      int32_t partition);
void rd_kafka_toppar_desired_add0 (rd_kafka_toppar_t *rktp);
shptr_rd_kafka_toppar_t *rd_kafka_toppar_desired_add (rd_kafka_itopic_t *rkt,
                                                      int32_t partition);
void rd_kafka_toppar_desired_link (rd_kafka_toppar_t *rktp);
void rd_kafka_toppar_desired_unlink (rd_kafka_toppar_t *rktp);
void rd_kafka_toppar_desired_del (rd_kafka_toppar_t *rktp);

void rd_kafka_toppar_next_offset_handle (rd_kafka_toppar_t *rktp,
                                         int64_t Offset);

void rd_kafka_toppar_offset_commit (rd_kafka_toppar_t *rktp, int64_t offset,
				    const char *metadata);

void rd_kafka_toppar_broker_delegate (rd_kafka_toppar_t *rktp,
				      rd_kafka_broker_t *rkb,
				      int for_removal);


rd_kafka_resp_err_t rd_kafka_toppar_op_fetch_start (rd_kafka_toppar_t *rktp,
                                                    int64_t offset,
                                                    rd_kafka_q_t *fwdq,
                                                    rd_kafka_replyq_t replyq);

rd_kafka_resp_err_t rd_kafka_toppar_op_fetch_stop (rd_kafka_toppar_t *rktp,
                                                   rd_kafka_replyq_t replyq);

rd_kafka_resp_err_t rd_kafka_toppar_op_seek (rd_kafka_toppar_t *rktp,
                                             int64_t offset,
                                             rd_kafka_replyq_t replyq);

rd_kafka_resp_err_t rd_kafka_toppar_op_pause (rd_kafka_toppar_t *rktp,
					      int pause, int flag);

void rd_kafka_toppar_fetch_stopped (rd_kafka_toppar_t *rktp,
                                    rd_kafka_resp_err_t err);



rd_ts_t rd_kafka_toppar_fetch_decide (rd_kafka_toppar_t *rktp,
                                      rd_kafka_broker_t *rkb,
                                      int force_remove);



rd_ts_t rd_kafka_broker_consumer_toppar_serve (rd_kafka_broker_t *rkb,
                                               rd_kafka_toppar_t *rktp);


void rd_kafka_toppar_offset_fetch (rd_kafka_toppar_t *rktp,
                                   rd_kafka_replyq_t replyq);

void rd_kafka_toppar_offset_request (rd_kafka_toppar_t *rktp,
				     int64_t query_offset, int backoff_ms);


rd_kafka_assignor_t *
rd_kafka_assignor_find (rd_kafka_t *rk, const char *protocol);


rd_kafka_broker_t *rd_kafka_toppar_leader (rd_kafka_toppar_t *rktp,
                                           int proper_broker);
void rd_kafka_toppar_leader_unavailable (rd_kafka_toppar_t *rktp,
                                         const char *reason,
                                         rd_kafka_resp_err_t err);

rd_kafka_resp_err_t
rd_kafka_toppars_pause_resume (rd_kafka_t *rk, int pause, int flag,
			       rd_kafka_topic_partition_list_t *partitions);


rd_kafka_topic_partition_t *rd_kafka_topic_partition_new (const char *topic,
							  int32_t partition);
rd_kafka_topic_partition_t *
rd_kafka_topic_partition_new_from_rktp (rd_kafka_toppar_t *rktp);

rd_kafka_topic_partition_t *
rd_kafka_topic_partition_list_add0 (rd_kafka_topic_partition_list_t *rktparlist,
                                    const char *topic, int32_t partition,
				    shptr_rd_kafka_toppar_t *_private);

rd_kafka_topic_partition_t *
rd_kafka_topic_partition_list_upsert (
        rd_kafka_topic_partition_list_t *rktparlist,
        const char *topic, int32_t partition);

int rd_kafka_topic_partition_match (rd_kafka_t *rk,
				    const rd_kafka_group_member_t *rkgm,
				    const rd_kafka_topic_partition_t *rktpar,
				    const char *topic, int *matched_by_regex);


void rd_kafka_topic_partition_list_sort_by_topic (
        rd_kafka_topic_partition_list_t *rktparlist);

void
rd_kafka_topic_partition_list_reset_offsets (rd_kafka_topic_partition_list_t *rktparlist,
					     int64_t offset);

int rd_kafka_topic_partition_list_set_offsets (
	rd_kafka_t *rk,
        rd_kafka_topic_partition_list_t *rktparlist,
        int from_rktp, int64_t def_value, int is_commit);

int rd_kafka_topic_partition_list_count_abs_offsets (
	const rd_kafka_topic_partition_list_t *rktparlist);

shptr_rd_kafka_toppar_t *
rd_kafka_topic_partition_get_toppar (rd_kafka_t *rk,
                                     rd_kafka_topic_partition_t *rktpar);

shptr_rd_kafka_toppar_t *
rd_kafka_topic_partition_list_get_toppar (
        rd_kafka_t *rk, rd_kafka_topic_partition_t *rktpar);

void
rd_kafka_topic_partition_list_update_toppars (rd_kafka_t *rk,
                                              rd_kafka_topic_partition_list_t
                                              *rktparlist);

int
rd_kafka_topic_partition_list_get_leaders (
        rd_kafka_t *rk,
        rd_kafka_topic_partition_list_t *rktparlist,
        rd_list_t *leaders, rd_list_t *query_topics);

rd_kafka_resp_err_t
rd_kafka_topic_partition_list_query_leaders (
        rd_kafka_t *rk,
        rd_kafka_topic_partition_list_t *rktparlist,
        rd_list_t *leaders, int timeout_ms);

int
rd_kafka_topic_partition_list_get_topics (
        rd_kafka_t *rk,
        rd_kafka_topic_partition_list_t *rktparlist,
        rd_list_t *rkts);

int
rd_kafka_topic_partition_list_get_topic_names (
        const rd_kafka_topic_partition_list_t *rktparlist,
        rd_list_t *topics, int include_regex);

void
rd_kafka_topic_partition_list_log (rd_kafka_t *rk, const char *fac, int dbg,
				   const rd_kafka_topic_partition_list_t *rktparlist);

#define RD_KAFKA_FMT_F_OFFSET    0x1  /* Print offset */
#define RD_KAFKA_FMT_F_ONLY_ERR  0x2  /* Only include errored entries */
#define RD_KAFKA_FMT_F_NO_ERR    0x4  /* Dont print error string */
const char *
rd_kafka_topic_partition_list_str (const rd_kafka_topic_partition_list_t *rktparlist,
                                   char *dest, size_t dest_size,
                                   int fmt_flags);

void
rd_kafka_topic_partition_list_update (rd_kafka_topic_partition_list_t *dst,
                                      const rd_kafka_topic_partition_list_t *src);

int rd_kafka_topic_partition_leader_cmp (const void *_a, const void *_b);

rd_kafka_topic_partition_list_t *rd_kafka_topic_partition_list_match (
        const rd_kafka_topic_partition_list_t *rktparlist,
        int (*match) (const void *elem, const void *opaque),
        void *opaque);

size_t
rd_kafka_topic_partition_list_sum (
        const rd_kafka_topic_partition_list_t *rktparlist,
        size_t (*cb) (const rd_kafka_topic_partition_t *rktpar, void *opaque),
        void *opaque);

void rd_kafka_topic_partition_list_set_err (
        rd_kafka_topic_partition_list_t *rktparlist,
        rd_kafka_resp_err_t err);

int rd_kafka_topic_partition_list_regex_cnt (
        const rd_kafka_topic_partition_list_t *rktparlist);

/**
 * @brief Toppar + Op version tuple used for mapping Fetched partitions
 *        back to their fetch versions.
 */
struct rd_kafka_toppar_ver {
	shptr_rd_kafka_toppar_t *s_rktp;
	int32_t version;
};


/**
 * @brief Toppar + Op version comparator.
 */
static RD_INLINE RD_UNUSED
int rd_kafka_toppar_ver_cmp (const void *_a, const void *_b) {
	const struct rd_kafka_toppar_ver *a = _a, *b = _b;
	const rd_kafka_toppar_t *rktp_a = rd_kafka_toppar_s2i(a->s_rktp);
	const rd_kafka_toppar_t *rktp_b = rd_kafka_toppar_s2i(b->s_rktp);
	int r;

	if (rktp_a->rktp_rkt != rktp_b->rktp_rkt &&
	    (r = rd_kafkap_str_cmp(rktp_a->rktp_rkt->rkt_topic,
				   rktp_b->rktp_rkt->rkt_topic)))
		return r;

	return rktp_a->rktp_partition - rktp_b->rktp_partition;
}

/**
 * @brief Frees up resources for \p tver but not the \p tver itself.
 */
static RD_INLINE RD_UNUSED
void rd_kafka_toppar_ver_destroy (struct rd_kafka_toppar_ver *tver) {
	rd_kafka_toppar_destroy(tver->s_rktp);
}


/**
 * @returns 1 if rko version is outdated, else 0.
 */
static RD_INLINE RD_UNUSED
int rd_kafka_op_version_outdated (rd_kafka_op_t *rko, int version) {
	if (!rko->rko_version)
		return 0;

	if (version)
		return rko->rko_version < version;

	if (rko->rko_rktp)
		return rko->rko_version <
			rd_atomic32_get(&rd_kafka_toppar_s2i(
						rko->rko_rktp)->rktp_version);
	return 0;
}

void
rd_kafka_toppar_offset_commit_result (rd_kafka_toppar_t *rktp,
				      rd_kafka_resp_err_t err,
				      rd_kafka_topic_partition_list_t *offsets);

void rd_kafka_toppar_broker_leave_for_remove (rd_kafka_toppar_t *rktp);


/**
 * @brief Represents a leader and the partitions it is leader for.
 */
struct rd_kafka_partition_leader {
        rd_kafka_broker_t *rkb;
        rd_kafka_topic_partition_list_t *partitions;
};

static RD_UNUSED void
rd_kafka_partition_leader_destroy (struct rd_kafka_partition_leader *leader) {
        rd_kafka_broker_destroy(leader->rkb);
        rd_kafka_topic_partition_list_destroy(leader->partitions);
        rd_free(leader);
}

static RD_UNUSED struct rd_kafka_partition_leader *
rd_kafka_partition_leader_new (rd_kafka_broker_t *rkb) {
        struct rd_kafka_partition_leader *leader = rd_malloc(sizeof(*leader));
        leader->rkb = rkb;
        rd_kafka_broker_keep(rkb);
        leader->partitions = rd_kafka_topic_partition_list_new(0);
        return leader;
}

static RD_UNUSED
int rd_kafka_partition_leader_cmp (const void *_a, const void *_b) {
        const struct rd_kafka_partition_leader *a = _a, *b = _b;
        return rd_kafka_broker_cmp(a->rkb, b->rkb);
}

#endif /* _RDKAFKA_PARTITION_H_ */
