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
#include "rdkafka_int.h"
#include "rdkafka_topic.h"
#include "rdkafka_broker.h"
#include "rdkafka_request.h"
#include "rdkafka_offset.h"
#include "rdkafka_partition.h"
#include "rdregex.h"
#include "rdports.h"  /* rd_qsort_r() */

const char *rd_kafka_fetch_states[] = {
	"none",
        "stopping",
        "stopped",
	"offset-query",
	"offset-wait",
	"active"
};


static rd_kafka_op_res_t
rd_kafka_toppar_op_serve (rd_kafka_t *rk,
                          rd_kafka_q_t *rkq, rd_kafka_op_t *rko,
                          rd_kafka_q_cb_type_t cb_type, void *opaque);

static void rd_kafka_toppar_offset_retry (rd_kafka_toppar_t *rktp,
                                          int backoff_ms,
                                          const char *reason);


static RD_INLINE int32_t
rd_kafka_toppar_version_new_barrier0 (rd_kafka_toppar_t *rktp,
				     const char *func, int line) {
	int32_t version = rd_atomic32_add(&rktp->rktp_version, 1);
	rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "BARRIER",
		     "%s [%"PRId32"]: %s:%d: new version barrier v%"PRId32,
		     rktp->rktp_rkt->rkt_topic->str, rktp->rktp_partition,
		     func, line, version);
	return version;
}

#define rd_kafka_toppar_version_new_barrier(rktp) \
	rd_kafka_toppar_version_new_barrier0(rktp, __FUNCTION__, __LINE__)


/**
 * Toppar based OffsetResponse handling.
 * This is used for updating the low water mark for consumer lag.
 */
static void rd_kafka_toppar_lag_handle_Offset (rd_kafka_t *rk,
					       rd_kafka_broker_t *rkb,
					       rd_kafka_resp_err_t err,
					       rd_kafka_buf_t *rkbuf,
					       rd_kafka_buf_t *request,
					       void *opaque) {
        shptr_rd_kafka_toppar_t *s_rktp = opaque;
        rd_kafka_toppar_t *rktp = rd_kafka_toppar_s2i(s_rktp);
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_topic_partition_t *rktpar;

        offsets = rd_kafka_topic_partition_list_new(1);

        /* Parse and return Offset */
        err = rd_kafka_handle_Offset(rkb->rkb_rk, rkb, err,
                                     rkbuf, request, offsets);

        if (err == RD_KAFKA_RESP_ERR__IN_PROGRESS) {
                rd_kafka_topic_partition_list_destroy(offsets);
                return; /* Retrying */
        }

        if (!err && !(rktpar = rd_kafka_topic_partition_list_find(
                              offsets,
                              rktp->rktp_rkt->rkt_topic->str,
                              rktp->rktp_partition)))
                err = RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;

        if (!err) {
                rd_kafka_toppar_lock(rktp);
                rktp->rktp_lo_offset = rktpar->offset;
                rd_kafka_toppar_unlock(rktp);
        }

        rd_kafka_topic_partition_list_destroy(offsets);

        rktp->rktp_wait_consumer_lag_resp = 0;

        rd_kafka_toppar_destroy(s_rktp); /* from request.opaque */
}



/**
 * Request information from broker to keep track of consumer lag.
 *
 * @locality toppar handle thread
 * @locks none
 */
static void rd_kafka_toppar_consumer_lag_req (rd_kafka_toppar_t *rktp) {
        rd_kafka_topic_partition_list_t *partitions;

        if (rktp->rktp_wait_consumer_lag_resp)
                return; /* Previous request not finished yet */

        rd_kafka_toppar_lock(rktp);

        /* Offset requests can only be sent to the leader replica.
         *
         * Note: If rktp is delegated to a preferred replica, it is
         * certain that FETCH >= v5 and so rktp_lo_offset will be
         * updated via LogStartOffset in the FETCH response.
         */
        if (!rktp->rktp_leader || (rktp->rktp_leader != rktp->rktp_broker)) {
                rd_kafka_toppar_unlock(rktp);
		return;
        }

        /* Also don't send a timed log start offset request if leader
         * broker supports FETCH >= v5, since this will be set when
         * doing fetch requests.
         */
        if (rd_kafka_broker_ApiVersion_supported(rktp->rktp_broker, 
                                                 RD_KAFKAP_Fetch, 0,
                                                 5, NULL) == 5) {
                rd_kafka_toppar_unlock(rktp);
                return;
        }

        rktp->rktp_wait_consumer_lag_resp = 1;

        partitions = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(partitions,
                                          rktp->rktp_rkt->rkt_topic->str,
                                          rktp->rktp_partition)->offset =
                                          RD_KAFKA_OFFSET_BEGINNING;

        /* Ask for oldest offset. The newest offset is automatically
         * propagated in FetchResponse.HighwaterMark. */
        rd_kafka_OffsetRequest(rktp->rktp_broker, partitions, 0,
                               RD_KAFKA_REPLYQ(rktp->rktp_ops, 0),
                               rd_kafka_toppar_lag_handle_Offset,
                               rd_kafka_toppar_keep(rktp));

        rd_kafka_toppar_unlock(rktp);

        rd_kafka_topic_partition_list_destroy(partitions);
}



/**
 * Request earliest offset for a partition
 *
 * Locality: toppar handler thread
 */
static void rd_kafka_toppar_consumer_lag_tmr_cb (rd_kafka_timers_t *rkts,
						 void *arg) {
	rd_kafka_toppar_t *rktp = arg;
	rd_kafka_toppar_consumer_lag_req(rktp);
}


/**
 * Add new partition to topic.
 *
 * Locks: rd_kafka_topic_wrlock() must be held.
 * Locks: rd_kafka_wrlock() must be held.
 */
shptr_rd_kafka_toppar_t *rd_kafka_toppar_new0 (rd_kafka_itopic_t *rkt,
					       int32_t partition,
					       const char *func, int line) {
	rd_kafka_toppar_t *rktp;

	rktp = rd_calloc(1, sizeof(*rktp));

	rktp->rktp_partition = partition;
	rktp->rktp_rkt = rkt;
        rktp->rktp_leader_id = -1;
        rktp->rktp_broker_id = -1;
        rd_interval_init(&rktp->rktp_lease_intvl);
        rd_interval_init(&rktp->rktp_new_lease_intvl);
        rd_interval_init(&rktp->rktp_new_lease_log_intvl);
        rd_interval_init(&rktp->rktp_metadata_intvl);
        /* Mark partition as unknown (does not exist) until we see the
         * partition in topic metadata. */
        if (partition != RD_KAFKA_PARTITION_UA)
                rktp->rktp_flags |= RD_KAFKA_TOPPAR_F_UNKNOWN;
	rktp->rktp_fetch_state = RD_KAFKA_TOPPAR_FETCH_NONE;
        rktp->rktp_fetch_msg_max_bytes
            = rkt->rkt_rk->rk_conf.fetch_msg_max_bytes;
	rktp->rktp_offset_fp = NULL;
        rd_kafka_offset_stats_reset(&rktp->rktp_offsets);
        rd_kafka_offset_stats_reset(&rktp->rktp_offsets_fin);
        rktp->rktp_ls_offset = RD_KAFKA_OFFSET_INVALID;
        rktp->rktp_hi_offset = RD_KAFKA_OFFSET_INVALID;
	rktp->rktp_lo_offset = RD_KAFKA_OFFSET_INVALID;
        rktp->rktp_query_offset = RD_KAFKA_OFFSET_INVALID;
        rktp->rktp_next_offset = RD_KAFKA_OFFSET_INVALID;
        rktp->rktp_last_next_offset = RD_KAFKA_OFFSET_INVALID;
	rktp->rktp_app_offset = RD_KAFKA_OFFSET_INVALID;
        rktp->rktp_stored_offset = RD_KAFKA_OFFSET_INVALID;
        rktp->rktp_committing_offset = RD_KAFKA_OFFSET_INVALID;
        rktp->rktp_committed_offset = RD_KAFKA_OFFSET_INVALID;
	rd_kafka_msgq_init(&rktp->rktp_msgq);
	rd_kafka_msgq_init(&rktp->rktp_xmit_msgq);
	mtx_init(&rktp->rktp_lock, mtx_plain);

        rd_refcnt_init(&rktp->rktp_refcnt, 0);
	rktp->rktp_fetchq = rd_kafka_q_new(rkt->rkt_rk);
        rktp->rktp_ops    = rd_kafka_q_new(rkt->rkt_rk);
        rktp->rktp_ops->rkq_serve = rd_kafka_toppar_op_serve;
        rktp->rktp_ops->rkq_opaque = rktp;
        rd_atomic32_init(&rktp->rktp_version, 1);
	rktp->rktp_op_version = rd_atomic32_get(&rktp->rktp_version);

        rd_atomic32_init(&rktp->rktp_msgs_inflight, 0);
        rd_kafka_pid_reset(&rktp->rktp_eos.pid);

        /* Consumer: If statistics is available we query the log start offset
         * of each partition.
         * Since the oldest offset only moves on log retention, we cap this
         * value on the low end to a reasonable value to avoid flooding
         * the brokers with OffsetRequests when our statistics interval is low.
         * FIXME: Use a global timer to collect offsets for all partitions
         * FIXME: This timer is superfulous for FETCH >= v5 because the log
         *        start offset is included in fetch responses.
         * */
        if (rktp->rktp_rkt->rkt_rk->rk_conf.stats_interval_ms > 0 &&
            rkt->rkt_rk->rk_type == RD_KAFKA_CONSUMER &&
            rktp->rktp_partition != RD_KAFKA_PARTITION_UA) {
                int intvl = rkt->rkt_rk->rk_conf.stats_interval_ms;
                if (intvl < 10 * 1000 /* 10s */)
                        intvl = 10 * 1000;
		rd_kafka_timer_start(&rkt->rkt_rk->rk_timers,
				     &rktp->rktp_consumer_lag_tmr,
                                     intvl * 1000ll,
				     rd_kafka_toppar_consumer_lag_tmr_cb,
				     rktp);
        }

        rktp->rktp_s_rkt = rd_kafka_topic_keep(rkt);

	rd_kafka_q_fwd_set(rktp->rktp_ops, rkt->rkt_rk->rk_ops);
	rd_kafka_dbg(rkt->rkt_rk, TOPIC, "TOPPARNEW", "NEW %s [%"PRId32"] %p (at %s:%d)",
		     rkt->rkt_topic->str, rktp->rktp_partition, rktp,
		     func, line);

	return rd_kafka_toppar_keep_src(func, line, rktp);
}



/**
 * Removes a toppar from its duties, global lists, etc.
 *
 * Locks: rd_kafka_toppar_lock() MUST be held
 */
static void rd_kafka_toppar_remove (rd_kafka_toppar_t *rktp) {
        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "TOPPARREMOVE",
                     "Removing toppar %s [%"PRId32"] %p",
                     rktp->rktp_rkt->rkt_topic->str, rktp->rktp_partition,
		     rktp);

	rd_kafka_timer_stop(&rktp->rktp_rkt->rkt_rk->rk_timers,
			    &rktp->rktp_offset_query_tmr, 1/*lock*/);
	rd_kafka_timer_stop(&rktp->rktp_rkt->rkt_rk->rk_timers,
			    &rktp->rktp_consumer_lag_tmr, 1/*lock*/);

	rd_kafka_q_fwd_set(rktp->rktp_ops, NULL);
}


/**
 * Final destructor for partition.
 */
void rd_kafka_toppar_destroy_final (rd_kafka_toppar_t *rktp) {

        rd_kafka_toppar_remove(rktp);

	rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "DESTROY",
		     "%s [%"PRId32"]: %p DESTROY_FINAL",
		     rktp->rktp_rkt->rkt_topic->str,
                     rktp->rktp_partition, rktp);

	/* Clear queues */
	rd_kafka_assert(rktp->rktp_rkt->rkt_rk,
			rd_kafka_msgq_len(&rktp->rktp_xmit_msgq) == 0);
	rd_kafka_dr_msgq(rktp->rktp_rkt, &rktp->rktp_msgq,
			 RD_KAFKA_RESP_ERR__DESTROY);
	rd_kafka_q_destroy_owner(rktp->rktp_fetchq);
        rd_kafka_q_destroy_owner(rktp->rktp_ops);

	rd_kafka_replyq_destroy(&rktp->rktp_replyq);

	rd_kafka_topic_destroy0(rktp->rktp_s_rkt);

	mtx_destroy(&rktp->rktp_lock);

        if (rktp->rktp_leader)
                rd_kafka_broker_destroy(rktp->rktp_leader);

        rd_refcnt_destroy(&rktp->rktp_refcnt);

	rd_free(rktp);
}


/**
 * Set toppar fetching state.
 *
 * Locality: broker thread
 * Locks: rd_kafka_toppar_lock() MUST be held.
 */
void rd_kafka_toppar_set_fetch_state (rd_kafka_toppar_t *rktp,
                                      int fetch_state) {
	rd_kafka_assert(NULL,
			thrd_is_current(rktp->rktp_rkt->rkt_rk->rk_thread));

        if ((int)rktp->rktp_fetch_state == fetch_state)
                return;

        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "PARTSTATE",
                     "Partition %.*s [%"PRId32"] changed fetch state %s -> %s",
                     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                     rktp->rktp_partition,
                     rd_kafka_fetch_states[rktp->rktp_fetch_state],
                     rd_kafka_fetch_states[fetch_state]);

        rktp->rktp_fetch_state = fetch_state;

        if (fetch_state == RD_KAFKA_TOPPAR_FETCH_ACTIVE)
                rd_kafka_dbg(rktp->rktp_rkt->rkt_rk,
                             CONSUMER|RD_KAFKA_DBG_TOPIC,
                             "FETCH",
                             "Partition %.*s [%"PRId32"] start fetching "
                             "at offset %s",
                             RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                             rktp->rktp_partition,
                             rd_kafka_offset2str(rktp->rktp_next_offset));
}


/**
 * Returns the appropriate toppar for a given rkt and partition.
 * The returned toppar has increased refcnt and must be unreffed by calling
 *  rd_kafka_toppar_destroy().
 * May return NULL.
 *
 * If 'ua_on_miss' is true the UA (unassigned) toppar is returned if
 * 'partition' was not known locally, else NULL is returned.
 *
 * Locks: Caller must hold rd_kafka_topic_*lock()
 */
shptr_rd_kafka_toppar_t *rd_kafka_toppar_get0 (const char *func, int line,
                                               const rd_kafka_itopic_t *rkt,
                                               int32_t partition,
                                               int ua_on_miss) {
        shptr_rd_kafka_toppar_t *s_rktp;

	if (partition >= 0 && partition < rkt->rkt_partition_cnt)
		s_rktp = rkt->rkt_p[partition];
	else if (partition == RD_KAFKA_PARTITION_UA || ua_on_miss)
		s_rktp = rkt->rkt_ua;
	else
		return NULL;

	if (s_rktp)
                return rd_kafka_toppar_keep_src(func,line,
                                                rd_kafka_toppar_s2i(s_rktp));

	return NULL;
}


/**
 * Same as rd_kafka_toppar_get() but no need for locking and
 * looks up the topic first.
 *
 * Locality: any
 * Locks: none
 */
shptr_rd_kafka_toppar_t *rd_kafka_toppar_get2 (rd_kafka_t *rk,
                                               const char *topic,
                                               int32_t partition,
                                               int ua_on_miss,
                                               int create_on_miss) {
	shptr_rd_kafka_itopic_t *s_rkt;
        rd_kafka_itopic_t *rkt;
        shptr_rd_kafka_toppar_t *s_rktp;

        rd_kafka_wrlock(rk);

        /* Find or create topic */
	if (unlikely(!(s_rkt = rd_kafka_topic_find(rk, topic, 0/*no-lock*/)))) {
                if (!create_on_miss) {
                        rd_kafka_wrunlock(rk);
                        return NULL;
                }
                s_rkt = rd_kafka_topic_new0(rk, topic, NULL,
					    NULL, 0/*no-lock*/);
                if (!s_rkt) {
                        rd_kafka_wrunlock(rk);
                        rd_kafka_log(rk, LOG_ERR, "TOPIC",
                                     "Failed to create local topic \"%s\": %s",
                                     topic, rd_strerror(errno));
                        return NULL;
                }
        }

        rd_kafka_wrunlock(rk);

        rkt = rd_kafka_topic_s2i(s_rkt);

	rd_kafka_topic_wrlock(rkt);
	s_rktp = rd_kafka_toppar_desired_add(rkt, partition);
	rd_kafka_topic_wrunlock(rkt);

        rd_kafka_topic_destroy0(s_rkt);

	return s_rktp;
}


/**
 * Returns a toppar if it is available in the cluster.
 * '*errp' is set to the error-code if lookup fails.
 *
 * Locks: topic_*lock() MUST be held
 */
shptr_rd_kafka_toppar_t *
rd_kafka_toppar_get_avail (const rd_kafka_itopic_t *rkt,
                           int32_t partition, int ua_on_miss,
                           rd_kafka_resp_err_t *errp) {
	shptr_rd_kafka_toppar_t *s_rktp;

        switch (rkt->rkt_state)
        {
        case RD_KAFKA_TOPIC_S_UNKNOWN:
                /* No metadata received from cluster yet.
                 * Put message in UA partition and re-run partitioner when
                 * cluster comes up. */
		partition = RD_KAFKA_PARTITION_UA;
                break;

        case RD_KAFKA_TOPIC_S_NOTEXISTS:
                /* Topic not found in cluster.
                 * Fail message immediately. */
                *errp = RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC;
                return NULL;

        case RD_KAFKA_TOPIC_S_EXISTS:
                /* Topic exists in cluster. */

                /* Topic exists but has no partitions.
                 * This is usually an transient state following the
                 * auto-creation of a topic. */
                if (unlikely(rkt->rkt_partition_cnt == 0)) {
                        partition = RD_KAFKA_PARTITION_UA;
                        break;
                }

                /* Check that partition exists. */
                if (partition >= rkt->rkt_partition_cnt) {
                        *errp = RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;
                        return NULL;
                }
                break;

        default:
                rd_kafka_assert(rkt->rkt_rk, !*"NOTREACHED");
                break;
        }

	/* Get new partition */
	s_rktp = rd_kafka_toppar_get(rkt, partition, 0);

	if (unlikely(!s_rktp)) {
		/* Unknown topic or partition */
		if (rkt->rkt_state == RD_KAFKA_TOPIC_S_NOTEXISTS)
			*errp = RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC;
		else
			*errp = RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;

		return NULL;
	}

	return s_rktp;
}


/**
 * Looks for partition 'i' in topic 'rkt's desired list.
 *
 * The desired partition list is the list of partitions that are desired
 * (e.g., by the consumer) but not yet seen on a broker.
 * As soon as the partition is seen on a broker the toppar is moved from
 * the desired list and onto the normal rkt_p array.
 * When the partition on the broker goes away a desired partition is put
 * back on the desired list.
 *
 * Locks: rd_kafka_topic_*lock() must be held.
 * Note: 'rktp' refcount is increased.
 */

shptr_rd_kafka_toppar_t *rd_kafka_toppar_desired_get (rd_kafka_itopic_t *rkt,
                                                      int32_t partition) {
	shptr_rd_kafka_toppar_t *s_rktp;
        int i;

	RD_LIST_FOREACH(s_rktp, &rkt->rkt_desp, i) {
                rd_kafka_toppar_t *rktp = rd_kafka_toppar_s2i(s_rktp);
		if (rktp->rktp_partition == partition)
			return rd_kafka_toppar_keep(rktp);
        }

	return NULL;
}


/**
 * Link toppar on desired list.
 *
 * Locks: rd_kafka_topic_wrlock() and toppar_lock() must be held.
 */
void rd_kafka_toppar_desired_link (rd_kafka_toppar_t *rktp) {
        shptr_rd_kafka_toppar_t *s_rktp;

        if (rktp->rktp_s_for_desp)
                return; /* Already linked */

        s_rktp = rd_kafka_toppar_keep(rktp);
        rd_list_add(&rktp->rktp_rkt->rkt_desp, s_rktp);
        rktp->rktp_s_for_desp = s_rktp; /* Desired list refcount */
}

/**
 * Unlink toppar from desired list.
 *
 * Locks: rd_kafka_topic_wrlock() and toppar_lock() must be held.
 */
void rd_kafka_toppar_desired_unlink (rd_kafka_toppar_t *rktp) {
        if (!rktp->rktp_s_for_desp)
                return; /* Not linked */

        rd_list_remove(&rktp->rktp_rkt->rkt_desp, rktp->rktp_s_for_desp);
        rd_kafka_toppar_destroy(rktp->rktp_s_for_desp);
        rktp->rktp_s_for_desp = NULL;
 }


/**
 * @brief If rktp is not already desired:
 *  - mark as DESIRED|UNKNOWN
 *  - add to desired list
 *
 * @remark toppar_lock() MUST be held
 */
void rd_kafka_toppar_desired_add0 (rd_kafka_toppar_t *rktp) {
        if ((rktp->rktp_flags & RD_KAFKA_TOPPAR_F_DESIRED))
                return;

        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "DESIRED",
                     "%s [%"PRId32"]: adding to DESIRED list",
                     rktp->rktp_rkt->rkt_topic->str, rktp->rktp_partition);
	rktp->rktp_flags |= RD_KAFKA_TOPPAR_F_DESIRED;
        rd_kafka_toppar_desired_link(rktp);
}


/**
 * Adds 'partition' as a desired partition to topic 'rkt', or updates
 * an existing partition to be desired.
 *
 * Locks: rd_kafka_topic_wrlock() must be held.
 */
shptr_rd_kafka_toppar_t *rd_kafka_toppar_desired_add (rd_kafka_itopic_t *rkt,
                                                      int32_t partition) {
	shptr_rd_kafka_toppar_t *s_rktp;
        rd_kafka_toppar_t *rktp;

	if ((s_rktp = rd_kafka_toppar_get(rkt,
                                          partition, 0/*no_ua_on_miss*/))) {
                rktp = rd_kafka_toppar_s2i(s_rktp);
		rd_kafka_toppar_lock(rktp);
                if (unlikely(!(rktp->rktp_flags & RD_KAFKA_TOPPAR_F_DESIRED))) {
                        rd_kafka_dbg(rkt->rkt_rk, TOPIC, "DESP",
                                     "Setting topic %s [%"PRId32"] partition "
                                     "as desired",
                                     rkt->rkt_topic->str, rktp->rktp_partition);
                        rktp->rktp_flags |= RD_KAFKA_TOPPAR_F_DESIRED;
                }
                /* If toppar was marked for removal this is no longer
                 * the case since the partition is now desired. */
                rktp->rktp_flags &= ~RD_KAFKA_TOPPAR_F_REMOVE;
		rd_kafka_toppar_unlock(rktp);
		return s_rktp;
	}

	if ((s_rktp = rd_kafka_toppar_desired_get(rkt, partition)))
		return s_rktp;

	s_rktp = rd_kafka_toppar_new(rkt, partition);
        rktp = rd_kafka_toppar_s2i(s_rktp);

        rd_kafka_toppar_lock(rktp);
        rd_kafka_toppar_desired_add0(rktp);
        rd_kafka_toppar_unlock(rktp);

	rd_kafka_dbg(rkt->rkt_rk, TOPIC, "DESP",
		     "Adding desired topic %s [%"PRId32"]",
		     rkt->rkt_topic->str, rktp->rktp_partition);

	return s_rktp; /* Callers refcount */
}




/**
 * Unmarks an 'rktp' as desired.
 *
 * Locks: rd_kafka_topic_wrlock() and rd_kafka_toppar_lock() MUST be held.
 */
void rd_kafka_toppar_desired_del (rd_kafka_toppar_t *rktp) {

	if (!(rktp->rktp_flags & RD_KAFKA_TOPPAR_F_DESIRED))
		return;

	rktp->rktp_flags &= ~RD_KAFKA_TOPPAR_F_DESIRED;
        rd_kafka_toppar_desired_unlink(rktp);

	rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "DESP",
		     "Removing (un)desired topic %s [%"PRId32"]",
		     rktp->rktp_rkt->rkt_topic->str, rktp->rktp_partition);

        if (rktp->rktp_flags & RD_KAFKA_TOPPAR_F_UNKNOWN) {
                /* If this partition does not exist in the cluster
                 * and is no longer desired, remove it. */
                rd_kafka_toppar_broker_leave_for_remove(rktp);
        }
}



/**
 * Append message at tail of 'rktp' message queue.
 */
void rd_kafka_toppar_enq_msg (rd_kafka_toppar_t *rktp, rd_kafka_msg_t *rkm) {
        int queue_len;
        rd_kafka_q_t *wakeup_q = NULL;

        rd_kafka_toppar_lock(rktp);

        if (!rkm->rkm_u.producer.msgid &&
            rktp->rktp_partition != RD_KAFKA_PARTITION_UA)
                rkm->rkm_u.producer.msgid = ++rktp->rktp_msgid;

        if (rktp->rktp_partition == RD_KAFKA_PARTITION_UA ||
            rktp->rktp_rkt->rkt_conf.queuing_strategy == RD_KAFKA_QUEUE_FIFO) {
                /* No need for enq_sorted(), this is the oldest message. */
                queue_len = rd_kafka_msgq_enq(&rktp->rktp_msgq, rkm);
        } else {
                queue_len = rd_kafka_msgq_enq_sorted(rktp->rktp_rkt,
                                                     &rktp->rktp_msgq, rkm);
        }

        if (unlikely(queue_len == 1 &&
                     (wakeup_q = rktp->rktp_msgq_wakeup_q)))
                rd_kafka_q_keep(wakeup_q);

        rd_kafka_toppar_unlock(rktp);

        if (wakeup_q) {
                rd_kafka_q_yield(wakeup_q, rd_true/*rate-limit*/);
                rd_kafka_q_destroy(wakeup_q);
        }
}


/**
 * @brief Insert \p srcq before \p insert_before in \p destq.
 *
 * If \p srcq and \p destq overlaps only part of the \p srcq will be inserted.
 *
 * Upon return \p srcq will contain any remaining messages that require
 * another insert position in \p destq.
 */
static void
rd_kafka_msgq_insert_msgq_before (rd_kafka_msgq_t *destq,
                                  rd_kafka_msg_t *insert_before,
                                  rd_kafka_msgq_t *srcq,
                                  int (*cmp) (const void *a, const void *b)) {
        rd_kafka_msg_t *slast;
        rd_kafka_msgq_t tmpq;

        if (!insert_before) {
                /* Append all of srcq to destq */
                rd_kafka_msgq_concat(destq, srcq);
                rd_kafka_msgq_verify_order(NULL, destq, 0, rd_false);
                return;
        }

        slast = rd_kafka_msgq_last(srcq);
        rd_dassert(slast);

        if (cmp(slast, insert_before) > 0) {
                rd_kafka_msg_t *new_sfirst;
                int cnt;
                int64_t bytes;

                /* destq insert_before resides somewhere between
                 * srcq.first and srcq.last, find the first message in
                 * srcq that is > insert_before and split srcq into
                 * a left part that contains the messages to insert before
                 * insert_before, and a right part that will need another
                 * insert position. */

                new_sfirst = rd_kafka_msgq_find_pos(srcq, NULL,
                                                    insert_before,
                                                    cmp, &cnt, &bytes);
                rd_assert(new_sfirst);

                /* split srcq into two parts using the divider message */
                rd_kafka_msgq_split(srcq, &tmpq, new_sfirst, cnt, bytes);

                rd_kafka_msgq_verify_order(NULL, srcq, 0, rd_false);
                rd_kafka_msgq_verify_order(NULL, &tmpq, 0, rd_false);
        } else {
                rd_kafka_msgq_init(&tmpq);
        }

        /* srcq now contains messages up to the first message in destq,
         * insert srcq at insert_before in destq. */
        rd_dassert(!TAILQ_EMPTY(&destq->rkmq_msgs));
        rd_dassert(!TAILQ_EMPTY(&srcq->rkmq_msgs));
        TAILQ_INSERT_LIST_BEFORE(&destq->rkmq_msgs,
                                 insert_before,
                                 &srcq->rkmq_msgs,
                                 rd_kafka_msgs_head_s,
                                 rd_kafka_msg_t *,
                                 rkm_link);
        destq->rkmq_msg_cnt   += srcq->rkmq_msg_cnt;
        destq->rkmq_msg_bytes += srcq->rkmq_msg_bytes;
        srcq->rkmq_msg_cnt     = 0;
        srcq->rkmq_msg_bytes   = 0;

        rd_kafka_msgq_verify_order(NULL, destq, 0, rd_false);
        rd_kafka_msgq_verify_order(NULL, srcq, 0, rd_false);

        /* tmpq contains the remaining messages in srcq, move it over. */
        rd_kafka_msgq_move(srcq, &tmpq);

        rd_kafka_msgq_verify_order(NULL, srcq, 0, rd_false);
}


/**
 * @brief Insert all messages from \p srcq into \p destq in their sorted
 *        position (using \p cmp)
 */
void rd_kafka_msgq_insert_msgq (rd_kafka_msgq_t *destq,
                                rd_kafka_msgq_t *srcq,
                                int (*cmp) (const void *a, const void *b)) {
        rd_kafka_msg_t *sfirst, *dlast, *start_pos = NULL;

        if (unlikely(RD_KAFKA_MSGQ_EMPTY(srcq))) {
                /* srcq is empty */
                return;
        }

        if (unlikely(RD_KAFKA_MSGQ_EMPTY(destq))) {
                /* destq is empty, simply move the srcq. */
                rd_kafka_msgq_move(destq, srcq);
                rd_kafka_msgq_verify_order(NULL, destq, 0, rd_false);
                return;
        }

        /* Optimize insertion by bulk-moving messages in place.
         * We know that:
         *  - destq is sorted but might not be continous (1,2,3,7)
         *  - srcq is sorted but might not be continous (4,5,6,8)
         *  - there migt be (multiple) overlaps between the two, e.g:
         *     destq = (1,2,3,7), srcq = (4,5,6,8)
         *  - there may be millions of messages.
         */

        rd_kafka_msgq_verify_order(NULL, destq, 0, rd_false);
        rd_kafka_msgq_verify_order(NULL, srcq, 0, rd_false);

        dlast = rd_kafka_msgq_last(destq);
        sfirst = rd_kafka_msgq_first(srcq);

        /* Most common case, all of srcq goes after destq */
        if (likely(cmp(dlast, sfirst) < 0)) {
                rd_kafka_msgq_concat(destq, srcq);

                rd_kafka_msgq_verify_order(NULL, destq, 0, rd_false);

                rd_assert(RD_KAFKA_MSGQ_EMPTY(srcq));
                return;
        }

        /* Insert messages from srcq into destq in non-overlapping
         * chunks until srcq is exhausted. */
        while (likely(sfirst != NULL)) {
                rd_kafka_msg_t *insert_before;

                /* Get insert position in destq of first element in srcq */
                insert_before = rd_kafka_msgq_find_pos(destq, start_pos,
                                                       sfirst, cmp,
                                                       NULL, NULL);

                /* Insert as much of srcq as possible at insert_before */
                rd_kafka_msgq_insert_msgq_before(destq, insert_before,
                                                 srcq, cmp);

                /* Remember the current destq position so the next find_pos()
                 * does not have to re-scan destq and what was
                 * added from srcq. */
                start_pos = insert_before;

                /* For next iteration */
                sfirst = rd_kafka_msgq_first(srcq);

                rd_kafka_msgq_verify_order(NULL, destq, 0, rd_false);
                rd_kafka_msgq_verify_order(NULL, srcq, 0, rd_false);
        }

        rd_kafka_msgq_verify_order(NULL, destq, 0, rd_false);

        rd_assert(RD_KAFKA_MSGQ_EMPTY(srcq));
}


/**
 * @brief Inserts messages from \p srcq according to their sorted position
 *        into \p destq, filtering out messages that can not be retried.
 *
 * @param incr_retry Increment retry count for messages.
 * @param max_retries Maximum retries allowed per message.
 * @param backoff Absolute retry backoff for retried messages.
 *
 * @returns 0 if all messages were retried, or 1 if some messages
 *          could not be retried.
 */
int rd_kafka_retry_msgq (rd_kafka_msgq_t *destq,
                         rd_kafka_msgq_t *srcq,
                         int incr_retry, int max_retries, rd_ts_t backoff,
                         rd_kafka_msg_status_t status,
                         int (*cmp) (const void *a, const void *b)) {
        rd_kafka_msgq_t retryable = RD_KAFKA_MSGQ_INITIALIZER(retryable);
        rd_kafka_msg_t *rkm, *tmp;

        /* Scan through messages to see which ones are eligible for retry,
         * move the retryable ones to temporary queue and
         * set backoff time for first message and optionally
         * increase retry count for each message.
         * Sorted insert is not necessary since the original order
         * srcq order is maintained. */
        TAILQ_FOREACH_SAFE(rkm, &srcq->rkmq_msgs, rkm_link, tmp) {
                if (rkm->rkm_u.producer.retries + incr_retry > max_retries)
                        continue;

                rd_kafka_msgq_deq(srcq, rkm, 1);
                rd_kafka_msgq_enq(&retryable, rkm);

                rkm->rkm_u.producer.ts_backoff = backoff;
                rkm->rkm_u.producer.retries  += incr_retry;

                /* Don't downgrade a message from any form of PERSISTED
                 * to NOT_PERSISTED, since the original cause of indicating
                 * PERSISTED can't be changed.
                 * E.g., a previous ack or in-flight timeout. */
                if (likely(!(status == RD_KAFKA_MSG_STATUS_NOT_PERSISTED &&
                             rkm->rkm_status !=
                             RD_KAFKA_MSG_STATUS_NOT_PERSISTED)))
                        rkm->rkm_status = status;
        }

        /* No messages are retryable */
        if (RD_KAFKA_MSGQ_EMPTY(&retryable))
                return 0;

        /* Insert retryable list at sorted position */
        rd_kafka_msgq_insert_msgq(destq, &retryable, cmp);

        return 1;
}

/**
 * @brief Inserts messages from \p rkmq according to their sorted position
 *        into the partition's message queue.
 *
 * @param incr_retry Increment retry count for messages.
 * @param status Set status on each message.
 *
 * @returns 0 if all messages were retried, or 1 if some messages
 *          could not be retried.
 *
 * @locality Broker thread (but not necessarily the leader broker thread)
 */

int rd_kafka_toppar_retry_msgq (rd_kafka_toppar_t *rktp, rd_kafka_msgq_t *rkmq,
                                int incr_retry, rd_kafka_msg_status_t status) {
        rd_kafka_t *rk = rktp->rktp_rkt->rkt_rk;
        rd_ts_t backoff = rd_clock() + (rk->rk_conf.retry_backoff_ms * 1000);
        int r;

        if (rd_kafka_terminating(rk))
                return 1;

        rd_kafka_toppar_lock(rktp);
        r = rd_kafka_retry_msgq(&rktp->rktp_msgq, rkmq,
                                incr_retry, rk->rk_conf.max_retries,
                                backoff, status,
                                rktp->rktp_rkt->rkt_conf.msg_order_cmp);
        rd_kafka_toppar_unlock(rktp);

        return r;
}

/**
 * @brief Insert sorted message list \p rkmq at sorted position in \p rktp 's
 *        message queue. The queues must not overlap.
 * @remark \p rkmq will be cleared.
 */
void rd_kafka_toppar_insert_msgq (rd_kafka_toppar_t *rktp,
                                  rd_kafka_msgq_t *rkmq) {
        rd_kafka_toppar_lock(rktp);
        rd_kafka_msgq_insert_msgq(&rktp->rktp_msgq, rkmq,
                                  rktp->rktp_rkt->rkt_conf.msg_order_cmp);
        rd_kafka_toppar_unlock(rktp);
}



/**
 * Helper method for purging queues when removing a toppar.
 * Locks: rd_kafka_toppar_lock() MUST be held
 */
void rd_kafka_toppar_purge_queues (rd_kafka_toppar_t *rktp) {
        rd_kafka_q_disable(rktp->rktp_fetchq);
        rd_kafka_q_purge(rktp->rktp_fetchq);
        rd_kafka_q_disable(rktp->rktp_ops);
        rd_kafka_q_purge(rktp->rktp_ops);
}


/**
 * @brief Migrate rktp from (optional) \p old_rkb to (optional) \p new_rkb,
 *        but at least one is required to be non-NULL.
 *
 * This is an async operation.
 *
 * @locks rd_kafka_toppar_lock() MUST be held
 */
static void rd_kafka_toppar_broker_migrate (rd_kafka_toppar_t *rktp,
                                            rd_kafka_broker_t *old_rkb,
                                            rd_kafka_broker_t *new_rkb) {
        rd_kafka_op_t *rko;
        rd_kafka_broker_t *dest_rkb;
        int had_next_broker = rktp->rktp_next_broker ? 1 : 0;

        rd_assert(old_rkb || new_rkb);

        /* Update next broker */
        if (new_rkb)
                rd_kafka_broker_keep(new_rkb);
        if (rktp->rktp_next_broker)
                rd_kafka_broker_destroy(rktp->rktp_next_broker);
        rktp->rktp_next_broker = new_rkb;

        /* If next_broker is set it means there is already an async
         * migration op going on and we should not send a new one
         * but simply change the next_broker (which we did above). */
        if (had_next_broker)
                return;

        /* Revert from offset-wait state back to offset-query
         * prior to leaving the broker to avoid stalling
         * on the new broker waiting for a offset reply from
         * this old broker (that might not come and thus need
         * to time out..slowly) */
        if (rktp->rktp_fetch_state == RD_KAFKA_TOPPAR_FETCH_OFFSET_WAIT)
                rd_kafka_toppar_offset_retry(rktp, 500,
                                             "migrating to new broker");

        if (old_rkb) {
                /* If there is an existing broker for this toppar we let it
                 * first handle its own leave and then trigger the join for
                 * the next broker, if any. */
                rko = rd_kafka_op_new(RD_KAFKA_OP_PARTITION_LEAVE);
                dest_rkb = old_rkb;
        } else {
                /* No existing broker, send join op directly to new broker. */
                rko = rd_kafka_op_new(RD_KAFKA_OP_PARTITION_JOIN);
                dest_rkb = new_rkb;
        }

        rko->rko_rktp = rd_kafka_toppar_keep(rktp);

        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "BRKMIGR",
                     "Migrating topic %.*s [%"PRId32"] %p from %s to %s "
		     "(sending %s to %s)",
                     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                     rktp->rktp_partition, rktp,
                     old_rkb ? rd_kafka_broker_name(old_rkb) : "(none)",
                     new_rkb ? rd_kafka_broker_name(new_rkb) : "(none)",
		     rd_kafka_op2str(rko->rko_type),
		     rd_kafka_broker_name(dest_rkb));

        rd_kafka_q_enq(dest_rkb->rkb_ops, rko);
}


/**
 * Async toppar leave from broker.
 * Only use this when partitions are to be removed.
 *
 * Locks: rd_kafka_toppar_lock() MUST be held
 */
void rd_kafka_toppar_broker_leave_for_remove (rd_kafka_toppar_t *rktp) {
        rd_kafka_op_t *rko;
        rd_kafka_broker_t *dest_rkb;

        rktp->rktp_flags |= RD_KAFKA_TOPPAR_F_REMOVE;

	if (rktp->rktp_next_broker)
		dest_rkb = rktp->rktp_next_broker;
	else if (rktp->rktp_broker)
		dest_rkb = rktp->rktp_broker;
	else {
		rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "TOPPARDEL",
			     "%.*s [%"PRId32"] %p not handled by any broker: "
			     "not sending LEAVE for remove",
			     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
			     rktp->rktp_partition, rktp);
		return;
	}


	/* Revert from offset-wait state back to offset-query
	 * prior to leaving the broker to avoid stalling
	 * on the new broker waiting for a offset reply from
	 * this old broker (that might not come and thus need
	 * to time out..slowly) */
	if (rktp->rktp_fetch_state == RD_KAFKA_TOPPAR_FETCH_OFFSET_WAIT)
		rd_kafka_toppar_set_fetch_state(
			rktp, RD_KAFKA_TOPPAR_FETCH_OFFSET_QUERY);

	rko = rd_kafka_op_new(RD_KAFKA_OP_PARTITION_LEAVE);
        rko->rko_rktp = rd_kafka_toppar_keep(rktp);

        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "BRKMIGR",
                     "%.*s [%"PRId32"] %p sending final LEAVE for removal by %s",
                     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                     rktp->rktp_partition, rktp,
                     rd_kafka_broker_name(dest_rkb));

        rd_kafka_q_enq(dest_rkb->rkb_ops, rko);
}


/**
 * @brief Delegates toppar 'rktp' to broker 'rkb'. 'rkb' may be NULL to
 *        undelegate broker.
 *
 * @locks Caller must have rd_kafka_toppar_lock(rktp) held.
 */
void rd_kafka_toppar_broker_delegate (rd_kafka_toppar_t *rktp,
				      rd_kafka_broker_t *rkb) {
        rd_kafka_t *rk = rktp->rktp_rkt->rkt_rk;
        int internal_fallback = 0;

	rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "BRKDELGT",
		     "%s [%"PRId32"]: delegate to broker %s "
		     "(rktp %p, term %d, ref %d)",
		     rktp->rktp_rkt->rkt_topic->str, rktp->rktp_partition,
		     rkb ? rkb->rkb_name : "(none)",
		     rktp, rd_kafka_terminating(rk),
		     rd_refcnt_get(&rktp->rktp_refcnt));

        /* Undelegated toppars are delgated to the internal
         * broker for bookkeeping. */
        if (!rkb && !rd_kafka_terminating(rk)) {
                rkb = rd_kafka_broker_internal(rk);
                internal_fallback = 1;
        }

	if (rktp->rktp_broker == rkb && !rktp->rktp_next_broker) {
                rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "BRKDELGT",
			     "%.*s [%"PRId32"]: not updating broker: "
                             "already on correct broker %s",
			     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
			     rktp->rktp_partition,
                             rkb ? rd_kafka_broker_name(rkb) : "(none)");

                if (internal_fallback)
                        rd_kafka_broker_destroy(rkb);
		return;
        }

	if (rktp->rktp_broker)
		rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "BRKDELGT",
			     "%.*s [%"PRId32"]: no longer delegated to "
			     "broker %s",
			     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
			     rktp->rktp_partition,
			     rd_kafka_broker_name(rktp->rktp_broker));


	if (rkb) {
		rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "BRKDELGT",
			     "%.*s [%"PRId32"]: delegating to broker %s "
			     "for partition with %i messages "
			     "(%"PRIu64" bytes) queued",
			     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
			     rktp->rktp_partition,
			     rd_kafka_broker_name(rkb),
                             rktp->rktp_msgq.rkmq_msg_cnt,
                             rktp->rktp_msgq.rkmq_msg_bytes);


	} else {
		rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "BRKDELGT",
			     "%.*s [%"PRId32"]: no broker delegated",
			     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
			     rktp->rktp_partition);
	}

        if (rktp->rktp_broker || rkb)
                rd_kafka_toppar_broker_migrate(rktp, rktp->rktp_broker, rkb);

        if (internal_fallback)
                rd_kafka_broker_destroy(rkb);
}





void
rd_kafka_toppar_offset_commit_result (rd_kafka_toppar_t *rktp,
				      rd_kafka_resp_err_t err,
				      rd_kafka_topic_partition_list_t *offsets){
	if (err) {
		rd_kafka_q_op_err(rktp->rktp_fetchq,
				  RD_KAFKA_OP_CONSUMER_ERR,
				  err, 0 /* FIXME:VERSION*/,
				  rktp, 0,
				  "Offset commit failed: %s",
				  rd_kafka_err2str(err));
		return;
	}

	rd_kafka_toppar_lock(rktp);
	rktp->rktp_committed_offset = offsets->elems[0].offset;

	/* When stopping toppars:
	 * Final commit is now done (or failed), propagate. */
	if (rktp->rktp_fetch_state == RD_KAFKA_TOPPAR_FETCH_STOPPING)
		rd_kafka_toppar_fetch_stopped(rktp, err);

	rd_kafka_toppar_unlock(rktp);
}











/**
 * Handle the next offset to consume for a toppar.
 * This is used during initial setup when trying to figure out what
 * offset to start consuming from.
 *
 * Locality: toppar handler thread.
 * Locks: toppar_lock(rktp) must be held
 */
void rd_kafka_toppar_next_offset_handle (rd_kafka_toppar_t *rktp,
                                         int64_t Offset) {

        if (RD_KAFKA_OFFSET_IS_LOGICAL(Offset)) {
                /* Offset storage returned logical offset (e.g. "end"),
                 * look it up. */

                /* Save next offset, even if logical, so that e.g.,
                 * assign(BEGINNING) survives a pause+resume, etc.
                 * See issue #2105. */
                rktp->rktp_next_offset = Offset;

                rd_kafka_offset_reset(rktp, Offset, RD_KAFKA_RESP_ERR_NO_ERROR,
                                      "update");
                return;
        }

        /* Adjust by TAIL count if, if wanted */
        if (rktp->rktp_query_offset <=
            RD_KAFKA_OFFSET_TAIL_BASE) {
                int64_t orig_Offset = Offset;
                int64_t tail_cnt =
                        llabs(rktp->rktp_query_offset -
                              RD_KAFKA_OFFSET_TAIL_BASE);

                if (tail_cnt > Offset)
                        Offset = 0;
                else
                        Offset -= tail_cnt;

                rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "OFFSET",
                             "OffsetReply for topic %s [%"PRId32"]: "
                             "offset %"PRId64": adjusting for "
                             "OFFSET_TAIL(%"PRId64"): "
                             "effective offset %"PRId64,
                             rktp->rktp_rkt->rkt_topic->str,
                             rktp->rktp_partition,
                             orig_Offset, tail_cnt,
                             Offset);
        }

        rktp->rktp_next_offset = Offset;

        rd_kafka_toppar_set_fetch_state(rktp, RD_KAFKA_TOPPAR_FETCH_ACTIVE);

        /* Wake-up broker thread which might be idling on IO */
        if (rktp->rktp_broker)
                rd_kafka_broker_wakeup(rktp->rktp_broker);

}



/**
 * Fetch stored offset for a single partition. (simple consumer)
 *
 * Locality: toppar thread
 */
void rd_kafka_toppar_offset_fetch (rd_kafka_toppar_t *rktp,
                                   rd_kafka_replyq_t replyq) {
        rd_kafka_t *rk = rktp->rktp_rkt->rkt_rk;
        rd_kafka_topic_partition_list_t *part;
        rd_kafka_op_t *rko;

        rd_kafka_dbg(rk, TOPIC, "OFFSETREQ",
                     "Partition %.*s [%"PRId32"]: querying cgrp for "
                     "stored offset (opv %d)",
                     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                     rktp->rktp_partition, replyq.version);

        part = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add0(part,
                                           rktp->rktp_rkt->rkt_topic->str,
                                           rktp->rktp_partition,
					   rd_kafka_toppar_keep(rktp));

        rko = rd_kafka_op_new(RD_KAFKA_OP_OFFSET_FETCH);
	rko->rko_rktp = rd_kafka_toppar_keep(rktp);
	rko->rko_replyq = replyq;

	rko->rko_u.offset_fetch.partitions = part;
	rko->rko_u.offset_fetch.do_free = 1;

        rd_kafka_q_enq(rktp->rktp_cgrp->rkcg_ops, rko);
}




/**
 * Toppar based OffsetResponse handling.
 * This is used for finding the next offset to Fetch.
 *
 * Locality: toppar handler thread
 */
static void rd_kafka_toppar_handle_Offset (rd_kafka_t *rk,
					   rd_kafka_broker_t *rkb,
					   rd_kafka_resp_err_t err,
					   rd_kafka_buf_t *rkbuf,
					   rd_kafka_buf_t *request,
					   void *opaque) {
        shptr_rd_kafka_toppar_t *s_rktp = opaque;
        rd_kafka_toppar_t *rktp = rd_kafka_toppar_s2i(s_rktp);
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_topic_partition_t *rktpar;
        int64_t Offset;

	rd_kafka_toppar_lock(rktp);
	/* Drop reply from previous partition leader */
	if (err != RD_KAFKA_RESP_ERR__DESTROY && rktp->rktp_broker != rkb)
		err = RD_KAFKA_RESP_ERR__OUTDATED;
	rd_kafka_toppar_unlock(rktp);

        offsets = rd_kafka_topic_partition_list_new(1);

	rd_rkb_dbg(rkb, TOPIC, "OFFSET",
		   "Offset reply for "
		   "topic %.*s [%"PRId32"] (v%d vs v%d)",
		   RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
		   rktp->rktp_partition, request->rkbuf_replyq.version,
		   rktp->rktp_op_version);

	rd_dassert(request->rkbuf_replyq.version > 0);
	if (err != RD_KAFKA_RESP_ERR__DESTROY &&
            rd_kafka_buf_version_outdated(request, rktp->rktp_op_version)) {
		/* Outdated request response, ignore. */
		    err = RD_KAFKA_RESP_ERR__OUTDATED;
	}

        if (err != RD_KAFKA_RESP_ERR__OUTDATED) {
                /* Parse and return Offset */
                err = rd_kafka_handle_Offset(rkb->rkb_rk, rkb, err,
                                             rkbuf, request, offsets);
        }

        if (!err &&
            (!(rktpar = rd_kafka_topic_partition_list_find(
                       offsets,
                       rktp->rktp_rkt->rkt_topic->str, rktp->rktp_partition))))
                err = RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;

        if (err) {
                rd_kafka_op_t *rko;

                rd_rkb_dbg(rkb, TOPIC, "OFFSET",
                           "Offset reply error for "
                           "topic %.*s [%"PRId32"] (v%d): %s",
                           RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                           rktp->rktp_partition, request->rkbuf_replyq.version,
			   rd_kafka_err2str(err));

                rd_kafka_topic_partition_list_destroy(offsets);

                if (err == RD_KAFKA_RESP_ERR__DESTROY ||
                    err == RD_KAFKA_RESP_ERR__OUTDATED) {
                        /* Termination or outdated, quick cleanup. */

                        if (err == RD_KAFKA_RESP_ERR__OUTDATED) {
                                rd_kafka_toppar_lock(rktp);
                                rd_kafka_toppar_offset_retry(
                                        rktp, 500, "outdated offset response");
                                rd_kafka_toppar_unlock(rktp);
                        }

                        /* from request.opaque */
                        rd_kafka_toppar_destroy(s_rktp);
                        return;

		} else if (err == RD_KAFKA_RESP_ERR__IN_PROGRESS)
			return; /* Retry in progress */


                rd_kafka_toppar_lock(rktp);
                rd_kafka_offset_reset(rktp, rktp->rktp_query_offset,
                                      err,
                                      "failed to query logical offset");

                /* Signal error back to application,
                 * unless this is an intermittent problem
                 * (e.g.,connection lost) */
                rko = rd_kafka_op_new(RD_KAFKA_OP_CONSUMER_ERR);
                rko->rko_err = err;
                if (rktp->rktp_query_offset <=
                    RD_KAFKA_OFFSET_TAIL_BASE)
                        rko->rko_u.err.offset =
                                rktp->rktp_query_offset -
                                RD_KAFKA_OFFSET_TAIL_BASE;
                else
                        rko->rko_u.err.offset = rktp->rktp_query_offset;
                rd_kafka_toppar_unlock(rktp);
                rko->rko_rktp = rd_kafka_toppar_keep(rktp);

                rd_kafka_q_enq(rktp->rktp_fetchq, rko);

                rd_kafka_toppar_destroy(s_rktp); /* from request.opaque */
                return;
        }

        Offset = rktpar->offset;
        rd_kafka_topic_partition_list_destroy(offsets);

	rd_kafka_toppar_lock(rktp);
        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "OFFSET",
                     "Offset %s request for %.*s [%"PRId32"] "
                     "returned offset %s (%"PRId64")",
                     rd_kafka_offset2str(rktp->rktp_query_offset),
                     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                     rktp->rktp_partition, rd_kafka_offset2str(Offset), Offset);

        rd_kafka_toppar_next_offset_handle(rktp, Offset);
	rd_kafka_toppar_unlock(rktp);

        rd_kafka_toppar_destroy(s_rktp); /* from request.opaque */
}


/**
 * @brief An Offset fetch failed (for whatever reason) in
 *        the RD_KAFKA_TOPPAR_FETCH_OFFSET_WAIT state:
 *        set the state back to FETCH_OFFSET_QUERY and start the
 *        offset_query_tmr to trigger a new request eventually.
 *
 * @locality toppar handler thread
 * @locks toppar_lock() MUST be held
 */
static void rd_kafka_toppar_offset_retry (rd_kafka_toppar_t *rktp,
                                          int backoff_ms,
                                          const char *reason) {
        rd_ts_t tmr_next;
        int restart_tmr;

        /* (Re)start timer if not started or the current timeout
         * is larger than \p backoff_ms. */
        tmr_next = rd_kafka_timer_next(&rktp->rktp_rkt->rkt_rk->rk_timers,
                                       &rktp->rktp_offset_query_tmr, 1);

        restart_tmr = (tmr_next == -1 ||
                       tmr_next > rd_clock() + (backoff_ms * 1000ll));

        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "OFFSET",
                     "%s [%"PRId32"]: %s: %s for offset %s",
                     rktp->rktp_rkt->rkt_topic->str,
                     rktp->rktp_partition,
                     reason,
                     restart_tmr ?
                     "(re)starting offset query timer" :
                     "offset query timer already scheduled",
                     rd_kafka_offset2str(rktp->rktp_query_offset));

        rd_kafka_toppar_set_fetch_state(rktp,
                                        RD_KAFKA_TOPPAR_FETCH_OFFSET_QUERY);

        if (restart_tmr)
                rd_kafka_timer_start(&rktp->rktp_rkt->rkt_rk->rk_timers,
                                     &rktp->rktp_offset_query_tmr,
                                     backoff_ms*1000ll,
                                     rd_kafka_offset_query_tmr_cb, rktp);
}



/**
 * Send OffsetRequest for toppar.
 *
 * If \p backoff_ms is non-zero only the query timer is started,
 * otherwise a query is triggered directly.
 *
 * Locality: toppar handler thread
 * Locks: toppar_lock() must be held
 */
void rd_kafka_toppar_offset_request (rd_kafka_toppar_t *rktp,
				     int64_t query_offset, int backoff_ms) {
	rd_kafka_broker_t *rkb;

	rd_kafka_assert(NULL,
			thrd_is_current(rktp->rktp_rkt->rkt_rk->rk_thread));

        rkb = rktp->rktp_broker;

        if (!backoff_ms && (!rkb || rkb->rkb_source == RD_KAFKA_INTERNAL))
                backoff_ms = 500;

        if (backoff_ms) {
                rd_kafka_toppar_offset_retry(rktp, backoff_ms,
                                             !rkb ?
                                             "no current leader for partition":
                                             "backoff");
                return;
        }


        rd_kafka_timer_stop(&rktp->rktp_rkt->rkt_rk->rk_timers,
                            &rktp->rktp_offset_query_tmr, 1/*lock*/);


	if (query_offset == RD_KAFKA_OFFSET_STORED &&
            rktp->rktp_rkt->rkt_conf.offset_store_method ==
            RD_KAFKA_OFFSET_METHOD_BROKER) {
                /*
                 * Get stored offset from broker based storage:
                 * ask cgrp manager for offsets
                 */
                rd_kafka_toppar_offset_fetch(
			rktp,
			RD_KAFKA_REPLYQ(rktp->rktp_ops,
					rktp->rktp_op_version));

	} else {
                shptr_rd_kafka_toppar_t *s_rktp;
                rd_kafka_topic_partition_list_t *offsets;

                /*
                 * Look up logical offset (end,beginning,tail,..)
                 */

                rd_rkb_dbg(rkb, TOPIC, "OFFREQ",
                           "Partition %.*s [%"PRId32"]: querying for logical "
                           "offset %s (opv %d)",
                           RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                           rktp->rktp_partition,
                           rd_kafka_offset2str(query_offset),
			   rktp->rktp_op_version);

                s_rktp = rd_kafka_toppar_keep(rktp);

		if (query_offset <= RD_KAFKA_OFFSET_TAIL_BASE)
			query_offset = RD_KAFKA_OFFSET_END;

                offsets = rd_kafka_topic_partition_list_new(1);
                rd_kafka_topic_partition_list_add(
                        offsets,
                        rktp->rktp_rkt->rkt_topic->str,
                        rktp->rktp_partition)->offset = query_offset;

                rd_kafka_OffsetRequest(rkb, offsets, 0,
                                       RD_KAFKA_REPLYQ(rktp->rktp_ops,
                                                       rktp->rktp_op_version),
                                       rd_kafka_toppar_handle_Offset,
                                       s_rktp);

                rd_kafka_topic_partition_list_destroy(offsets);
        }

        rd_kafka_toppar_set_fetch_state(rktp,
					RD_KAFKA_TOPPAR_FETCH_OFFSET_WAIT);
}


/**
 * Start fetching toppar.
 *
 * Locality: toppar handler thread
 * Locks: none
 */
static void rd_kafka_toppar_fetch_start (rd_kafka_toppar_t *rktp,
					 int64_t offset,
					 rd_kafka_op_t *rko_orig) {
        rd_kafka_cgrp_t *rkcg = rko_orig->rko_u.fetch_start.rkcg;
        rd_kafka_resp_err_t err = 0;
        int32_t version = rko_orig->rko_version;

	rd_kafka_toppar_lock(rktp);

        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "FETCH",
                     "Start fetch for %.*s [%"PRId32"] in "
                     "state %s at offset %s (v%"PRId32")",
                     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                     rktp->rktp_partition,
                     rd_kafka_fetch_states[rktp->rktp_fetch_state],
                     rd_kafka_offset2str(offset), version);

        if (rktp->rktp_fetch_state == RD_KAFKA_TOPPAR_FETCH_STOPPING) {
                err = RD_KAFKA_RESP_ERR__PREV_IN_PROGRESS;
		rd_kafka_toppar_unlock(rktp);
                goto err_reply;
        }

	rktp->rktp_op_version = version;

        if (rkcg) {
                rd_kafka_assert(rktp->rktp_rkt->rkt_rk, !rktp->rktp_cgrp);
                /* Attach toppar to cgrp */
                rktp->rktp_cgrp = rkcg;
                rd_kafka_cgrp_op(rkcg, rktp, RD_KAFKA_NO_REPLYQ,
                                 RD_KAFKA_OP_PARTITION_JOIN, 0);
        }


        if (offset == RD_KAFKA_OFFSET_BEGINNING ||
	    offset == RD_KAFKA_OFFSET_END ||
            offset <= RD_KAFKA_OFFSET_TAIL_BASE) {
		rd_kafka_toppar_next_offset_handle(rktp, offset);

	} else if (offset == RD_KAFKA_OFFSET_STORED) {
                rd_kafka_offset_store_init(rktp);

	} else if (offset == RD_KAFKA_OFFSET_INVALID) {
		rd_kafka_offset_reset(rktp, offset,
				      RD_KAFKA_RESP_ERR__NO_OFFSET,
				      "no previously committed offset "
				      "available");

	} else {
		rktp->rktp_next_offset = offset;
                rd_kafka_toppar_set_fetch_state(rktp,
						RD_KAFKA_TOPPAR_FETCH_ACTIVE);

                /* Wake-up broker thread which might be idling on IO */
                if (rktp->rktp_broker)
                        rd_kafka_broker_wakeup(rktp->rktp_broker);

	}

        rktp->rktp_offsets_fin.eof_offset = RD_KAFKA_OFFSET_INVALID;

	rd_kafka_toppar_unlock(rktp);

        /* Signal back to caller thread that start has commenced, or err */
err_reply:
        if (rko_orig->rko_replyq.q) {
                rd_kafka_op_t *rko;

                rko = rd_kafka_op_new(RD_KAFKA_OP_FETCH_START);

                rko->rko_err = err;
                rko->rko_rktp = rd_kafka_toppar_keep(rktp);

                rd_kafka_replyq_enq(&rko_orig->rko_replyq, rko, 0);
        }
}




/**
 * Mark toppar's fetch state as stopped (all decommissioning is done,
 * offsets are stored, etc).
 *
 * Locality: toppar handler thread
 * Locks: toppar_lock(rktp) MUST be held
 */
void rd_kafka_toppar_fetch_stopped (rd_kafka_toppar_t *rktp,
                                    rd_kafka_resp_err_t err) {


        rd_kafka_toppar_set_fetch_state(rktp, RD_KAFKA_TOPPAR_FETCH_STOPPED);

        rktp->rktp_app_offset = RD_KAFKA_OFFSET_INVALID;

        if (rktp->rktp_cgrp) {
                /* Detach toppar from cgrp */
                rd_kafka_cgrp_op(rktp->rktp_cgrp, rktp, RD_KAFKA_NO_REPLYQ,
                                 RD_KAFKA_OP_PARTITION_LEAVE, 0);
                rktp->rktp_cgrp = NULL;
        }

        /* Signal back to application thread that stop is done. */
	if (rktp->rktp_replyq.q) {
		rd_kafka_op_t *rko;
		rko = rd_kafka_op_new(RD_KAFKA_OP_FETCH_STOP|RD_KAFKA_OP_REPLY);
                rko->rko_err = err;
		rko->rko_rktp = rd_kafka_toppar_keep(rktp);

		rd_kafka_replyq_enq(&rktp->rktp_replyq, rko, 0);
	}
}


/**
 * Stop toppar fetcher.
 * This is usually an async operation.
 *
 * Locality: toppar handler thread
 */
void rd_kafka_toppar_fetch_stop (rd_kafka_toppar_t *rktp,
				 rd_kafka_op_t *rko_orig) {
        int32_t version = rko_orig->rko_version;

	rd_kafka_toppar_lock(rktp);

        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "FETCH",
                     "Stopping fetch for %.*s [%"PRId32"] in state %s (v%d)",
                     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                     rktp->rktp_partition,
                     rd_kafka_fetch_states[rktp->rktp_fetch_state], version);

	rktp->rktp_op_version = version;

	/* Abort pending offset lookups. */
	if (rktp->rktp_fetch_state == RD_KAFKA_TOPPAR_FETCH_OFFSET_QUERY)
		rd_kafka_timer_stop(&rktp->rktp_rkt->rkt_rk->rk_timers,
				    &rktp->rktp_offset_query_tmr,
				    1/*lock*/);

        /* Clear out the forwarding queue. */
        rd_kafka_q_fwd_set(rktp->rktp_fetchq, NULL);

        /* Assign the future replyq to propagate stop results. */
        rd_kafka_assert(rktp->rktp_rkt->rkt_rk, rktp->rktp_replyq.q == NULL);
        rktp->rktp_replyq = rko_orig->rko_replyq;
        rd_kafka_replyq_clear(&rko_orig->rko_replyq);

        rd_kafka_toppar_set_fetch_state(rktp, RD_KAFKA_TOPPAR_FETCH_STOPPING);

        /* Stop offset store (possibly async).
         * NOTE: will call .._stopped() if store finishes immediately,
         *       so no more operations after this call! */
        rd_kafka_offset_store_stop(rktp);

	rd_kafka_toppar_unlock(rktp);
}


/**
 * Update a toppars offset.
 * The toppar must have been previously FETCH_START:ed
 *
 * Locality: toppar handler thread
 */
void rd_kafka_toppar_seek (rd_kafka_toppar_t *rktp,
			   int64_t offset, rd_kafka_op_t *rko_orig) {
        rd_kafka_resp_err_t err = 0;
        int32_t version = rko_orig->rko_version;

	rd_kafka_toppar_lock(rktp);

        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "FETCH",
                     "Seek %.*s [%"PRId32"] to offset %s "
                     "in state %s (v%"PRId32")",
                     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                     rktp->rktp_partition,
		     rd_kafka_offset2str(offset),
                     rd_kafka_fetch_states[rktp->rktp_fetch_state], version);


        if (rktp->rktp_fetch_state == RD_KAFKA_TOPPAR_FETCH_STOPPING) {
                err = RD_KAFKA_RESP_ERR__PREV_IN_PROGRESS;
                goto err_reply;
        } else if (!RD_KAFKA_TOPPAR_FETCH_IS_STARTED(rktp->rktp_fetch_state)) {
                err = RD_KAFKA_RESP_ERR__STATE;
                goto err_reply;
        } else if (offset == RD_KAFKA_OFFSET_STORED) {
		err = RD_KAFKA_RESP_ERR__INVALID_ARG;
		goto err_reply;
	}

	rktp->rktp_op_version = version;

	/* Abort pending offset lookups. */
	if (rktp->rktp_fetch_state == RD_KAFKA_TOPPAR_FETCH_OFFSET_QUERY)
		rd_kafka_timer_stop(&rktp->rktp_rkt->rkt_rk->rk_timers,
				    &rktp->rktp_offset_query_tmr,
				    1/*lock*/);

	if (RD_KAFKA_OFFSET_IS_LOGICAL(offset))
		rd_kafka_toppar_next_offset_handle(rktp, offset);
	else {
		rktp->rktp_next_offset = offset;
                rd_kafka_toppar_set_fetch_state(rktp,
						RD_KAFKA_TOPPAR_FETCH_ACTIVE);

                /* Wake-up broker thread which might be idling on IO */
                if (rktp->rktp_broker)
                        rd_kafka_broker_wakeup(rktp->rktp_broker);
	}

        /* Signal back to caller thread that seek has commenced, or err */
err_reply:
	rd_kafka_toppar_unlock(rktp);

        if (rko_orig->rko_replyq.q) {
                rd_kafka_op_t *rko;

                rko = rd_kafka_op_new(RD_KAFKA_OP_SEEK|RD_KAFKA_OP_REPLY);

                rko->rko_err = err;
		rko->rko_u.fetch_start.offset =
			rko_orig->rko_u.fetch_start.offset;
                rko->rko_rktp = rd_kafka_toppar_keep(rktp);

                rd_kafka_replyq_enq(&rko_orig->rko_replyq, rko, 0);
        }
}


static void rd_kafka_toppar_pause_resume (rd_kafka_toppar_t *rktp,
					  rd_kafka_op_t *rko_orig) {
	rd_kafka_t *rk = rktp->rktp_rkt->rkt_rk;
	int pause = rko_orig->rko_u.pause.pause;
	int flag = rko_orig->rko_u.pause.flag;
        int32_t version = rko_orig->rko_version;

	rd_kafka_toppar_lock(rktp);

	rktp->rktp_op_version = version;

	if (pause) {
		/* Pause partition */
		rktp->rktp_flags |= flag;

		if (rk->rk_type == RD_KAFKA_CONSUMER) {
			/* Save offset of last consumed message+1 as the
			 * next message to fetch on resume. */
			if (rktp->rktp_app_offset != RD_KAFKA_OFFSET_INVALID) {
				rktp->rktp_next_offset = rktp->rktp_app_offset;
			}

			rd_kafka_dbg(rk, TOPIC, pause?"PAUSE":"RESUME",
				     "%s %s [%"PRId32"]: at offset %s "
				     "(state %s, v%d)",
				     pause ? "Pause":"Resume",
				     rktp->rktp_rkt->rkt_topic->str,
				     rktp->rktp_partition,
				     rd_kafka_offset2str(
					     rktp->rktp_next_offset),
				     rd_kafka_fetch_states[rktp->
							   rktp_fetch_state],
				     version);
		} else {
			rd_kafka_dbg(rk, TOPIC, pause?"PAUSE":"RESUME",
				     "%s %s [%"PRId32"] (state %s, v%d)",
				     pause ? "Pause":"Resume",
				     rktp->rktp_rkt->rkt_topic->str,
				     rktp->rktp_partition,
				     rd_kafka_fetch_states[rktp->
							   rktp_fetch_state],
				     version);
			}

	} else {
		/* Resume partition */
		rktp->rktp_flags &= ~flag;

		if (rk->rk_type == RD_KAFKA_CONSUMER) {
			rd_kafka_dbg(rk, TOPIC, pause?"PAUSE":"RESUME",
				     "%s %s [%"PRId32"]: at offset %s "
				     "(state %s, v%d)",
				     rktp->rktp_fetch_state ==
				     RD_KAFKA_TOPPAR_FETCH_ACTIVE ?
				     "Resuming" : "Not resuming stopped",
				     rktp->rktp_rkt->rkt_topic->str,
				     rktp->rktp_partition,
				     rd_kafka_offset2str(
					     rktp->rktp_next_offset),
				     rd_kafka_fetch_states[rktp->
							   rktp_fetch_state],
				     version);

			/* If the resuming offset is logical we
			 * need to trigger a seek (that performs the
			 * logical->absolute lookup logic) to get
			 * things going.
			 * Typical case is when a partition is paused
			 * before anything has been consumed by app
			 * yet thus having rktp_app_offset=INVALID. */
			if ((rktp->rktp_fetch_state ==
			     RD_KAFKA_TOPPAR_FETCH_ACTIVE ||
			     rktp->rktp_fetch_state ==
			     RD_KAFKA_TOPPAR_FETCH_OFFSET_WAIT) &&
			    rktp->rktp_next_offset == RD_KAFKA_OFFSET_INVALID)
				rd_kafka_toppar_next_offset_handle(
					rktp, rktp->rktp_next_offset);

		} else
			rd_kafka_dbg(rk, TOPIC, pause?"PAUSE":"RESUME",
				     "%s %s [%"PRId32"] (state %s, v%d)",
				     pause ? "Pause":"Resume",
				     rktp->rktp_rkt->rkt_topic->str,
				     rktp->rktp_partition,
				     rd_kafka_fetch_states[rktp->
							   rktp_fetch_state],
				     version);
	}
	rd_kafka_toppar_unlock(rktp);

	if (pause && rk->rk_type == RD_KAFKA_CONSUMER) {
		/* Flush partition's fetch queue */
		rd_kafka_q_purge_toppar_version(rktp->rktp_fetchq, rktp,
						rko_orig->rko_version);
	}
}




/**
 * @brief Decide whether this toppar should be on the fetch list or not.
 *
 * Also:
 *  - update toppar's op version (for broker thread's copy)
 *  - finalize statistics (move rktp_offsets to rktp_offsets_fin)
 *
 * @returns the partition's Fetch backoff timestamp, or 0 if no backoff.
 *
 * @locality broker thread
 * @locks none
 */
rd_ts_t rd_kafka_toppar_fetch_decide (rd_kafka_toppar_t *rktp,
				   rd_kafka_broker_t *rkb,
				   int force_remove) {
        int should_fetch = 1;
        const char *reason = "";
        int32_t version;
        rd_ts_t ts_backoff = 0;
        rd_bool_t lease_expired = rd_false;

        rd_kafka_toppar_lock(rktp);

        /* Check for preferred replica lease expiry */
        lease_expired =
                rktp->rktp_leader_id != rktp->rktp_broker_id &&
                rd_interval(&rktp->rktp_lease_intvl,
                            5*60*1000*1000/*5 minutes*/, 0) > 0;
        if (lease_expired) {
                /* delete_to_leader() requires no locks to be held */
                rd_kafka_toppar_unlock(rktp);
                rd_kafka_toppar_delegate_to_leader(rktp);
                rd_kafka_toppar_lock(rktp);

                reason = "preferred replica lease expired";
                should_fetch = 0;
                goto done;
        }

	/* Forced removal from fetch list */
	if (unlikely(force_remove)) {
		reason = "forced removal";
		should_fetch = 0;
		goto done;
	}

	if (unlikely((rktp->rktp_flags & RD_KAFKA_TOPPAR_F_REMOVE) != 0)) {
		reason = "partition removed";
		should_fetch = 0;
		goto done;
	}

	/* Skip toppars not in active fetch state */
	if (rktp->rktp_fetch_state != RD_KAFKA_TOPPAR_FETCH_ACTIVE) {
                reason = "not in active fetch state";
		should_fetch = 0;
		goto done;
	}

        /* Update broker thread's fetch op version */
        version = rktp->rktp_op_version;
        if (version > rktp->rktp_fetch_version ||
            rktp->rktp_next_offset != rktp->rktp_last_next_offset ||
            rktp->rktp_offsets.fetch_offset == RD_KAFKA_OFFSET_INVALID) {
                /* New version barrier, something was modified from the
                 * control plane. Reset and start over.
		 * Alternatively only the next_offset changed but not the
		 * barrier, which is the case when automatically triggering
		 * offset.reset (such as on PARTITION_EOF or
                 * OFFSET_OUT_OF_RANGE). */

                rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "FETCHDEC",
                             "Topic %s [%"PRId32"]: fetch decide: "
                             "updating to version %d (was %d) at "
                             "offset %"PRId64" (was %"PRId64")",
                             rktp->rktp_rkt->rkt_topic->str,
                             rktp->rktp_partition,
                             version, rktp->rktp_fetch_version,
                             rktp->rktp_next_offset,
                             rktp->rktp_offsets.fetch_offset);

                rd_kafka_offset_stats_reset(&rktp->rktp_offsets);

                /* New start offset */
                rktp->rktp_offsets.fetch_offset = rktp->rktp_next_offset;
		rktp->rktp_last_next_offset = rktp->rktp_next_offset;

                rktp->rktp_fetch_version = version;

                rd_kafka_q_purge_toppar_version(rktp->rktp_fetchq, rktp,
                                                version);
        }


	if (RD_KAFKA_TOPPAR_IS_PAUSED(rktp)) {
		should_fetch = 0;
		reason = "paused";

	} else if (RD_KAFKA_OFFSET_IS_LOGICAL(rktp->rktp_next_offset)) {
                should_fetch = 0;
                reason = "no concrete offset";

        } else if (rd_kafka_q_len(rktp->rktp_fetchq) >=
		   rkb->rkb_rk->rk_conf.queued_min_msgs) {
		/* Skip toppars who's local message queue is already above
		 * the lower threshold. */
                reason = "queued.min.messages exceeded";
                should_fetch = 0;

        } else if ((int64_t)rd_kafka_q_size(rktp->rktp_fetchq) >=
            rkb->rkb_rk->rk_conf.queued_max_msg_bytes) {
                reason = "queued.max.messages.kbytes exceeded";
                should_fetch = 0;

        } else if (rktp->rktp_ts_fetch_backoff > rd_clock()) {
                reason = "fetch backed off";
                ts_backoff = rktp->rktp_ts_fetch_backoff;
                should_fetch = 0;
        }

 done:
        /* Copy offset stats to finalized place holder. */
        rktp->rktp_offsets_fin = rktp->rktp_offsets;

        if (rktp->rktp_fetch != should_fetch) {
                rd_rkb_dbg(rkb, FETCH, "FETCH",
                           "Topic %s [%"PRId32"] in state %s at offset %s "
                           "(%d/%d msgs, %"PRId64"/%d kb queued, "
			   "opv %"PRId32") is %s%s",
                           rktp->rktp_rkt->rkt_topic->str,
                           rktp->rktp_partition,
			   rd_kafka_fetch_states[rktp->rktp_fetch_state],
                           rd_kafka_offset2str(rktp->rktp_next_offset),
                           rd_kafka_q_len(rktp->rktp_fetchq),
                           rkb->rkb_rk->rk_conf.queued_min_msgs,
                           rd_kafka_q_size(rktp->rktp_fetchq) / 1024,
                           rkb->rkb_rk->rk_conf.queued_max_msg_kbytes,
			   rktp->rktp_fetch_version,
                           should_fetch ? "fetchable" : "not fetchable: ",
                           reason);

                if (should_fetch) {
			rd_dassert(rktp->rktp_fetch_version > 0);
                        rd_kafka_broker_active_toppar_add(rkb, rktp);
                } else {
                        rd_kafka_broker_active_toppar_del(rkb, rktp);
                        /* Non-fetching partitions will have an
                         * indefinate backoff, unless explicitly specified. */
                        if (!ts_backoff)
                                ts_backoff = RD_TS_MAX;
                }
        }

        rd_kafka_toppar_unlock(rktp);

        return ts_backoff;
}


/**
 * @brief Serve a toppar in a consumer broker thread.
 *        This is considered the fast path and should be minimal,
 *        mostly focusing on fetch related mechanisms.
 *
 * @returns the partition's Fetch backoff timestamp, or 0 if no backoff.
 *
 * @locality broker thread
 * @locks none
 */
rd_ts_t rd_kafka_broker_consumer_toppar_serve (rd_kafka_broker_t *rkb,
                                               rd_kafka_toppar_t *rktp) {
        return rd_kafka_toppar_fetch_decide(rktp, rkb, 0);
}



/**
 * @brief Serve a toppar op
 *
 * @param rktp may be NULL for certain ops (OP_RECV_BUF)
 *
 * Will send an empty reply op if the request rko has a replyq set,
 * providing synchronous operation.
 *
 * @locality toppar handler thread
 */
static rd_kafka_op_res_t
rd_kafka_toppar_op_serve (rd_kafka_t *rk,
                          rd_kafka_q_t *rkq, rd_kafka_op_t *rko,
                          rd_kafka_q_cb_type_t cb_type, void *opaque) {
	rd_kafka_toppar_t *rktp = NULL;
	int outdated = 0;

	if (rko->rko_rktp)
		rktp = rd_kafka_toppar_s2i(rko->rko_rktp);

	if (rktp) {
		outdated = rd_kafka_op_version_outdated(rko,
							rktp->rktp_op_version);

		rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "OP",
			     "%.*s [%"PRId32"] received %sop %s "
			     "(v%"PRId32") in fetch-state %s (opv%d)",
			     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
			     rktp->rktp_partition,
			     outdated ? "outdated ": "",
			     rd_kafka_op2str(rko->rko_type),
			     rko->rko_version,
			     rd_kafka_fetch_states[rktp->rktp_fetch_state],
			     rktp->rktp_op_version);

		if (outdated) {
#if ENABLE_DEVEL
			rd_kafka_op_print(stdout, "PART_OUTDATED", rko);
#endif
                        rd_kafka_op_reply(rko, RD_KAFKA_RESP_ERR__OUTDATED);
			return RD_KAFKA_OP_RES_HANDLED;
		}
	}

	switch ((int)rko->rko_type)
	{
	case RD_KAFKA_OP_FETCH_START:
		rd_kafka_toppar_fetch_start(rktp,
					    rko->rko_u.fetch_start.offset, rko);
		break;

	case RD_KAFKA_OP_FETCH_STOP:
		rd_kafka_toppar_fetch_stop(rktp, rko);
		break;

	case RD_KAFKA_OP_SEEK:
		rd_kafka_toppar_seek(rktp, rko->rko_u.fetch_start.offset, rko);
		break;

	case RD_KAFKA_OP_PAUSE:
		rd_kafka_toppar_pause_resume(rktp, rko);
		break;

        case RD_KAFKA_OP_OFFSET_COMMIT | RD_KAFKA_OP_REPLY:
                rd_kafka_assert(NULL, rko->rko_u.offset_commit.cb);
                rko->rko_u.offset_commit.cb(
                        rk, rko->rko_err,
                        rko->rko_u.offset_commit.partitions,
                        rko->rko_u.offset_commit.opaque);
                break;

	case RD_KAFKA_OP_OFFSET_FETCH | RD_KAFKA_OP_REPLY:
        {
                /* OffsetFetch reply */
                rd_kafka_topic_partition_list_t *offsets =
			rko->rko_u.offset_fetch.partitions;
                shptr_rd_kafka_toppar_t *s_rktp;
		int64_t offset = RD_KAFKA_OFFSET_INVALID;

                s_rktp = offsets->elems[0]._private;
                if (!rko->rko_err) {
                        /* Request succeeded but per-partition might have failed */
                        rko->rko_err = offsets->elems[0].err;
			offset       = offsets->elems[0].offset;
                }
                offsets->elems[0]._private = NULL;
                rd_kafka_topic_partition_list_destroy(offsets);
		rko->rko_u.offset_fetch.partitions = NULL;
                rktp = rd_kafka_toppar_s2i(s_rktp);

		rd_kafka_timer_stop(&rktp->rktp_rkt->rkt_rk->rk_timers,
				    &rktp->rktp_offset_query_tmr,
				    1/*lock*/);

		rd_kafka_toppar_lock(rktp);

		if (rko->rko_err) {
			rd_kafka_dbg(rktp->rktp_rkt->rkt_rk,
				     TOPIC, "OFFSET",
				     "Failed to fetch offset for "
				     "%.*s [%"PRId32"]: %s",
				     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
				     rktp->rktp_partition,
				     rd_kafka_err2str(rko->rko_err));

                        /* Keep on querying until we succeed. */
                        rd_kafka_toppar_offset_retry(rktp, 500,
                                                     "failed to fetch offsets");
                        rd_kafka_toppar_unlock(rktp);


			/* Propagate error to application */
			if (rko->rko_err != RD_KAFKA_RESP_ERR__WAIT_COORD) {
				rd_kafka_q_op_err(rktp->rktp_fetchq,
						  RD_KAFKA_OP_ERR, rko->rko_err,
						  0, rktp, 0,
						  "Failed to fetch "
						  "offsets from brokers: %s",
						  rd_kafka_err2str(rko->rko_err));
			}

			rd_kafka_toppar_destroy(s_rktp);

			break;
		}

		rd_kafka_dbg(rktp->rktp_rkt->rkt_rk,
			     TOPIC, "OFFSET",
			     "%.*s [%"PRId32"]: OffsetFetch returned "
			     "offset %s (%"PRId64")",
			     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
			     rktp->rktp_partition,
			     rd_kafka_offset2str(offset), offset);

		if (offset > 0)
			rktp->rktp_committed_offset = offset;

		if (offset >= 0)
			rd_kafka_toppar_next_offset_handle(rktp, offset);
		else
			rd_kafka_offset_reset(rktp, offset,
					      RD_KAFKA_RESP_ERR__NO_OFFSET,
					      "no previously committed offset "
					      "available");
		rd_kafka_toppar_unlock(rktp);

                rd_kafka_toppar_destroy(s_rktp);
        }
        break;

        default:
                rd_kafka_assert(NULL, !*"unknown type");
                break;
        }

        rd_kafka_op_reply(rko, RD_KAFKA_RESP_ERR_NO_ERROR);

        return RD_KAFKA_OP_RES_HANDLED;
}





/**
 * Send command op to toppar (handled by toppar's thread).
 *
 * Locality: any thread
 */
static void rd_kafka_toppar_op0 (rd_kafka_toppar_t *rktp, rd_kafka_op_t *rko,
				 rd_kafka_replyq_t replyq) {
        rko->rko_rktp = rd_kafka_toppar_keep(rktp);
	rko->rko_replyq = replyq;

        rd_kafka_q_enq(rktp->rktp_ops, rko);
}


/**
 * Send command op to toppar (handled by toppar's thread).
 *
 * Locality: any thread
 */
static void rd_kafka_toppar_op (rd_kafka_toppar_t *rktp,
				rd_kafka_op_type_t type, int32_t version,
				int64_t offset, rd_kafka_cgrp_t *rkcg,
				rd_kafka_replyq_t replyq) {
        rd_kafka_op_t *rko;

        rko = rd_kafka_op_new(type);
	rko->rko_version = version;
        if (type == RD_KAFKA_OP_FETCH_START ||
	    type == RD_KAFKA_OP_SEEK) {
		if (rkcg)
			rko->rko_u.fetch_start.rkcg = rkcg;
		rko->rko_u.fetch_start.offset = offset;
	}

	rd_kafka_toppar_op0(rktp, rko, replyq);
}



/**
 * Start consuming partition (async operation).
 *  'offset' is the initial offset
 *  'fwdq' is an optional queue to forward messages to, if this is NULL
 *  then messages will be enqueued on rktp_fetchq.
 *  'replyq' is an optional queue for handling the consume_start ack.
 *
 * This is the thread-safe interface that can be called from any thread.
 */
rd_kafka_resp_err_t rd_kafka_toppar_op_fetch_start (rd_kafka_toppar_t *rktp,
                                                    int64_t offset,
                                                    rd_kafka_q_t *fwdq,
                                                    rd_kafka_replyq_t replyq) {
	int32_t version;

        rd_kafka_q_lock(rktp->rktp_fetchq);
        if (fwdq && !(rktp->rktp_fetchq->rkq_flags & RD_KAFKA_Q_F_FWD_APP))
                rd_kafka_q_fwd_set0(rktp->rktp_fetchq, fwdq,
                                    0, /* no do_lock */
                                    0 /* no fwd_app */);
        rd_kafka_q_unlock(rktp->rktp_fetchq);

	/* Bump version barrier. */
	version = rd_kafka_toppar_version_new_barrier(rktp);

	rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "CONSUMER",
		     "Start consuming %.*s [%"PRId32"] at "
		     "offset %s (v%"PRId32")",
		     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
		     rktp->rktp_partition, rd_kafka_offset2str(offset),
		     version);

        rd_kafka_toppar_op(rktp, RD_KAFKA_OP_FETCH_START, version,
                           offset, rktp->rktp_rkt->rkt_rk->rk_cgrp, replyq);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * Stop consuming partition (async operatoin)
 * This is thread-safe interface that can be called from any thread.
 *
 * Locality: any thread
 */
rd_kafka_resp_err_t rd_kafka_toppar_op_fetch_stop (rd_kafka_toppar_t *rktp,
                                                   rd_kafka_replyq_t replyq) {
	int32_t version;

	/* Bump version barrier. */
        version = rd_kafka_toppar_version_new_barrier(rktp);

        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "CONSUMER",
		     "Stop consuming %.*s [%"PRId32"] (v%"PRId32")",
		     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
		     rktp->rktp_partition, version);

        rd_kafka_toppar_op(rktp, RD_KAFKA_OP_FETCH_STOP, version,
			   0, NULL, replyq);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * Set/Seek offset of a consumed partition (async operation).
 *  'offset' is the target offset
 *  'replyq' is an optional queue for handling the ack.
 *
 * This is the thread-safe interface that can be called from any thread.
 */
rd_kafka_resp_err_t rd_kafka_toppar_op_seek (rd_kafka_toppar_t *rktp,
                                             int64_t offset,
                                             rd_kafka_replyq_t replyq) {
	int32_t version;

	/* Bump version barrier. */
	version = rd_kafka_toppar_version_new_barrier(rktp);

	rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "CONSUMER",
		     "Seek %.*s [%"PRId32"] to "
		     "offset %s (v%"PRId32")",
		     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
		     rktp->rktp_partition, rd_kafka_offset2str(offset),
		     version);

        rd_kafka_toppar_op(rktp, RD_KAFKA_OP_SEEK, version,
			   offset, NULL, replyq);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * @brief Pause/resume partition (async operation).
 *
 * @param flag is either RD_KAFKA_TOPPAR_F_APP_PAUSE or .._F_LIB_PAUSE
 *             depending on if the app paused or librdkafka.
 * @param pause is 1 for pausing or 0 for resuming.
 *
 * @locality any
 */
static rd_kafka_resp_err_t
rd_kafka_toppar_op_pause_resume (rd_kafka_toppar_t *rktp, int pause, int flag,
                                 rd_kafka_replyq_t replyq) {
	int32_t version;
	rd_kafka_op_t *rko;

	/* Bump version barrier. */
	version = rd_kafka_toppar_version_new_barrier(rktp);

	rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, pause ? "PAUSE":"RESUME",
		     "%s %.*s [%"PRId32"] (v%"PRId32")",
		     pause ? "Pause" : "Resume",
		     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
		     rktp->rktp_partition, version);

	rko = rd_kafka_op_new(RD_KAFKA_OP_PAUSE);
	rko->rko_version = version;
	rko->rko_u.pause.pause = pause;
	rko->rko_u.pause.flag = flag;

        rd_kafka_toppar_op0(rktp, rko, replyq);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}





/**
 * @brief Pause or resume a list of partitions.
 *
 * @param flag is either RD_KAFKA_TOPPAR_F_APP_PAUSE or .._F_LIB_PAUSE
 *             depending on if the app paused or librdkafka.
 * @param pause true for pausing, false for resuming.
 * @param async RD_SYNC to wait for background thread to handle op,
 *              RD_ASYNC for asynchronous operation.
 *
 * @locality any
 *
 * @remark This is an asynchronous call, the actual pause/resume is performed
 *         by toppar_pause() in the toppar's handler thread.
 */
rd_kafka_resp_err_t
rd_kafka_toppars_pause_resume (rd_kafka_t *rk,
                               rd_bool_t pause, rd_async_t async, int flag,
                               rd_kafka_topic_partition_list_t *partitions) {
        int i;
        int waitcnt = 0;
        rd_kafka_q_t *tmpq = NULL;

        if (!async)
                tmpq = rd_kafka_q_new(rk);

	rd_kafka_dbg(rk, TOPIC, pause ? "PAUSE":"RESUME",
		     "%s %s %d partition(s)",
		     flag & RD_KAFKA_TOPPAR_F_APP_PAUSE ? "Application" : "Library",
		     pause ? "pausing" : "resuming", partitions->cnt);

	for (i = 0 ; i < partitions->cnt ; i++) {
		rd_kafka_topic_partition_t *rktpar = &partitions->elems[i];
		shptr_rd_kafka_toppar_t *s_rktp;
		rd_kafka_toppar_t *rktp;

                s_rktp = rd_kafka_topic_partition_list_get_toppar(rk, rktpar);
		if (!s_rktp) {
			rd_kafka_dbg(rk, TOPIC, pause ? "PAUSE":"RESUME",
				     "%s %s [%"PRId32"]: skipped: "
				     "unknown partition",
				     pause ? "Pause":"Resume",
				     rktpar->topic, rktpar->partition);

			rktpar->err = RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;
			continue;
		}

		rktp = rd_kafka_toppar_s2i(s_rktp);

                rd_kafka_toppar_op_pause_resume(rktp, pause, flag,
                                                RD_KAFKA_REPLYQ(tmpq, 0));

                if (!async)
                        waitcnt++;

		rd_kafka_toppar_destroy(s_rktp);

		rktpar->err = RD_KAFKA_RESP_ERR_NO_ERROR;
	}

        if (!async) {
                while (waitcnt-- > 0)
                        rd_kafka_q_wait_result(tmpq, RD_POLL_INFINITE);

                rd_kafka_q_destroy_owner(tmpq);
        }

	return RD_KAFKA_RESP_ERR_NO_ERROR;
}





/**
 * Propagate error for toppar
 */
void rd_kafka_toppar_enq_error (rd_kafka_toppar_t *rktp,
                                rd_kafka_resp_err_t err,
                                const char *reason) {
        rd_kafka_op_t *rko;
        char buf[512];

        rko = rd_kafka_op_new(RD_KAFKA_OP_ERR);
        rko->rko_err  = err;
        rko->rko_rktp = rd_kafka_toppar_keep(rktp);

        rd_snprintf(buf, sizeof(buf), "%.*s [%"PRId32"]: %s (%s)",
                    RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                    rktp->rktp_partition, reason,
                    rd_kafka_err2str(err));

        rko->rko_u.err.errstr = rd_strdup(buf);

        rd_kafka_q_enq(rktp->rktp_fetchq, rko);
}





/**
 * Returns the currently delegated broker for this toppar.
 * If \p proper_broker is set NULL will be returned if current handler
 * is not a proper broker (INTERNAL broker).
 *
 * The returned broker has an increased refcount.
 *
 * Locks: none
 */
rd_kafka_broker_t *rd_kafka_toppar_broker (rd_kafka_toppar_t *rktp,
                                           int proper_broker) {
        rd_kafka_broker_t *rkb;
        rd_kafka_toppar_lock(rktp);
        rkb = rktp->rktp_broker;
        if (rkb) {
                if (proper_broker && rkb->rkb_source == RD_KAFKA_INTERNAL)
                        rkb = NULL;
                else
                        rd_kafka_broker_keep(rkb);
        }
        rd_kafka_toppar_unlock(rktp);

        return rkb;
}


/**
 * @brief Take action when partition broker becomes unavailable.
 *        This should be called when requests fail with
 *        NOT_LEADER_FOR.. or similar error codes, e.g. ProduceRequest.
 *
 * @locks none
 * @locality any
 */
void rd_kafka_toppar_leader_unavailable (rd_kafka_toppar_t *rktp,
                                         const char *reason,
                                         rd_kafka_resp_err_t err) {
        rd_kafka_itopic_t *rkt = rktp->rktp_rkt;

        rd_kafka_dbg(rkt->rkt_rk, TOPIC, "BROKERUA",
                     "%s [%"PRId32"]: broker unavailable: %s: %s",
                     rkt->rkt_topic->str, rktp->rktp_partition, reason,
                     rd_kafka_err2str(err));

        rd_kafka_topic_wrlock(rkt);
        rkt->rkt_flags |= RD_KAFKA_TOPIC_F_LEADER_UNAVAIL;
        rd_kafka_topic_wrunlock(rkt);

        rd_kafka_topic_fast_leader_query(rkt->rkt_rk);
}


const char *
rd_kafka_topic_partition_topic (const rd_kafka_topic_partition_t *rktpar) {
        const rd_kafka_toppar_t *rktp = (const rd_kafka_toppar_t *)rktpar;
        return rktp->rktp_rkt->rkt_topic->str;
}

int32_t
rd_kafka_topic_partition_partition (const rd_kafka_topic_partition_t *rktpar) {
        const rd_kafka_toppar_t *rktp = (const rd_kafka_toppar_t *)rktpar;
        return rktp->rktp_partition;
}

void rd_kafka_topic_partition_get (const rd_kafka_topic_partition_t *rktpar,
                                   const char **name, int32_t *partition) {
        const rd_kafka_toppar_t *rktp = (const rd_kafka_toppar_t *)rktpar;
        *name = rktp->rktp_rkt->rkt_topic->str;
        *partition = rktp->rktp_partition;
}




/**
 *
 * rd_kafka_topic_partition_t lists
 * Fixed-size non-growable list of partitions for propagation to application.
 *
 */


static void
rd_kafka_topic_partition_list_grow (rd_kafka_topic_partition_list_t *rktparlist,
                                    int add_size) {
        if (add_size < rktparlist->size)
                add_size = RD_MAX(rktparlist->size, 32);

        rktparlist->size += add_size;
        rktparlist->elems = rd_realloc(rktparlist->elems,
                                       sizeof(*rktparlist->elems) *
                                       rktparlist->size);

}
/**
 * Create a list for fitting 'size' topic_partitions (rktp).
 */
rd_kafka_topic_partition_list_t *rd_kafka_topic_partition_list_new (int size) {
        rd_kafka_topic_partition_list_t *rktparlist;

        rktparlist = rd_calloc(1, sizeof(*rktparlist));

        if (size > 0)
                rd_kafka_topic_partition_list_grow(rktparlist, size);

        return rktparlist;
}



rd_kafka_topic_partition_t *rd_kafka_topic_partition_new (const char *topic,
							  int32_t partition) {
	rd_kafka_topic_partition_t *rktpar = rd_calloc(1, sizeof(*rktpar));

	rktpar->topic = rd_strdup(topic);
	rktpar->partition = partition;

	return rktpar;
}


rd_kafka_topic_partition_t *
rd_kafka_topic_partition_new_from_rktp (rd_kafka_toppar_t *rktp) {
	rd_kafka_topic_partition_t *rktpar = rd_calloc(1, sizeof(*rktpar));

	rktpar->topic = RD_KAFKAP_STR_DUP(rktp->rktp_rkt->rkt_topic);
	rktpar->partition = rktp->rktp_partition;

	return rktpar;
}



static void
rd_kafka_topic_partition_destroy0 (rd_kafka_topic_partition_t *rktpar, int do_free) {
	if (rktpar->topic)
		rd_free(rktpar->topic);
	if (rktpar->metadata)
		rd_free(rktpar->metadata);
	if (rktpar->_private)
		rd_kafka_toppar_destroy((shptr_rd_kafka_toppar_t *)
					rktpar->_private);

	if (do_free)
		rd_free(rktpar);
}

void rd_kafka_topic_partition_destroy (rd_kafka_topic_partition_t *rktpar) {
	rd_kafka_topic_partition_destroy0(rktpar, 1);
}


/**
 * Destroys a list previously created with .._list_new() and drops
 * any references to contained toppars.
 */
void
rd_kafka_topic_partition_list_destroy (rd_kafka_topic_partition_list_t *rktparlist) {
        int i;

        for (i = 0 ; i < rktparlist->cnt ; i++)
		rd_kafka_topic_partition_destroy0(&rktparlist->elems[i], 0);

        if (rktparlist->elems)
                rd_free(rktparlist->elems);

        rd_free(rktparlist);
}


/**
 * Add a partition to an rktpar list.
 * The list must have enough room to fit it.
 *
 * '_private' must be NULL or a valid 'shptr_rd_kafka_toppar_t *'.
 *
 * Returns a pointer to the added element.
 */
rd_kafka_topic_partition_t *
rd_kafka_topic_partition_list_add0 (rd_kafka_topic_partition_list_t *rktparlist,
                                    const char *topic, int32_t partition,
				    shptr_rd_kafka_toppar_t *_private) {
        rd_kafka_topic_partition_t *rktpar;
        if (rktparlist->cnt == rktparlist->size)
                rd_kafka_topic_partition_list_grow(rktparlist, 1);
        rd_kafka_assert(NULL, rktparlist->cnt < rktparlist->size);

        rktpar = &rktparlist->elems[rktparlist->cnt++];
        memset(rktpar, 0, sizeof(*rktpar));
        rktpar->topic = rd_strdup(topic);
        rktpar->partition = partition;
	rktpar->offset = RD_KAFKA_OFFSET_INVALID;
        rktpar->_private = _private;

        return rktpar;
}


rd_kafka_topic_partition_t *
rd_kafka_topic_partition_list_add (rd_kafka_topic_partition_list_t *rktparlist,
                                   const char *topic, int32_t partition) {
        return rd_kafka_topic_partition_list_add0(rktparlist,
                                                  topic, partition, NULL);
}


/**
 * Adds a consecutive list of partitions to a list
 */
void
rd_kafka_topic_partition_list_add_range (rd_kafka_topic_partition_list_t
                                         *rktparlist,
                                         const char *topic,
                                         int32_t start, int32_t stop) {

        for (; start <= stop ; start++)
                rd_kafka_topic_partition_list_add(rktparlist, topic, start);
}


rd_kafka_topic_partition_t *
rd_kafka_topic_partition_list_upsert (
        rd_kafka_topic_partition_list_t *rktparlist,
        const char *topic, int32_t partition) {
        rd_kafka_topic_partition_t *rktpar;

        if ((rktpar = rd_kafka_topic_partition_list_find(rktparlist,
                                                         topic, partition)))
                return rktpar;

        return rd_kafka_topic_partition_list_add(rktparlist, topic, partition);
}

/**
 * @brief Creates a copy of \p rktpar and adds it to \p rktparlist
 */
void
rd_kafka_topic_partition_copy (rd_kafka_topic_partition_list_t *rktparlist,
                               const rd_kafka_topic_partition_t *rktpar) {
        rd_kafka_topic_partition_t *dst;

        dst = rd_kafka_topic_partition_list_add0(
                rktparlist,
                rktpar->topic,
                rktpar->partition,
                rktpar->_private ?
                rd_kafka_toppar_keep(
                        rd_kafka_toppar_s2i((shptr_rd_kafka_toppar_t *)
                                            rktpar->_private)) : NULL);
        dst->offset = rktpar->offset;
        dst->opaque = rktpar->opaque;
        dst->err    = rktpar->err;
        if (rktpar->metadata_size > 0) {
                dst->metadata =
                        rd_malloc(rktpar->metadata_size);
                dst->metadata_size = rktpar->metadata_size;
                memcpy((void *)dst->metadata, rktpar->metadata,
                       rktpar->metadata_size);
        }
}



/**
 * Create and return a copy of list 'src'
 */
rd_kafka_topic_partition_list_t *
rd_kafka_topic_partition_list_copy (const rd_kafka_topic_partition_list_t *src){
        rd_kafka_topic_partition_list_t *dst;
        int i;

        dst = rd_kafka_topic_partition_list_new(src->size);

        for (i = 0 ; i < src->cnt ; i++)
                rd_kafka_topic_partition_copy(dst, &src->elems[i]);
        return dst;
}

/**
 * @returns (and sets if necessary) the \p rktpar's _private / toppar.
 * @remark a new reference is returned.
 */
shptr_rd_kafka_toppar_t *
rd_kafka_topic_partition_get_toppar (rd_kafka_t *rk,
                                     rd_kafka_topic_partition_t *rktpar) {
        shptr_rd_kafka_toppar_t *s_rktp;

        if (!(s_rktp = rktpar->_private))
                s_rktp = rktpar->_private =
                        rd_kafka_toppar_get2(rk,
                                             rktpar->topic,
                                             rktpar->partition, 0, 0);
        if (!s_rktp)
                return NULL;

        return rd_kafka_toppar_keep(rd_kafka_toppar_s2i(s_rktp));
}


static int rd_kafka_topic_partition_cmp (const void *_a, const void *_b,
                                         void *opaque) {
        const rd_kafka_topic_partition_t *a = _a;
        const rd_kafka_topic_partition_t *b = _b;
        int r = strcmp(a->topic, b->topic);
        if (r)
                return r;
        else
                return RD_CMP(a->partition, b->partition);
}


/**
 * @brief Search 'rktparlist' for 'topic' and 'partition'.
 * @returns the elems[] index or -1 on miss.
 */
int
rd_kafka_topic_partition_list_find0 (rd_kafka_topic_partition_list_t *rktparlist,
				     const char *topic, int32_t partition) {
        rd_kafka_topic_partition_t skel;
        int i;

        skel.topic = (char *)topic;
        skel.partition = partition;

        for (i = 0 ; i < rktparlist->cnt ; i++) {
                if (!rd_kafka_topic_partition_cmp(&skel,
                                                  &rktparlist->elems[i],
                                                  NULL))
                        return i;
        }

        return -1;
}

rd_kafka_topic_partition_t *
rd_kafka_topic_partition_list_find (rd_kafka_topic_partition_list_t *rktparlist,
				     const char *topic, int32_t partition) {
	int i = rd_kafka_topic_partition_list_find0(rktparlist,
						    topic, partition);
	if (i == -1)
		return NULL;
	else
		return &rktparlist->elems[i];
}


int
rd_kafka_topic_partition_list_del_by_idx (rd_kafka_topic_partition_list_t *rktparlist,
					  int idx) {
	if (unlikely(idx < 0 || idx >= rktparlist->cnt))
		return 0;

	rktparlist->cnt--;
	rd_kafka_topic_partition_destroy0(&rktparlist->elems[idx], 0);
	memmove(&rktparlist->elems[idx], &rktparlist->elems[idx+1],
		(rktparlist->cnt - idx) * sizeof(rktparlist->elems[idx]));

	return 1;
}


int
rd_kafka_topic_partition_list_del (rd_kafka_topic_partition_list_t *rktparlist,
				   const char *topic, int32_t partition) {
	int i = rd_kafka_topic_partition_list_find0(rktparlist,
						    topic, partition);
	if (i == -1)
		return 0;

	return rd_kafka_topic_partition_list_del_by_idx(rktparlist, i);
}



/**
 * Returns true if 'topic' matches the 'rktpar', else false.
 * On match, if rktpar is a regex pattern then 'matched_by_regex' is set to 1.
 */
int rd_kafka_topic_partition_match (rd_kafka_t *rk,
				    const rd_kafka_group_member_t *rkgm,
				    const rd_kafka_topic_partition_t *rktpar,
				    const char *topic, int *matched_by_regex) {
	int ret = 0;

	if (*rktpar->topic == '^') {
		char errstr[128];

		ret = rd_regex_match(rktpar->topic, topic,
				     errstr, sizeof(errstr));
		if (ret == -1) {
			rd_kafka_dbg(rk, CGRP,
				     "SUBMATCH",
				     "Invalid regex for member "
				     "\"%.*s\" subscription \"%s\": %s",
				     RD_KAFKAP_STR_PR(rkgm->rkgm_member_id),
				     rktpar->topic, errstr);
			return 0;
		}

		if (ret && matched_by_regex)
			*matched_by_regex = 1;

	} else if (!strcmp(rktpar->topic, topic)) {

		if (matched_by_regex)
			*matched_by_regex = 0;

		ret = 1;
	}

	return ret;
}



void rd_kafka_topic_partition_list_sort (
        rd_kafka_topic_partition_list_t *rktparlist,
        int (*cmp) (const void *, const void *, void *),
        void *opaque) {

        if (!cmp)
                cmp = rd_kafka_topic_partition_cmp;

        rd_qsort_r(rktparlist->elems, rktparlist->cnt,
                   sizeof(*rktparlist->elems),
                   cmp, opaque);
}


void rd_kafka_topic_partition_list_sort_by_topic (
        rd_kafka_topic_partition_list_t *rktparlist) {
        rd_kafka_topic_partition_list_sort(rktparlist,
                                           rd_kafka_topic_partition_cmp, NULL);
}

rd_kafka_resp_err_t rd_kafka_topic_partition_list_set_offset (
	rd_kafka_topic_partition_list_t *rktparlist,
	const char *topic, int32_t partition, int64_t offset) {
	rd_kafka_topic_partition_t *rktpar;

	if (!(rktpar = rd_kafka_topic_partition_list_find(rktparlist,
							  topic, partition)))
		return RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;

	rktpar->offset = offset;

	return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * @brief Reset all offsets to the provided value.
 */
void
rd_kafka_topic_partition_list_reset_offsets (rd_kafka_topic_partition_list_t *rktparlist,
					     int64_t offset) {

        int i;
        for (i = 0 ; i < rktparlist->cnt ; i++)
		rktparlist->elems[i].offset = offset;
}


/**
 * Set offset values in partition list based on toppar's last stored offset.
 *
 *  from_rktp - true: set rktp's last stored offset, false: set def_value
 *  unless a concrete offset is set.
 *  is_commit: indicates that set offset is to be committed (for debug log)
 *
 * Returns the number of valid non-logical offsets (>=0).
 */
int rd_kafka_topic_partition_list_set_offsets (
	rd_kafka_t *rk,
        rd_kafka_topic_partition_list_t *rktparlist,
        int from_rktp, int64_t def_value, int is_commit) {
        int i;
	int valid_cnt = 0;

        for (i = 0 ; i < rktparlist->cnt ; i++) {
                rd_kafka_topic_partition_t *rktpar = &rktparlist->elems[i];
		const char *verb = "setting";
                char preamble[80];

                *preamble = '\0'; /* Avoid warning */

                if (from_rktp) {
                        shptr_rd_kafka_toppar_t *s_rktp = rktpar->_private;
                        rd_kafka_toppar_t *rktp = rd_kafka_toppar_s2i(s_rktp);
                        rd_kafka_toppar_lock(rktp);

                        if (rk->rk_conf.debug & (RD_KAFKA_DBG_CGRP |
                                                 RD_KAFKA_DBG_TOPIC))
                                rd_snprintf(preamble, sizeof(preamble),
                                            "stored offset %"PRId64
                                            ", committed offset %"PRId64": ",
                                            rktp->rktp_stored_offset,
                                            rktp->rktp_committed_offset);

			if (rktp->rktp_stored_offset >
			    rktp->rktp_committed_offset) {
				verb = "setting stored";
				rktpar->offset = rktp->rktp_stored_offset;
			} else {
				rktpar->offset = RD_KAFKA_OFFSET_INVALID;
			}
                        rd_kafka_toppar_unlock(rktp);
                } else {
			if (RD_KAFKA_OFFSET_IS_LOGICAL(rktpar->offset)) {
				verb = "setting default";
				rktpar->offset = def_value;
			} else
				verb = "keeping";
                }

                if (is_commit && rktpar->offset == RD_KAFKA_OFFSET_INVALID)
                        rd_kafka_dbg(rk, CGRP | RD_KAFKA_DBG_TOPIC, "OFFSET",
                                     "Topic %s [%"PRId32"]: "
                                     "%snot including in commit",
                                     rktpar->topic, rktpar->partition,
                                     preamble);
                else
                        rd_kafka_dbg(rk, CGRP | RD_KAFKA_DBG_TOPIC, "OFFSET",
                                     "Topic %s [%"PRId32"]: "
                                     "%s%s offset %s%s",
                                     rktpar->topic, rktpar->partition,
                                     preamble,
                                     verb,
                                     rd_kafka_offset2str(rktpar->offset),
                                     is_commit ? " for commit" : "");

		if (!RD_KAFKA_OFFSET_IS_LOGICAL(rktpar->offset))
			valid_cnt++;
        }

	return valid_cnt;
}


/**
 * @returns the number of partitions with absolute (non-logical) offsets set.
 */
int rd_kafka_topic_partition_list_count_abs_offsets (
	const rd_kafka_topic_partition_list_t *rktparlist) {
	int i;
	int valid_cnt = 0;

        for (i = 0 ; i < rktparlist->cnt ; i++)
		if (!RD_KAFKA_OFFSET_IS_LOGICAL(rktparlist->elems[i].offset))
			valid_cnt++;

	return valid_cnt;
}

/**
 * @returns a new shared toppar pointer for partition at index 'idx',
 * or NULL if not set, not found, or out of range.
 *
 * @remark A new reference is returned.
 * @remark The _private field is set to the toppar it not previously set.
 */
shptr_rd_kafka_toppar_t *
rd_kafka_topic_partition_list_get_toppar (
        rd_kafka_t *rk, rd_kafka_topic_partition_t *rktpar) {
        shptr_rd_kafka_toppar_t *s_rktp;

        s_rktp = rd_kafka_topic_partition_get_toppar(rk, rktpar);
        if (!s_rktp)
                return NULL;

        return s_rktp;
}


/**
 * @brief Update _private (toppar) field to point to valid s_rktp
 *        for each parition.
 */
void
rd_kafka_topic_partition_list_update_toppars (rd_kafka_t *rk,
                                              rd_kafka_topic_partition_list_t
                                              *rktparlist) {
        int i;
        for (i = 0 ; i < rktparlist->cnt ; i++) {
                rd_kafka_topic_partition_t *rktpar = &rktparlist->elems[i];

                rd_kafka_topic_partition_list_get_toppar(rk, rktpar);
        }
}


/**
 * @brief Populate \p leaders with the leaders+partitions for the partitions in
 *        \p rktparlist. Duplicates are suppressed.
 *
 *        If no leader is found for a partition that element's \c .err will
 *        be set to RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE.
 *
 *        If the partition does not exist \c .err will be set to
 *        RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION.
 *
 * @param leaders rd_list_t of allocated (struct rd_kafka_partition_leader *)
 * @param query_topics (optional) rd_list of strdupped (char *)
 *
 * @remark This is based on the current topic_t and partition state
 *         which may lag behind the last metadata update due to internal
 *         threading and also the fact that no topic_t may have been created.
 *
 * @param leaders rd_list_t of type (struct rd_kafka_partition_leader *)
 *
 * @returns the number of leaders added.
 *
 * @sa rd_kafka_topic_partition_list_get_leaders_by_metadata
 *
 * @locks rd_kafka_*lock() MUST NOT be held
 */
int
rd_kafka_topic_partition_list_get_leaders (
        rd_kafka_t *rk,
        rd_kafka_topic_partition_list_t *rktparlist,
        rd_list_t *leaders,
        rd_list_t *query_topics) {
        int cnt = 0;
        int i;

        rd_kafka_rdlock(rk);

        for (i = 0 ; i < rktparlist->cnt ; i++) {
                rd_kafka_topic_partition_t *rktpar = &rktparlist->elems[i];
                rd_kafka_broker_t *rkb = NULL;
                struct rd_kafka_partition_leader leader_skel;
                struct rd_kafka_partition_leader *leader;
                const rd_kafka_metadata_topic_t *mtopic;
                const rd_kafka_metadata_partition_t *mpart;

                rd_kafka_metadata_cache_topic_partition_get(
                        rk, &mtopic, &mpart,
                        rktpar->topic, rktpar->partition, 1/*valid*/);

                if (mtopic &&
                    mtopic->err != RD_KAFKA_RESP_ERR_NO_ERROR &&
                    mtopic->err != RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE) {
                        /* Topic permanently errored */
                        rktpar->err = mtopic->err;
                        continue;
                }

                if (mtopic && !mpart && mtopic->partition_cnt > 0) {
                        /* Topic exists but partition doesnt.
                         * This is a permanent error. */
                        rktpar->err = RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;
                        continue;
                }

                if (mpart &&
                    (mpart->leader == -1 ||
                     !(rkb = rd_kafka_broker_find_by_nodeid0(
                               rk, mpart->leader, -1/*any state*/,
                               rd_false)))) {
                        /* Partition has no (valid) leader */
                        rktpar->err =
                                mtopic->err ? mtopic->err :
                                RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE;
                }

                if (!mtopic || !rkb) {
                        /* Topic unknown or no current leader for partition,
                         * add topic to query list. */
                        if (query_topics &&
                            !rd_list_find(query_topics, rktpar->topic,
                                          (void *)strcmp))
                                rd_list_add(query_topics,
                                            rd_strdup(rktpar->topic));
                        continue;
                }

                /* Leader exists, add to leader list. */

                rktpar->err = RD_KAFKA_RESP_ERR_NO_ERROR;

                memset(&leader_skel, 0, sizeof(leader_skel));
                leader_skel.rkb = rkb;

                leader = rd_list_find(leaders, &leader_skel,
                                      rd_kafka_partition_leader_cmp);

                if (!leader) {
                        leader = rd_kafka_partition_leader_new(rkb);
                        rd_list_add(leaders, leader);
                        cnt++;
                }

                rd_kafka_topic_partition_copy(leader->partitions, rktpar);

                rd_kafka_broker_destroy(rkb);    /* loose refcount */
        }

        rd_kafka_rdunlock(rk);

        return cnt;

}




/**
 * @brief Get leaders for all partitions in \p rktparlist, querying metadata
 *        if needed.
 *
 * @param leaders is a pre-initialized (empty) list which will be populated
 *        with the leader brokers and their partitions
 *        (struct rd_kafka_partition_leader *)
 *
 * @returns an error code on error.
 *
 * @locks rd_kafka_*lock() MUST NOT be held
 */
rd_kafka_resp_err_t
rd_kafka_topic_partition_list_query_leaders (
        rd_kafka_t *rk,
        rd_kafka_topic_partition_list_t *rktparlist,
        rd_list_t *leaders, int timeout_ms) {
        rd_ts_t ts_end = rd_timeout_init(timeout_ms);
        rd_ts_t ts_query = 0;
        rd_ts_t now;
        int i = 0;

        /* Get all the partition leaders, try multiple times:
         * if there are no leaders after the first run fire off a leader
         * query and wait for broker state update before trying again,
         * keep trying and re-querying at increasing intervals until
         * success or timeout. */
        do {
                rd_list_t query_topics;
                int query_intvl;

                rd_list_init(&query_topics, rktparlist->cnt, rd_free);

                rd_kafka_topic_partition_list_get_leaders(
                        rk, rktparlist, leaders, &query_topics);

                if (rd_list_empty(&query_topics)) {
                        /* No remaining topics to query: leader-list complete.*/
                        rd_list_destroy(&query_topics);

                        /* No leader(s) for partitions means all partitions
                         * are unknown. */
                        if (rd_list_empty(leaders))
                                return RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;

                        return RD_KAFKA_RESP_ERR_NO_ERROR;
                }

                now = rd_clock();
                /*
                 * Missing leader for some partitions
                 */
                query_intvl = (i+1) * 100; /* add 100ms per iteration */
                if (query_intvl > 2*1000)
                        query_intvl = 2*1000; /* Cap to 2s */

                if (now >= ts_query + (query_intvl*1000)) {
                        /* Query metadata for missing leaders,
                         * possibly creating the topic. */
                        rd_kafka_metadata_refresh_topics(
                                rk, NULL, &query_topics, 1/*force*/,
                                "query partition leaders");
                        ts_query = now;
                } else {
                        /* Wait for broker ids to be updated from
                         * metadata refresh above. */
                        int wait_ms = rd_timeout_remains_limit(ts_end,
                                                               query_intvl);
                        rd_kafka_metadata_cache_wait_change(rk, wait_ms);
                }

                rd_list_destroy(&query_topics);

                i++;
        } while (ts_end == RD_POLL_INFINITE ||
                 now < ts_end); /* now is deliberately outdated here
                                 * since wait_change() will block.
                                 * This gives us one more chance to spin thru*/

        return RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE;
}


/**
 * @brief Populate \p rkts with the rd_kafka_itopic_t objects for the
 *        partitions in. Duplicates are suppressed.
 *
 * @returns the number of topics added.
 */
int
rd_kafka_topic_partition_list_get_topics (
        rd_kafka_t *rk,
        rd_kafka_topic_partition_list_t *rktparlist,
        rd_list_t *rkts) {
        int cnt = 0;

        int i;
        for (i = 0 ; i < rktparlist->cnt ; i++) {
                rd_kafka_topic_partition_t *rktpar = &rktparlist->elems[i];
                shptr_rd_kafka_toppar_t *s_rktp;
                rd_kafka_toppar_t *rktp;

                s_rktp = rd_kafka_topic_partition_get_toppar(rk, rktpar);
                if (!s_rktp) {
                        rktpar->err = RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;
                        continue;
                }

                rktp = rd_kafka_toppar_s2i(s_rktp);

                if (!rd_list_find(rkts, rktp->rktp_s_rkt,
                                  rd_kafka_topic_cmp_s_rkt)) {
                        rd_list_add(rkts, rd_kafka_topic_keep(rktp->rktp_rkt));
                        cnt++;
                }

                rd_kafka_toppar_destroy(s_rktp);
        }

        return cnt;
}


/**
 * @brief Populate \p topics with the strdupped topic names in \p rktparlist.
 *        Duplicates are suppressed.
 *
 * @param include_regex: include regex topics
 *
 * @returns the number of topics added.
 */
int
rd_kafka_topic_partition_list_get_topic_names (
        const rd_kafka_topic_partition_list_t *rktparlist,
        rd_list_t *topics, int include_regex) {
        int cnt = 0;
        int i;

        for (i = 0 ; i < rktparlist->cnt ; i++) {
                const rd_kafka_topic_partition_t *rktpar = &rktparlist->elems[i];

                if (!include_regex && *rktpar->topic == '^')
                        continue;

                if (!rd_list_find(topics, rktpar->topic, (void *)strcmp)) {
                        rd_list_add(topics, rd_strdup(rktpar->topic));
                        cnt++;
                }
        }

        return cnt;
}


/**
 * @brief Create a copy of \p rktparlist only containing the partitions
 *        matched by \p match function.
 *
 * \p match shall return 1 for match, else 0.
 *
 * @returns a new list
 */
rd_kafka_topic_partition_list_t *rd_kafka_topic_partition_list_match (
        const rd_kafka_topic_partition_list_t *rktparlist,
        int (*match) (const void *elem, const void *opaque),
        void *opaque) {
        rd_kafka_topic_partition_list_t *newlist;
        int i;

        newlist = rd_kafka_topic_partition_list_new(0);

        for (i = 0 ; i < rktparlist->cnt ; i++) {
                const rd_kafka_topic_partition_t *rktpar =
                        &rktparlist->elems[i];

                if (!match(rktpar, opaque))
                        continue;

                rd_kafka_topic_partition_copy(newlist, rktpar);
        }

        return newlist;
}

void
rd_kafka_topic_partition_list_log (rd_kafka_t *rk, const char *fac, int dbg,
				   const rd_kafka_topic_partition_list_t *rktparlist) {
        int i;

	rd_kafka_dbg(rk, NONE|dbg, fac, "List with %d partition(s):",
		     rktparlist->cnt);
        for (i = 0 ; i < rktparlist->cnt ; i++) {
		const rd_kafka_topic_partition_t *rktpar =
			&rktparlist->elems[i];
		rd_kafka_dbg(rk, NONE|dbg, fac, " %s [%"PRId32"] offset %s%s%s",
			     rktpar->topic, rktpar->partition,
			     rd_kafka_offset2str(rktpar->offset),
			     rktpar->err ? ": error: " : "",
			     rktpar->err ? rd_kafka_err2str(rktpar->err) : "");
	}
}

/**
 * @returns a comma-separated list of partitions.
 */
const char *
rd_kafka_topic_partition_list_str (const rd_kafka_topic_partition_list_t *rktparlist,
                                   char *dest, size_t dest_size,
                                   int fmt_flags) {
        int i;
        size_t of = 0;
        int trunc = 0;

        for (i = 0 ; i < rktparlist->cnt ; i++) {
                const rd_kafka_topic_partition_t *rktpar =
                        &rktparlist->elems[i];
                char errstr[128];
                char offsetstr[32];
                int r;

                if (trunc) {
                        if (dest_size > 4)
                                rd_snprintf(&dest[dest_size-4], 4, "...");
                        break;
                }

                if (!rktpar->err && (fmt_flags & RD_KAFKA_FMT_F_ONLY_ERR))
                        continue;

                if (rktpar->err && !(fmt_flags & RD_KAFKA_FMT_F_NO_ERR))
                        rd_snprintf(errstr, sizeof(errstr),
                                    "(%s)", rd_kafka_err2str(rktpar->err));
                else
                        errstr[0] = '\0';

                if (rktpar->offset != RD_KAFKA_OFFSET_INVALID)
                        rd_snprintf(offsetstr, sizeof(offsetstr),
                                    "@%"PRId64, rktpar->offset);
                else
                        offsetstr[0] = '\0';

                r = rd_snprintf(&dest[of], dest_size-of,
                                "%s"
                                "%s[%"PRId32"]"
                                "%s"
                                "%s",
                                of == 0 ? "" : ", ",
                                rktpar->topic, rktpar->partition,
                                offsetstr,
                                errstr);

                if ((size_t)r >= dest_size-of)
                        trunc++;
                else
                        of += r;
        }

        return dest;
}



/**
 * @brief Update \p dst with info from \p src.
 *
 * Fields updated:
 *  - metadata
 *  - metadata_size
 *  - offset
 *  - err
 *
 * Will only update partitions that are in both dst and src, other partitions will
 * remain unchanged.
 */
void
rd_kafka_topic_partition_list_update (rd_kafka_topic_partition_list_t *dst,
                                      const rd_kafka_topic_partition_list_t *src){
        int i;

        for (i = 0 ; i < dst->cnt ; i++) {
                rd_kafka_topic_partition_t *d = &dst->elems[i];
                rd_kafka_topic_partition_t *s;

                if (!(s = rd_kafka_topic_partition_list_find(
                              (rd_kafka_topic_partition_list_t *)src,
                              d->topic, d->partition)))
                        continue;

                d->offset = s->offset;
                d->err    = s->err;
                if (d->metadata) {
                        rd_free(d->metadata);
                        d->metadata = NULL;
                        d->metadata_size = 0;
                }
                if (s->metadata_size > 0) {
                        d->metadata =
                                rd_malloc(s->metadata_size);
                        d->metadata_size = s->metadata_size;
                        memcpy((void *)d->metadata, s->metadata,
                                s->metadata_size);
                }
        }
}


/**
 * @returns the sum of \p cb called for each element.
 */
size_t
rd_kafka_topic_partition_list_sum (
        const rd_kafka_topic_partition_list_t *rktparlist,
        size_t (*cb) (const rd_kafka_topic_partition_t *rktpar, void *opaque),
        void *opaque) {
        int i;
        size_t sum = 0;

        for (i = 0 ; i < rktparlist->cnt ; i++) {
                const rd_kafka_topic_partition_t *rktpar =
                        &rktparlist->elems[i];
                sum += cb(rktpar, opaque);
       }
        return sum;
}


/**
 * @brief Set \c .err field \p err on all partitions in list.
 */
void rd_kafka_topic_partition_list_set_err (
        rd_kafka_topic_partition_list_t *rktparlist,
        rd_kafka_resp_err_t err) {
        int i;

        for (i = 0 ; i < rktparlist->cnt ; i++)
                rktparlist->elems[i].err = err;
}


/**
 * @returns the number of wildcard/regex topics
 */
int rd_kafka_topic_partition_list_regex_cnt (
        const rd_kafka_topic_partition_list_t *rktparlist) {
        int i;
        int cnt = 0;

        for (i = 0 ; i < rktparlist->cnt ; i++) {
                const rd_kafka_topic_partition_t *rktpar =
                        &rktparlist->elems[i];
                cnt += *rktpar->topic == '^';
        }
        return cnt;
}


/**
 * @brief Reset base sequence for this toppar.
 *
 * See rd_kafka_toppar_pid_change() below.
 *
 * @warning Toppar must be completely drained.
 *
 * @locality toppar handler thread
 * @locks toppar_lock MUST be held.
 */
static void rd_kafka_toppar_reset_base_msgid (rd_kafka_toppar_t *rktp,
                                              uint64_t new_base_msgid) {
        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk,
                     TOPIC|RD_KAFKA_DBG_EOS, "RESETSEQ",
                     "%.*s [%"PRId32"] "
                     "resetting epoch base seq from %"PRIu64" to %"PRIu64,
                     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                     rktp->rktp_partition,
                     rktp->rktp_eos.epoch_base_msgid, new_base_msgid);

        rktp->rktp_eos.next_ack_seq = 0;
        rktp->rktp_eos.next_err_seq = 0;
        rktp->rktp_eos.epoch_base_msgid = new_base_msgid;
}


/**
 * @brief Update/change the Producer ID for this toppar.
 *
 * Must only be called when pid is different from the current toppar pid.
 *
 * The epoch base sequence will be set to \p base_msgid, which must be the
 * first message in the partition
 * queue. However, if there are outstanding messages in-flight to the broker
 * we will need to wait for these ProduceRequests to finish (most likely
 * with failure) and have their messages re-enqueued to maintain original order.
 * In this case the pid will not be updated and this function should be
 * called again when there are no outstanding messages.
 *
 * @remark This function must only be called when rktp_xmitq is non-empty.
 *
 * @returns 1 if a new pid was set, else 0.
 *
 * @locality toppar handler thread
 * @locks none
 */
int rd_kafka_toppar_pid_change (rd_kafka_toppar_t *rktp, rd_kafka_pid_t pid,
                                uint64_t base_msgid) {
        int inflight = rd_atomic32_get(&rktp->rktp_msgs_inflight);

        if (unlikely(inflight > 0)) {
                rd_kafka_dbg(rktp->rktp_rkt->rkt_rk,
                             TOPIC|RD_KAFKA_DBG_EOS, "NEWPID",
                             "%.*s [%"PRId32"] will not change %s -> %s yet: "
                             "%d message(s) still in-flight from current "
                             "epoch",
                             RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                             rktp->rktp_partition,
                             rd_kafka_pid2str(rktp->rktp_eos.pid),
                             rd_kafka_pid2str(pid),
                             inflight);
                return 0;
        }

        rd_assert(base_msgid != 0 &&
                  *"BUG: pid_change() must only be called with "
                  "non-empty xmitq");

        rd_kafka_toppar_lock(rktp);
        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk,
                     TOPIC|RD_KAFKA_DBG_EOS, "NEWPID",
                     "%.*s [%"PRId32"] changed %s -> %s "
                     "with base MsgId %"PRIu64,
                     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                     rktp->rktp_partition,
                     rd_kafka_pid2str(rktp->rktp_eos.pid),
                     rd_kafka_pid2str(pid),
                     base_msgid);

        rktp->rktp_eos.pid = pid;
        rd_kafka_toppar_reset_base_msgid(rktp, base_msgid);

        rd_kafka_toppar_unlock(rktp);

        return 1;
}


/**
 * @brief Purge messages in partition queues.
 *        Delivery reports will be enqueued for all purged messages, the error
 *        code is set to RD_KAFKA_RESP_ERR__PURGE_QUEUE.
 *
 * @warning Only to be used with the producer
 *
 * @returns the number of messages purged
 *
 * @locality toppar handler thread
 * @locks none
 */
int rd_kafka_toppar_handle_purge_queues (rd_kafka_toppar_t *rktp,
                                         rd_kafka_broker_t *rkb,
                                         int purge_flags) {
        rd_kafka_msgq_t rkmq = RD_KAFKA_MSGQ_INITIALIZER(rkmq);
        int cnt;

        rd_assert(rkb->rkb_rk->rk_type == RD_KAFKA_PRODUCER);
        rd_assert(thrd_is_current(rkb->rkb_thread));

        if (!(purge_flags & RD_KAFKA_PURGE_F_QUEUE))
                return 0;

        /* xmit_msgq is owned by the toppar handler thread (broker thread)
         * and requires no locking. */
        rd_kafka_msgq_concat(&rkmq, &rktp->rktp_xmit_msgq);

        rd_kafka_toppar_lock(rktp);
        rd_kafka_msgq_concat(&rkmq, &rktp->rktp_msgq);
        rd_kafka_toppar_unlock(rktp);

        cnt = rd_kafka_msgq_len(&rkmq);
        rd_kafka_dr_msgq(rktp->rktp_rkt, &rkmq, RD_KAFKA_RESP_ERR__PURGE_QUEUE);

        return cnt;
}


/**
 * @brief Purge queues for the unassigned toppars of all known topics.
 *
 * @locality application thread
 * @locks none
 */
void rd_kafka_purge_ua_toppar_queues (rd_kafka_t *rk) {
        rd_kafka_itopic_t *rkt;
        int msg_cnt = 0, part_cnt = 0;

        rd_kafka_rdlock(rk);
        TAILQ_FOREACH(rkt, &rk->rk_topics, rkt_link) {
                shptr_rd_kafka_toppar_t *s_rktp;
                rd_kafka_toppar_t *rktp;
                int r;

                rd_kafka_topic_rdlock(rkt);
                s_rktp = rkt->rkt_ua;
                if (s_rktp)
                        s_rktp = rd_kafka_toppar_keep(
                                rd_kafka_toppar_s2i(s_rktp));
                rd_kafka_topic_rdunlock(rkt);

                if (unlikely(!s_rktp))
                        continue;


                rktp = rd_kafka_toppar_s2i(s_rktp);
                rd_kafka_toppar_lock(rktp);

                r = rd_kafka_msgq_len(&rktp->rktp_msgq);
                rd_kafka_dr_msgq(rkt, &rktp->rktp_msgq,
                                 RD_KAFKA_RESP_ERR__PURGE_QUEUE);
                rd_kafka_toppar_unlock(rktp);
                rd_kafka_toppar_destroy(s_rktp);

                if (r > 0) {
                        msg_cnt += r;
                        part_cnt++;
                }
        }
        rd_kafka_rdunlock(rk);

        rd_kafka_dbg(rk, QUEUE|RD_KAFKA_DBG_TOPIC, "PURGEQ",
                     "Purged %i message(s) from %d UA-partition(s)",
                     msg_cnt, part_cnt);
}
