/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012,2013 Magnus Edenhill
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

#include "rd.h"
#include "rdkafka_int.h"
#include "rdkafka_msg.h"
#include "rdkafka_topic.h"
#include "rdkafka_partition.h"
#include "rdkafka_broker.h"
#include "rdkafka_cgrp.h"
#include "rdkafka_metadata.h"
#include "rdlog.h"
#include "rdsysqueue.h"
#include "rdtime.h"
#include "rdregex.h"

#if WITH_ZSTD
#include <zstd.h>
#endif


const char *rd_kafka_topic_state_names[] = {
        "unknown",
        "exists",
        "notexists"
};



static int
rd_kafka_topic_metadata_update (rd_kafka_itopic_t *rkt,
                                const struct rd_kafka_metadata_topic *mdt,
                                rd_ts_t ts_insert);


/**
 * @brief Increases the app's topic reference count and returns the app pointer.
 *
 * The app refcounts are implemented separately from the librdkafka refcounts
 * and to play nicely with shptr we keep one single shptr for the application
 * and increase/decrease a separate rkt_app_refcnt to keep track of its use.
 *
 * This only covers topic_new() & topic_destroy().
 * The topic_t exposed in rd_kafka_message_t is NOT covered and is handled
 * like a standard shptr -> app pointer conversion (keep_a()).
 *
 * @returns a (new) rkt app reference.
 *
 * @remark \p rkt and \p s_rkt are mutually exclusive.
 */
static rd_kafka_topic_t *rd_kafka_topic_keep_app (rd_kafka_itopic_t *rkt) {
	rd_kafka_topic_t *app_rkt;

        mtx_lock(&rkt->rkt_app_lock);
	rkt->rkt_app_refcnt++;
        if (!(app_rkt = rkt->rkt_app_rkt))
                app_rkt = rkt->rkt_app_rkt = rd_kafka_topic_keep_a(rkt);
        mtx_unlock(&rkt->rkt_app_lock);

	return app_rkt;
}

/**
 * @brief drop rkt app reference
 */
static void rd_kafka_topic_destroy_app (rd_kafka_topic_t *app_rkt) {
	rd_kafka_itopic_t *rkt = rd_kafka_topic_a2i(app_rkt);
        shptr_rd_kafka_itopic_t *s_rkt = NULL;

        mtx_lock(&rkt->rkt_app_lock);
	rd_kafka_assert(NULL, rkt->rkt_app_refcnt > 0);
	rkt->rkt_app_refcnt--;
        if (unlikely(rkt->rkt_app_refcnt == 0)) {
		rd_kafka_assert(NULL, rkt->rkt_app_rkt);
		s_rkt = rd_kafka_topic_a2s(app_rkt);
                rkt->rkt_app_rkt = NULL;
	}
        mtx_unlock(&rkt->rkt_app_lock);

	if (s_rkt) /* final app reference lost, destroy the shared ptr. */
		rd_kafka_topic_destroy0(s_rkt);
}


/**
 * Final destructor for topic. Refcnt must be 0.
 */
void rd_kafka_topic_destroy_final (rd_kafka_itopic_t *rkt) {

	rd_kafka_assert(rkt->rkt_rk, rd_refcnt_get(&rkt->rkt_refcnt) == 0);

        rd_kafka_wrlock(rkt->rkt_rk);
        TAILQ_REMOVE(&rkt->rkt_rk->rk_topics, rkt, rkt_link);
        rkt->rkt_rk->rk_topic_cnt--;
        rd_kafka_wrunlock(rkt->rkt_rk);

        rd_kafka_assert(rkt->rkt_rk, rd_list_empty(&rkt->rkt_desp));
        rd_list_destroy(&rkt->rkt_desp);

        rd_avg_destroy(&rkt->rkt_avg_batchsize);
        rd_avg_destroy(&rkt->rkt_avg_batchcnt);

	if (rkt->rkt_topic)
		rd_kafkap_str_destroy(rkt->rkt_topic);

	rd_kafka_anyconf_destroy(_RK_TOPIC, &rkt->rkt_conf);

        mtx_destroy(&rkt->rkt_app_lock);
	rwlock_destroy(&rkt->rkt_lock);
        rd_refcnt_destroy(&rkt->rkt_refcnt);

	rd_free(rkt);
}

/**
 * Application destroy
 */
void rd_kafka_topic_destroy (rd_kafka_topic_t *app_rkt) {
	rd_kafka_topic_destroy_app(app_rkt);
}


/**
 * Finds and returns a topic based on its name, or NULL if not found.
 * The 'rkt' refcount is increased by one and the caller must call
 * rd_kafka_topic_destroy() when it is done with the topic to decrease
 * the refcount.
 *
 * Locality: any thread
 */
shptr_rd_kafka_itopic_t *rd_kafka_topic_find_fl (const char *func, int line,
                                                rd_kafka_t *rk,
                                                const char *topic, int do_lock){
	rd_kafka_itopic_t *rkt;
        shptr_rd_kafka_itopic_t *s_rkt = NULL;

        if (do_lock)
                rd_kafka_rdlock(rk);
	TAILQ_FOREACH(rkt, &rk->rk_topics, rkt_link) {
		if (!rd_kafkap_str_cmp_str(rkt->rkt_topic, topic)) {
                        s_rkt = rd_kafka_topic_keep(rkt);
			break;
		}
	}
        if (do_lock)
                rd_kafka_rdunlock(rk);

	return s_rkt;
}

/**
 * Same semantics as ..find() but takes a Kafka protocol string instead.
 */
shptr_rd_kafka_itopic_t *rd_kafka_topic_find0_fl (const char *func, int line,
                                                 rd_kafka_t *rk,
                                                 const rd_kafkap_str_t *topic) {
	rd_kafka_itopic_t *rkt;
        shptr_rd_kafka_itopic_t *s_rkt = NULL;

	rd_kafka_rdlock(rk);
	TAILQ_FOREACH(rkt, &rk->rk_topics, rkt_link) {
		if (!rd_kafkap_str_cmp(rkt->rkt_topic, topic)) {
                        s_rkt = rd_kafka_topic_keep(rkt);
			break;
		}
	}
	rd_kafka_rdunlock(rk);

	return s_rkt;
}


/**
 * Compare shptr_rd_kafka_itopic_t for underlying itopic_t
 */
int rd_kafka_topic_cmp_s_rkt (const void *_a, const void *_b) {
        shptr_rd_kafka_itopic_t *a = (void *)_a, *b = (void *)_b;
        rd_kafka_itopic_t *rkt_a = rd_kafka_topic_s2i(a);
        rd_kafka_itopic_t *rkt_b = rd_kafka_topic_s2i(b);

        if (rkt_a == rkt_b)
                return 0;

        return rd_kafkap_str_cmp(rkt_a->rkt_topic, rkt_b->rkt_topic);
}


/**
 * Create new topic handle. 
 *
 * Locality: any
 */
shptr_rd_kafka_itopic_t *rd_kafka_topic_new0 (rd_kafka_t *rk,
                                              const char *topic,
                                              rd_kafka_topic_conf_t *conf,
                                              int *existing,
                                              int do_lock) {
	rd_kafka_itopic_t *rkt;
        shptr_rd_kafka_itopic_t *s_rkt;
        const struct rd_kafka_metadata_cache_entry *rkmce;
        const char *conf_err;

	/* Verify configuration.
	 * Maximum topic name size + headers must never exceed message.max.bytes
	 * which is min-capped to 1000.
	 * See rd_kafka_broker_produce_toppar() and rdkafka_conf.c */
	if (!topic || strlen(topic) > 512) {
		if (conf)
			rd_kafka_topic_conf_destroy(conf);
		rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__INVALID_ARG,
					EINVAL);
		return NULL;
	}

	if (do_lock)
                rd_kafka_wrlock(rk);
	if ((s_rkt = rd_kafka_topic_find(rk, topic, 0/*no lock*/))) {
                if (do_lock)
                        rd_kafka_wrunlock(rk);
		if (conf)
			rd_kafka_topic_conf_destroy(conf);
                if (existing)
                        *existing = 1;
		return s_rkt;
        }

        if (!conf) {
                if (rk->rk_conf.topic_conf)
                        conf = rd_kafka_topic_conf_dup(rk->rk_conf.topic_conf);
                else
                        conf = rd_kafka_topic_conf_new();
        }


        /* Verify and finalize topic configuration */
        if ((conf_err = rd_kafka_topic_conf_finalize(rk->rk_type,
                                                     &rk->rk_conf, conf))) {
                if (do_lock)
                        rd_kafka_wrunlock(rk);
                /* Incompatible configuration settings */
                rd_kafka_log(rk, LOG_ERR, "TOPICCONF",
                             "Incompatible configuration settings "
                             "for topic \"%s\": %s", topic, conf_err);
                rd_kafka_topic_conf_destroy(conf);
                rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__INVALID_ARG, EINVAL);
                return NULL;
        }

        if (existing)
                *existing = 0;

	rkt = rd_calloc(1, sizeof(*rkt));

	rkt->rkt_topic     = rd_kafkap_str_new(topic, -1);
	rkt->rkt_rk        = rk;

	rkt->rkt_conf = *conf;
	rd_free(conf); /* explicitly not rd_kafka_topic_destroy()
                        * since we dont want to rd_free internal members,
                        * just the placeholder. The internal members
                        * were copied on the line above. */

        /* Partitioner */
        if (!rkt->rkt_conf.partitioner) {
                const struct {
                        const char *str;
                        void *part;
                } part_map[] = {
                        { "random",
                          (void *)rd_kafka_msg_partitioner_random },
                        { "consistent",
                          (void *)rd_kafka_msg_partitioner_consistent },
                        { "consistent_random",
                          (void *)rd_kafka_msg_partitioner_consistent_random },
                        { "murmur2",
                          (void *)rd_kafka_msg_partitioner_murmur2 },
                        { "murmur2_random",
                          (void *)rd_kafka_msg_partitioner_murmur2_random },
                        { "fnv1a",
                          (void *)rd_kafka_msg_partitioner_fnv1a },
                        { "fnv1a_random",
                          (void *)rd_kafka_msg_partitioner_fnv1a_random },
                        { NULL }
                };
                int i;

                /* Use "partitioner" configuration property string, if set */
                for (i = 0 ; rkt->rkt_conf.partitioner_str && part_map[i].str ;
                     i++) {
                        if (!strcmp(rkt->rkt_conf.partitioner_str,
                                    part_map[i].str)) {
                                rkt->rkt_conf.partitioner = part_map[i].part;
                                break;
                        }
                }

                /* Default partitioner: consistent_random */
                if (!rkt->rkt_conf.partitioner) {
                        /* Make sure part_map matched something, otherwise
                         * there is a discreprency between this code
                         * and the validator in rdkafka_conf.c */
                        assert(!rkt->rkt_conf.partitioner_str);

                        rkt->rkt_conf.partitioner =
                                rd_kafka_msg_partitioner_consistent_random;
                }
        }

        if (rkt->rkt_conf.queuing_strategy == RD_KAFKA_QUEUE_FIFO)
                rkt->rkt_conf.msg_order_cmp = rd_kafka_msg_cmp_msgid;
        else
                rkt->rkt_conf.msg_order_cmp = rd_kafka_msg_cmp_msgid_lifo;

	if (rkt->rkt_conf.compression_codec == RD_KAFKA_COMPRESSION_INHERIT)
		rkt->rkt_conf.compression_codec = rk->rk_conf.compression_codec;

        /* Translate compression level to library-specific level and check
         * upper bound */
        switch (rkt->rkt_conf.compression_codec) {
#if WITH_ZLIB
        case RD_KAFKA_COMPRESSION_GZIP:
                if (rkt->rkt_conf.compression_level == RD_KAFKA_COMPLEVEL_DEFAULT)
                        rkt->rkt_conf.compression_level = Z_DEFAULT_COMPRESSION;
                else if (rkt->rkt_conf.compression_level > RD_KAFKA_COMPLEVEL_GZIP_MAX)
                        rkt->rkt_conf.compression_level =
                                RD_KAFKA_COMPLEVEL_GZIP_MAX;
                break;
#endif
        case RD_KAFKA_COMPRESSION_LZ4:
                if (rkt->rkt_conf.compression_level == RD_KAFKA_COMPLEVEL_DEFAULT)
                        /* LZ4 has no notion of system-wide default compression
                         * level, use zero in this case */
                        rkt->rkt_conf.compression_level = 0;
                else if (rkt->rkt_conf.compression_level > RD_KAFKA_COMPLEVEL_LZ4_MAX)
                        rkt->rkt_conf.compression_level =
                                RD_KAFKA_COMPLEVEL_LZ4_MAX;
                break;
#if WITH_ZSTD
        case RD_KAFKA_COMPRESSION_ZSTD:
                if (rkt->rkt_conf.compression_level == RD_KAFKA_COMPLEVEL_DEFAULT)
                        rkt->rkt_conf.compression_level = 3;
                else if (rkt->rkt_conf.compression_level > RD_KAFKA_COMPLEVEL_ZSTD_MAX)
                        rkt->rkt_conf.compression_level =
                                RD_KAFKA_COMPLEVEL_ZSTD_MAX;
                break;
#endif
        case RD_KAFKA_COMPRESSION_SNAPPY:
        default:
                /* Compression level has no effect in this case */
                rkt->rkt_conf.compression_level = RD_KAFKA_COMPLEVEL_DEFAULT;
        }
	
        rd_avg_init(&rkt->rkt_avg_batchsize, RD_AVG_GAUGE, 0,
                    rk->rk_conf.max_msg_size, 2,
                    rk->rk_conf.stats_interval_ms ? 1 : 0);
        rd_avg_init(&rkt->rkt_avg_batchcnt, RD_AVG_GAUGE, 0,
                    rk->rk_conf.batch_num_messages, 2,
                    rk->rk_conf.stats_interval_ms ? 1 : 0);

	rd_kafka_dbg(rk, TOPIC, "TOPIC", "New local topic: %.*s",
		     RD_KAFKAP_STR_PR(rkt->rkt_topic));

        rd_list_init(&rkt->rkt_desp, 16, NULL);
        rd_refcnt_init(&rkt->rkt_refcnt, 0);

        s_rkt = rd_kafka_topic_keep(rkt);

	rwlock_init(&rkt->rkt_lock);
        mtx_init(&rkt->rkt_app_lock, mtx_plain);

	/* Create unassigned partition */
	rkt->rkt_ua = rd_kafka_toppar_new(rkt, RD_KAFKA_PARTITION_UA);

	TAILQ_INSERT_TAIL(&rk->rk_topics, rkt, rkt_link);
	rk->rk_topic_cnt++;

        /* Populate from metadata cache. */
        if ((rkmce = rd_kafka_metadata_cache_find(rk, topic, 1/*valid*/))) {
                if (existing)
                        *existing = 1;

                rd_kafka_topic_metadata_update(rkt, &rkmce->rkmce_mtopic,
                                               rkmce->rkmce_ts_insert);
        }

        if (do_lock)
                rd_kafka_wrunlock(rk);

	return s_rkt;
}



/**
 * Create new app topic handle.
 *
 * Locality: application thread
 */
rd_kafka_topic_t *rd_kafka_topic_new (rd_kafka_t *rk, const char *topic,
                                      rd_kafka_topic_conf_t *conf) {
        shptr_rd_kafka_itopic_t *s_rkt;
        rd_kafka_itopic_t *rkt;
        rd_kafka_topic_t *app_rkt;
        int existing;

        s_rkt = rd_kafka_topic_new0(rk, topic, conf, &existing, 1/*lock*/);
        if (!s_rkt)
                return NULL;

        rkt = rd_kafka_topic_s2i(s_rkt);

        /* Save a shared pointer to be used in callbacks. */
	app_rkt = rd_kafka_topic_keep_app(rkt);

        /* Query for the topic leader (async) */
        if (!existing)
                rd_kafka_topic_leader_query(rk, rkt);

        /* Drop our reference since there is already/now a rkt_app_rkt */
        rd_kafka_topic_destroy0(s_rkt);

        return app_rkt;
}



/**
 * Sets the state for topic.
 * NOTE: rd_kafka_topic_wrlock(rkt) MUST be held
 */
static void rd_kafka_topic_set_state (rd_kafka_itopic_t *rkt, int state) {

        if ((int)rkt->rkt_state == state)
                return;

        rd_kafka_dbg(rkt->rkt_rk, TOPIC, "STATE",
                     "Topic %s changed state %s -> %s",
                     rkt->rkt_topic->str,
                     rd_kafka_topic_state_names[rkt->rkt_state],
                     rd_kafka_topic_state_names[state]);
        rkt->rkt_state = state;
}

/**
 * Returns the name of a topic.
 * NOTE:
 *   The topic Kafka String representation is crafted with an extra byte
 *   at the end for the Nul that is not included in the length, this way
 *   we can use the topic's String directly.
 *   This is not true for Kafka Strings read from the network.
 */
const char *rd_kafka_topic_name (const rd_kafka_topic_t *app_rkt) {
        const rd_kafka_itopic_t *rkt = rd_kafka_topic_a2i(app_rkt);
	return rkt->rkt_topic->str;
}


/**
 * @brief Update the broker that a topic+partition is delegated to.
 *
 * @param broker_id The id of the broker to associate the toppar with.
 * @param rkb A reference to the broker to delegate to (must match
 *        broker_id) or NULL if the toppar should be undelegated for
 *        any reason.
 * @param reason Human-readable reason for the update, included in debug log.
 *
 * @returns 1 if the broker delegation was changed, -1 if the broker
 *          delegation was changed and is now undelegated, else 0.
 *
 * @locks caller must have rd_kafka_toppar_lock(rktp)
 * @locality any
 */
int rd_kafka_toppar_broker_update (rd_kafka_toppar_t *rktp,
                                   int32_t broker_id,
                                   rd_kafka_broker_t *rkb,
                                   const char *reason) {

        rktp->rktp_broker_id = broker_id;

	if (!rkb) {
		int had_broker = rktp->rktp_broker ? 1 : 0;
		rd_kafka_toppar_broker_delegate(rktp, NULL);
		return had_broker ? -1 : 0;
	}

	if (rktp->rktp_broker) {
		if (rktp->rktp_broker == rkb) {
			/* No change in broker */
			return 0;
		}

                rd_kafka_dbg(rktp->rktp_rkt->rkt_rk,
                             TOPIC|RD_KAFKA_DBG_FETCH, "TOPICUPD",
                             "Topic %s [%"PRId32"]: migrating from "
                             "broker %"PRId32" to %"PRId32" (leader is "
                             "%"PRId32"): %s",
                             rktp->rktp_rkt->rkt_topic->str,
                             rktp->rktp_partition,
                             rktp->rktp_broker->rkb_nodeid,
                             rkb->rkb_nodeid,
                             rktp->rktp_leader_id,
                             reason);
	}

	rd_kafka_toppar_broker_delegate(rktp, rkb);

	return 1;
}


/**
 * @brief Update a topic+partition for a new leader.
 *
 * @remark If a toppar is currently delegated to a preferred replica,
 *         it will not be delegated to the leader broker unless there
 *         has been a leader change.
 *
 * @param leader_id The id of the new leader broker.
 * @param leader A reference to the leader broker or NULL if the
 *        toppar should be undelegated for any reason.
 *
 * @returns 1 if the broker delegation was changed, -1 if the broker
 *        delegation was changed and is now undelegated, else 0.
 *
 * @locks caller must have rd_kafka_topic_wrlock(rkt)
 *        AND NOT rd_kafka_toppar_lock(rktp)
 * @locality any
 */
static int rd_kafka_toppar_leader_update (rd_kafka_itopic_t *rkt,
                                          int32_t partition,
                                          int32_t leader_id,
                                          rd_kafka_broker_t *leader) {
	rd_kafka_toppar_t *rktp;
        shptr_rd_kafka_toppar_t *s_rktp;
	int r;

	s_rktp = rd_kafka_toppar_get(rkt, partition, 0);
        if (unlikely(!s_rktp)) {
                /* Have only seen this in issue #132.
                 * Probably caused by corrupt broker state. */
                rd_kafka_log(rkt->rkt_rk, LOG_WARNING, "BROKER",
                             "%s [%"PRId32"] is unknown "
                             "(partition_cnt %i): "
                             "ignoring leader (%"PRId32") update",
                             rkt->rkt_topic->str, partition,
                             rkt->rkt_partition_cnt, leader_id);
                return -1;
        }

        rktp = rd_kafka_toppar_s2i(s_rktp);

        rd_kafka_toppar_lock(rktp);

        if (leader != NULL &&
            rktp->rktp_broker != NULL &&
            rktp->rktp_broker->rkb_source != RD_KAFKA_INTERNAL &&
            rktp->rktp_broker != leader &&
            rktp->rktp_leader_id == leader_id) {
                rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "BROKER",
                        "Topic %s [%"PRId32"]: leader %"PRId32" unchanged, "
                        "not migrating away from preferred replica %"PRId32,
                        rktp->rktp_rkt->rkt_topic->str,
                        rktp->rktp_partition,
                        leader_id, rktp->rktp_broker_id);
                r = 0;
        } else {
                rktp->rktp_leader_id = leader_id;
                if (rktp->rktp_leader)
                        rd_kafka_broker_destroy(rktp->rktp_leader);
                if (leader)
                        rd_kafka_broker_keep(leader);
                rktp->rktp_leader = leader;
                r = rd_kafka_toppar_broker_update(rktp, leader_id, leader,
                                                  "leader updated");
        }

        rd_kafka_toppar_unlock(rktp);

        rd_kafka_toppar_destroy(s_rktp);  /* from get() */

	return r;
}


/**
 * @brief Revert the topic+partition delegation to the leader from
 *        a preferred replica.
 *
 * @returns 1 if the broker delegation was changed, -1 if the broker
 *          delegation was changed and is now undelegated, else 0.
 *
 * @locks none
 * @locality any
 */
int rd_kafka_toppar_delegate_to_leader (rd_kafka_toppar_t *rktp) {
        rd_kafka_broker_t *leader;
        int r;

        rd_kafka_rdlock(rktp->rktp_rkt->rkt_rk);
        rd_kafka_toppar_lock(rktp);

        rd_assert(rktp->rktp_leader_id != rktp->rktp_broker_id);

        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, TOPIC, "BROKER",
                "Topic %s [%"PRId32"]: Reverting from preferred "
                "replica %"PRId32" to leader %"PRId32,
                rktp->rktp_rkt->rkt_topic->str, rktp->rktp_partition,
                rktp->rktp_broker_id, rktp->rktp_leader_id);

        leader = rd_kafka_broker_find_by_nodeid(rktp->rktp_rkt->rkt_rk,
                                                rktp->rktp_leader_id);

        rd_kafka_toppar_unlock(rktp);
        rd_kafka_rdunlock(rktp->rktp_rkt->rkt_rk);

        rd_kafka_toppar_lock(rktp);
        r = rd_kafka_toppar_broker_update(
                rktp, rktp->rktp_leader_id, leader,
                "reverting from preferred replica to leader");
        rd_kafka_toppar_unlock(rktp);

        if (leader)
                rd_kafka_broker_destroy(leader);

        return r;
}


/**
 * @brief Update the number of partitions for a topic and takes actions
 *        accordingly.
 *
 * @returns 1 if the partition count changed, else 0.
 *
 * @locks rd_kafka_topic_wrlock(rkt) MUST be held.
 */
static int rd_kafka_topic_partition_cnt_update (rd_kafka_itopic_t *rkt,
						int32_t partition_cnt) {
	rd_kafka_t *rk = rkt->rkt_rk;
	shptr_rd_kafka_toppar_t **rktps;
        shptr_rd_kafka_toppar_t *s_rktp;
	rd_kafka_toppar_t *rktp;
	int32_t i;

	if (likely(rkt->rkt_partition_cnt == partition_cnt))
		return 0; /* No change in partition count */

        if (unlikely(rkt->rkt_partition_cnt != 0 &&
                     !rd_kafka_terminating(rkt->rkt_rk)))
                rd_kafka_log(rk, LOG_NOTICE, "PARTCNT",
                             "Topic %s partition count changed "
                             "from %"PRId32" to %"PRId32,
                             rkt->rkt_topic->str,
                             rkt->rkt_partition_cnt, partition_cnt);
        else
                rd_kafka_dbg(rk, TOPIC, "PARTCNT",
                             "Topic %s partition count changed "
                             "from %"PRId32" to %"PRId32,
                             rkt->rkt_topic->str,
                             rkt->rkt_partition_cnt, partition_cnt);


	/* Create and assign new partition list */
	if (partition_cnt > 0)
		rktps = rd_calloc(partition_cnt, sizeof(*rktps));
	else
		rktps = NULL;

	for (i = 0 ; i < partition_cnt ; i++) {
		if (i >= rkt->rkt_partition_cnt) {
			/* New partition. Check if its in the list of
			 * desired partitions first. */

                        s_rktp = rd_kafka_toppar_desired_get(rkt, i);

                        rktp = s_rktp ? rd_kafka_toppar_s2i(s_rktp) : NULL;
                        if (rktp) {
				rd_kafka_toppar_lock(rktp);
                                rktp->rktp_flags &=
                                        ~(RD_KAFKA_TOPPAR_F_UNKNOWN |
                                          RD_KAFKA_TOPPAR_F_REMOVE);

                                /* Remove from desp list since the
                                 * partition is now known. */
                                rd_kafka_toppar_desired_unlink(rktp);
                                rd_kafka_toppar_unlock(rktp);
			} else {
				s_rktp = rd_kafka_toppar_new(rkt, i);
                                rktp = rd_kafka_toppar_s2i(s_rktp);

                                rd_kafka_toppar_lock(rktp);
                                rktp->rktp_flags &=
                                        ~(RD_KAFKA_TOPPAR_F_UNKNOWN |
                                          RD_KAFKA_TOPPAR_F_REMOVE);
                                rd_kafka_toppar_unlock(rktp);
                        }
			rktps[i] = s_rktp;
		} else {
			/* Existing partition, grab our own reference. */
			rktps[i] = rd_kafka_toppar_keep(
				rd_kafka_toppar_s2i(rkt->rkt_p[i]));
			/* Loose previous ref */
			rd_kafka_toppar_destroy(rkt->rkt_p[i]);
		}
	}

        /* Propagate notexist errors for desired partitions */
        RD_LIST_FOREACH(s_rktp, &rkt->rkt_desp, i) {
                rd_kafka_dbg(rkt->rkt_rk, TOPIC, "DESIRED",
                             "%s [%"PRId32"]: "
                             "desired partition does not exist in cluster",
                             rkt->rkt_topic->str,
                             rd_kafka_toppar_s2i(s_rktp)->rktp_partition);
                rd_kafka_toppar_enq_error(rd_kafka_toppar_s2i(s_rktp),
                                          RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION,
                                          "desired partition does not exist "
                                          "in cluster");

        }

	/* Remove excessive partitions */
	for (i = partition_cnt ; i < rkt->rkt_partition_cnt ; i++) {
		s_rktp = rkt->rkt_p[i];
                rktp = rd_kafka_toppar_s2i(s_rktp);

		rd_kafka_dbg(rkt->rkt_rk, TOPIC, "REMOVE",
			     "%s [%"PRId32"] no longer reported in metadata",
			     rkt->rkt_topic->str, rktp->rktp_partition);

		rd_kafka_toppar_lock(rktp);

                rktp->rktp_flags |= RD_KAFKA_TOPPAR_F_UNKNOWN;

		if (rktp->rktp_flags & RD_KAFKA_TOPPAR_F_DESIRED) {
                        rd_kafka_dbg(rkt->rkt_rk, TOPIC, "DESIRED",
                                     "Topic %s [%"PRId32"] is desired "
                                     "but no longer known: "
                                     "moving back on desired list",
                                     rkt->rkt_topic->str, rktp->rktp_partition);

                        /* If this is a desired partition move it back on to
                         * the desired list since partition is no longer known*/
                        rd_kafka_toppar_desired_link(rktp);

                        if (!rd_kafka_terminating(rkt->rkt_rk))
                                rd_kafka_toppar_enq_error(
                                        rktp,
                                        RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION,
                                        "desired partition no longer exists");

			rd_kafka_toppar_broker_delegate(rktp, NULL);

		} else {
			/* Tell handling broker to let go of the toppar */
			rd_kafka_toppar_broker_leave_for_remove(rktp);
		}

		rd_kafka_toppar_unlock(rktp);

		rd_kafka_toppar_destroy(s_rktp);
	}

	if (rkt->rkt_p)
		rd_free(rkt->rkt_p);

	rkt->rkt_p = rktps;

	rkt->rkt_partition_cnt = partition_cnt;

	return 1;
}



/**
 * Topic 'rkt' does not exist: propagate to interested parties.
 * The topic's state must have been set to NOTEXISTS and
 * rd_kafka_topic_partition_cnt_update() must have been called prior to
 * calling this function.
 *
 * Locks: rd_kafka_topic_*lock() must be held.
 */
static void rd_kafka_topic_propagate_notexists (rd_kafka_itopic_t *rkt,
                                                rd_kafka_resp_err_t err) {
        shptr_rd_kafka_toppar_t *s_rktp;
        int i;

        if (rkt->rkt_rk->rk_type != RD_KAFKA_CONSUMER)
                return;


        /* Notify consumers that the topic doesn't exist. */
        RD_LIST_FOREACH(s_rktp, &rkt->rkt_desp, i)
                rd_kafka_toppar_enq_error(rd_kafka_toppar_s2i(s_rktp), err,
                                          "topic does not exist");
}


/**
 * Assign messages on the UA partition to available partitions.
 * Locks: rd_kafka_topic_*lock() must be held.
 */
static void rd_kafka_topic_assign_uas (rd_kafka_itopic_t *rkt,
                                       rd_kafka_resp_err_t err) {
	rd_kafka_t *rk = rkt->rkt_rk;
	shptr_rd_kafka_toppar_t *s_rktp_ua;
        rd_kafka_toppar_t *rktp_ua;
	rd_kafka_msg_t *rkm, *tmp;
	rd_kafka_msgq_t uas = RD_KAFKA_MSGQ_INITIALIZER(uas);
	rd_kafka_msgq_t failed = RD_KAFKA_MSGQ_INITIALIZER(failed);
	int cnt;

	if (rkt->rkt_rk->rk_type != RD_KAFKA_PRODUCER)
		return;

	s_rktp_ua = rd_kafka_toppar_get(rkt, RD_KAFKA_PARTITION_UA, 0);
	if (unlikely(!s_rktp_ua)) {
		rd_kafka_dbg(rk, TOPIC, "ASSIGNUA",
			     "No UnAssigned partition available for %s",
			     rkt->rkt_topic->str);
		return;
	}

        rktp_ua = rd_kafka_toppar_s2i(s_rktp_ua);

	/* Assign all unassigned messages to new topics. */
        rd_kafka_toppar_lock(rktp_ua);

        rd_kafka_dbg(rk, TOPIC, "PARTCNT",
                     "Partitioning %i unassigned messages in topic %.*s to "
                     "%"PRId32" partitions",
                     rktp_ua->rktp_msgq.rkmq_msg_cnt,
                     RD_KAFKAP_STR_PR(rkt->rkt_topic),
                     rkt->rkt_partition_cnt);

	rd_kafka_msgq_move(&uas, &rktp_ua->rktp_msgq);
	cnt = uas.rkmq_msg_cnt;
	rd_kafka_toppar_unlock(rktp_ua);

	TAILQ_FOREACH_SAFE(rkm, &uas.rkmq_msgs, rkm_link, tmp) {
		/* Fast-path for failing messages with forced partition */
		if (rkm->rkm_partition != RD_KAFKA_PARTITION_UA &&
		    rkm->rkm_partition >= rkt->rkt_partition_cnt &&
		    rkt->rkt_state != RD_KAFKA_TOPIC_S_UNKNOWN) {
			rd_kafka_msgq_enq(&failed, rkm);
			continue;
		}

		if (unlikely(rd_kafka_msg_partitioner(rkt, rkm, 0) != 0)) {
			/* Desired partition not available */
			rd_kafka_msgq_enq(&failed, rkm);
		}
	}

        rd_kafka_dbg(rk, TOPIC, "UAS",
                     "%i/%i messages were partitioned in topic %s",
                     cnt - failed.rkmq_msg_cnt, cnt, rkt->rkt_topic->str);

        if (failed.rkmq_msg_cnt > 0) {
                /* Fail the messages */
                rd_kafka_dbg(rk, TOPIC, "UAS",
                             "%"PRId32"/%i messages failed partitioning "
                             "in topic %s",
                             failed.rkmq_msg_cnt, cnt, rkt->rkt_topic->str);
		rd_kafka_dr_msgq(rkt, &failed,
				 rkt->rkt_state == RD_KAFKA_TOPIC_S_NOTEXISTS ?
				 err :
				 RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION);
	}

	rd_kafka_toppar_destroy(s_rktp_ua); /* from get() */
}


/**
 * Received metadata request contained no information about topic 'rkt'
 * and thus indicates the topic is not available in the cluster.
 */
void rd_kafka_topic_metadata_none (rd_kafka_itopic_t *rkt) {
	rd_kafka_topic_wrlock(rkt);

	if (unlikely(rd_kafka_terminating(rkt->rkt_rk))) {
		/* Dont update metadata while terminating, do this
		 * after acquiring lock for proper synchronisation */
		rd_kafka_topic_wrunlock(rkt);
		return;
	}

	rkt->rkt_ts_metadata = rd_clock();

        rd_kafka_topic_set_state(rkt, RD_KAFKA_TOPIC_S_NOTEXISTS);

        rkt->rkt_flags &= ~RD_KAFKA_TOPIC_F_LEADER_UNAVAIL;

	/* Update number of partitions */
	rd_kafka_topic_partition_cnt_update(rkt, 0);

        /* Purge messages with forced partition */
        rd_kafka_topic_assign_uas(rkt, RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC);

        /* Propagate nonexistent topic info */
        rd_kafka_topic_propagate_notexists(rkt,
                                           RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC);

	rd_kafka_topic_wrunlock(rkt);
}


/**
 * @brief Update a topic from metadata.
 *
 * @param ts_age absolute age (timestamp) of metadata.
 * @returns 1 if the number of partitions changed, 0 if not, and -1 if the
 *          topic is unknown.

 *
 * @locks rd_kafka_*lock() MUST be held.
 */
static int
rd_kafka_topic_metadata_update (rd_kafka_itopic_t *rkt,
                                const struct rd_kafka_metadata_topic *mdt,
                                rd_ts_t ts_age) {
        rd_kafka_t *rk = rkt->rkt_rk;
	int upd = 0;
	int j;
        rd_kafka_broker_t **partbrokers;
        int leader_cnt = 0;
        int old_state;

	if (mdt->err != RD_KAFKA_RESP_ERR_NO_ERROR)
		rd_kafka_dbg(rk, TOPIC|RD_KAFKA_DBG_METADATA, "METADATA",
			   "Error in metadata reply for "
			   "topic %s (PartCnt %i): %s",
			   rkt->rkt_topic->str, mdt->partition_cnt,
			   rd_kafka_err2str(mdt->err));

        if (unlikely(rd_kafka_terminating(rk))) {
                /* Dont update metadata while terminating, do this
                 * after acquiring lock for proper synchronisation */
                return -1;
        }

        /* Look up brokers before acquiring rkt lock to preserve lock order */
        partbrokers = rd_alloca(mdt->partition_cnt * sizeof(*partbrokers));

	for (j = 0 ; j < mdt->partition_cnt ; j++) {
		if (mdt->partitions[j].leader == -1) {
                        partbrokers[j] = NULL;
			continue;
		}

                partbrokers[j] =
                        rd_kafka_broker_find_by_nodeid(rk,
                                                       mdt->partitions[j].
                                                       leader);
	}


	rd_kafka_topic_wrlock(rkt);

        old_state = rkt->rkt_state;
	rkt->rkt_ts_metadata = ts_age;

	/* Set topic state.
         * UNKNOWN_TOPIC_OR_PART may indicate that auto.create.topics failed */
	if (mdt->err == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART ||
            mdt->err == RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION/*invalid topic*/)
                rd_kafka_topic_set_state(rkt, RD_KAFKA_TOPIC_S_NOTEXISTS);
        else if (mdt->partition_cnt > 0)
                rd_kafka_topic_set_state(rkt, RD_KAFKA_TOPIC_S_EXISTS);

	/* Update number of partitions, but not if there are
	 * (possibly intermittent) errors (e.g., "Leader not available"). */
	if (mdt->err == RD_KAFKA_RESP_ERR_NO_ERROR) {
		upd += rd_kafka_topic_partition_cnt_update(rkt,
							   mdt->partition_cnt);

                /* If the metadata times out for a topic (because all brokers
                 * are down) the state will transition to S_UNKNOWN.
                 * When updated metadata is eventually received there might
                 * not be any change to partition count or leader,
                 * but there may still be messages in the UA partition that
                 * needs to be assigned, so trigger an update for this case too.
                 * Issue #1985. */
                if (old_state == RD_KAFKA_TOPIC_S_UNKNOWN)
                        upd++;
        }

	/* Update leader for each partition */
	for (j = 0 ; j < mdt->partition_cnt ; j++) {
                int r;
		rd_kafka_broker_t *leader;

		rd_kafka_dbg(rk, TOPIC|RD_KAFKA_DBG_METADATA, "METADATA",
			   "  Topic %s partition %i Leader %"PRId32,
			   rkt->rkt_topic->str,
			   mdt->partitions[j].id,
			   mdt->partitions[j].leader);

		leader = partbrokers[j];
		partbrokers[j] = NULL;

		/* Update leader for partition */
		r = rd_kafka_toppar_leader_update(rkt,
						   mdt->partitions[j].id,
                                                   mdt->partitions[j].leader,
						   leader);

                upd += (r != 0 ? 1 : 0);

                if (leader) {
                        if (r != -1)
                                leader_cnt++;
                        /* Drop reference to broker (from find()) */
                        rd_kafka_broker_destroy(leader);
                }
        }

        /* If all partitions have leaders we can turn off fast leader query. */
        if (mdt->partition_cnt > 0 && leader_cnt == mdt->partition_cnt)
                rkt->rkt_flags &= ~RD_KAFKA_TOPIC_F_LEADER_UNAVAIL;

	if (mdt->err != RD_KAFKA_RESP_ERR_NO_ERROR && rkt->rkt_partition_cnt) {
                /* (Possibly intermittent) topic-wide error:
                 * remove leaders for partitions */

		for (j = 0 ; j < rkt->rkt_partition_cnt ; j++) {
                        rd_kafka_toppar_t *rktp;
			if (!rkt->rkt_p[j])
                                continue;

                        rktp = rd_kafka_toppar_s2i(rkt->rkt_p[j]);
                        rd_kafka_toppar_lock(rktp);
                        rd_kafka_toppar_broker_delegate(rktp, NULL);
                        rd_kafka_toppar_unlock(rktp);
                }
        }

	/* Try to assign unassigned messages to new partitions, or fail them */
	if (upd > 0 || rkt->rkt_state == RD_KAFKA_TOPIC_S_NOTEXISTS)
		rd_kafka_topic_assign_uas(rkt, mdt->err ?
                                          mdt->err :
                                          RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC);

        /* Trigger notexists propagation */
        if (old_state != (int)rkt->rkt_state &&
            rkt->rkt_state == RD_KAFKA_TOPIC_S_NOTEXISTS)
                rd_kafka_topic_propagate_notexists(
                        rkt,
                        mdt->err ? mdt->err : RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC);

	rd_kafka_topic_wrunlock(rkt);

	/* Loose broker references */
	for (j = 0 ; j < mdt->partition_cnt ; j++)
		if (partbrokers[j])
			rd_kafka_broker_destroy(partbrokers[j]);


	return upd;
}

/**
 * @brief Update topic by metadata, if topic is locally known.
 * @sa rd_kafka_topic_metadata_update()
 * @locks none
 */
int
rd_kafka_topic_metadata_update2 (rd_kafka_broker_t *rkb,
                                 const struct rd_kafka_metadata_topic *mdt) {
        rd_kafka_itopic_t *rkt;
        shptr_rd_kafka_itopic_t *s_rkt;
        int r;

        rd_kafka_wrlock(rkb->rkb_rk);
        if (!(s_rkt = rd_kafka_topic_find(rkb->rkb_rk,
                                          mdt->topic, 0/*!lock*/))) {
                rd_kafka_wrunlock(rkb->rkb_rk);
                return -1; /* Ignore topics that we dont have locally. */
        }

        rkt = rd_kafka_topic_s2i(s_rkt);

        r = rd_kafka_topic_metadata_update(rkt, mdt, rd_clock());

        rd_kafka_wrunlock(rkb->rkb_rk);

        rd_kafka_topic_destroy0(s_rkt); /* from find() */

        return r;
}



/**
 * @returns a list of all partitions (s_rktp's) for a topic.
 * @remark rd_kafka_topic_*lock() MUST be held.
 */
static rd_list_t *rd_kafka_topic_get_all_partitions (rd_kafka_itopic_t *rkt) {
	rd_list_t *list;
	shptr_rd_kafka_toppar_t *s_rktp;
	int i;

        list = rd_list_new(rkt->rkt_partition_cnt +
                           rd_list_cnt(&rkt->rkt_desp) + 1/*ua*/, NULL);

	for (i = 0 ; i < rkt->rkt_partition_cnt ; i++)
		rd_list_add(list, rd_kafka_toppar_keep(
				    rd_kafka_toppar_s2i(rkt->rkt_p[i])));

	RD_LIST_FOREACH(s_rktp, &rkt->rkt_desp, i)
		rd_list_add(list, rd_kafka_toppar_keep(
				    rd_kafka_toppar_s2i(s_rktp)));

	if (rkt->rkt_ua)
		rd_list_add(list, rd_kafka_toppar_keep(
				    rd_kafka_toppar_s2i(rkt->rkt_ua)));

	return list;
}




/**
 * Remove all partitions from a topic, including the ua.
 * Must only be called during rd_kafka_t termination.
 *
 * Locality: main thread
 */
void rd_kafka_topic_partitions_remove (rd_kafka_itopic_t *rkt) {
        shptr_rd_kafka_toppar_t *s_rktp;
        shptr_rd_kafka_itopic_t *s_rkt;
	rd_list_t *partitions;
	int i;

	/* Purge messages for all partitions outside the topic_wrlock since
	 * a message can hold a reference to the topic_t and thus
	 * would trigger a recursive lock dead-lock. */
	rd_kafka_topic_rdlock(rkt);
	partitions = rd_kafka_topic_get_all_partitions(rkt);
	rd_kafka_topic_rdunlock(rkt);

	RD_LIST_FOREACH(s_rktp, partitions, i) {
		rd_kafka_toppar_t *rktp = rd_kafka_toppar_s2i(s_rktp);

		rd_kafka_toppar_lock(rktp);
		rd_kafka_msgq_purge(rkt->rkt_rk, &rktp->rktp_msgq);
		rd_kafka_toppar_purge_queues(rktp);
		rd_kafka_toppar_unlock(rktp);

		rd_kafka_toppar_destroy(s_rktp);
	}
	rd_list_destroy(partitions);

	s_rkt = rd_kafka_topic_keep(rkt);
	rd_kafka_topic_wrlock(rkt);

	/* Setting the partition count to 0 moves all partitions to
	 * the desired list (rktp_desp). */
        rd_kafka_topic_partition_cnt_update(rkt, 0);

        /* Now clean out the desired partitions list.
         * Use reverse traversal to avoid excessive memory shuffling
         * in rd_list_remove() */
        RD_LIST_FOREACH_REVERSE(s_rktp, &rkt->rkt_desp, i) {
		rd_kafka_toppar_t *rktp = rd_kafka_toppar_s2i(s_rktp);
		/* Our reference */
		shptr_rd_kafka_toppar_t *s_rktp2 = rd_kafka_toppar_keep(rktp);
                rd_kafka_toppar_lock(rktp);
                rd_kafka_toppar_desired_del(rktp);
                rd_kafka_toppar_unlock(rktp);
                rd_kafka_toppar_destroy(s_rktp2);
        }

        rd_kafka_assert(rkt->rkt_rk, rkt->rkt_partition_cnt == 0);

	if (rkt->rkt_p)
		rd_free(rkt->rkt_p);

	rkt->rkt_p = NULL;
	rkt->rkt_partition_cnt = 0;

        if ((s_rktp = rkt->rkt_ua)) {
                rkt->rkt_ua = NULL;
                rd_kafka_toppar_destroy(s_rktp);
	}

	rd_kafka_topic_wrunlock(rkt);

	rd_kafka_topic_destroy0(s_rkt);
}



/**
 * @returns the broker state (as a human readable string) if a query
 *          for the partition leader is necessary, else NULL.
 * @locality any
 * @locks rd_kafka_toppar_lock MUST be held
 */
static const char *rd_kafka_toppar_needs_query (rd_kafka_t *rk,
                                                rd_kafka_toppar_t *rktp) {
        int broker_state;

        if (!rktp->rktp_broker)
                return "not delegated";

        if (rktp->rktp_broker->rkb_source == RD_KAFKA_INTERNAL)
                return "internal";

        broker_state = rd_kafka_broker_get_state(rktp->rktp_broker);

        if (broker_state >= RD_KAFKA_BROKER_STATE_UP)
                return NULL;

        if (!rk->rk_conf.sparse_connections)
                return "down";

        /* Partition assigned to broker but broker does not
         * need a persistent connection, this typically means
         * the partition is not being fetched or not being produced to,
         * so there is no need to re-query the leader. */
        if (broker_state == RD_KAFKA_BROKER_STATE_INIT)
                return NULL;

        /* This is most likely a persistent broker,
         * which means the partition leader should probably
         * be re-queried to see if it needs changing. */
        return "down";
}



/**
 * @brief Scan all topics and partitions for:
 *  - timed out messages in UA partitions.
 *  - topics that needs to be created on the broker.
 *  - topics who's metadata is too old.
 *  - partitions with unknown leaders that require leader query.
 *
 * @locality rdkafka main thread
 */
void rd_kafka_topic_scan_all (rd_kafka_t *rk, rd_ts_t now) {
	rd_kafka_itopic_t *rkt;
	rd_kafka_toppar_t *rktp;
        shptr_rd_kafka_toppar_t *s_rktp;
        rd_list_t query_topics;

        rd_list_init(&query_topics, 0, rd_free);

	rd_kafka_rdlock(rk);
	TAILQ_FOREACH(rkt, &rk->rk_topics, rkt_link) {
		int p;
                int query_this = 0;
                rd_kafka_msgq_t timedout = RD_KAFKA_MSGQ_INITIALIZER(timedout);

		rd_kafka_topic_wrlock(rkt);

                /* Check if metadata information has timed out. */
                if (rkt->rkt_state != RD_KAFKA_TOPIC_S_UNKNOWN &&
                    !rd_kafka_metadata_cache_topic_get(
                            rk, rkt->rkt_topic->str, 1/*only valid*/)) {
                        rd_kafka_dbg(rk, TOPIC, "NOINFO",
                                     "Topic %s metadata information timed out "
                                     "(%"PRId64"ms old)",
                                     rkt->rkt_topic->str,
                                     (rd_clock() - rkt->rkt_ts_metadata)/1000);
                        rd_kafka_topic_set_state(rkt, RD_KAFKA_TOPIC_S_UNKNOWN);

                        query_this = 1;
                } else if (rkt->rkt_state == RD_KAFKA_TOPIC_S_UNKNOWN) {
                        rd_kafka_dbg(rk, TOPIC, "NOINFO",
                                     "Topic %s metadata information unknown",
                                     rkt->rkt_topic->str);
                        query_this = 1;
                }

                /* Just need a read-lock from here on. */
                rd_kafka_topic_wrunlock(rkt);
                rd_kafka_topic_rdlock(rkt);

                if (rkt->rkt_partition_cnt == 0) {
                        /* If this partition is unknown by brokers try
                         * to create it by sending a topic-specific
                         * metadata request.
                         * This requires "auto.create.topics.enable=true"
                         * on the brokers. */
                        rd_kafka_dbg(rk, TOPIC, "NOINFO",
                                     "Topic %s partition count is zero: "
                                     "should refresh metadata",
                                     rkt->rkt_topic->str);

                        query_this = 1;
                }

		for (p = RD_KAFKA_PARTITION_UA ;
		     p < rkt->rkt_partition_cnt ; p++) {

                        if (!(s_rktp = rd_kafka_toppar_get(
                                      rkt, p,
                                      p == RD_KAFKA_PARTITION_UA ?
                                      rd_true : rd_false)))
                                continue;

                        rktp = rd_kafka_toppar_s2i(s_rktp);
			rd_kafka_toppar_lock(rktp);

                        /* Check that partition is delegated to a broker that
                         * is up, else add topic to query list. */
                        if (p != RD_KAFKA_PARTITION_UA) {
                                const char *leader_reason =
                                        rd_kafka_toppar_needs_query(rk, rktp);

                                if (leader_reason) {
                                        rd_kafka_dbg(rk, TOPIC, "QRYLEADER",
                                                     "Topic %s [%"PRId32"]: "
                                                     "broker is %s: re-query",
                                                     rkt->rkt_topic->str,
                                                     rktp->rktp_partition,
                                                     leader_reason);
                                           query_this = 1;
                                }
                        } else {
                                if (rk->rk_type == RD_KAFKA_PRODUCER) {
                                        /* Scan UA partition for message
                                         * timeouts.
                                         * Proper partitions are scanned by
                                         * their toppar broker thread. */
                                        rd_kafka_msgq_age_scan(rktp,
                                                               &rktp->rktp_msgq,
                                                               &timedout, now,
                                                               NULL);
                                }
                        }

			rd_kafka_toppar_unlock(rktp);
			rd_kafka_toppar_destroy(s_rktp);
		}

                rd_kafka_topic_rdunlock(rkt);

                /* Propagate delivery reports for timed out messages */
                if (rd_kafka_msgq_len(&timedout) > 0) {
                        rd_kafka_dbg(rk, MSG, "TIMEOUT",
                                     "%s: %d message(s) timed out",
                                     rkt->rkt_topic->str,
                                     rd_kafka_msgq_len(&timedout));
                        rd_kafka_dr_msgq(rkt, &timedout,
                                         RD_KAFKA_RESP_ERR__MSG_TIMED_OUT);
                }

                /* Need to re-query this topic's leader. */
                if (query_this &&
                    !rd_list_find(&query_topics, rkt->rkt_topic->str,
                                  (void *)strcmp))
                        rd_list_add(&query_topics,
                                    rd_strdup(rkt->rkt_topic->str));

        }
        rd_kafka_rdunlock(rk);

        if (!rd_list_empty(&query_topics))
                rd_kafka_metadata_refresh_topics(rk, NULL, &query_topics,
                                                 1/*force even if cached
                                                    * info exists*/,
                                                 "refresh unavailable topics");
        rd_list_destroy(&query_topics);
}


/**
 * Locks: rd_kafka_topic_*lock() must be held.
 */
int rd_kafka_topic_partition_available (const rd_kafka_topic_t *app_rkt,
					int32_t partition) {
	int avail;
	shptr_rd_kafka_toppar_t *s_rktp;
        rd_kafka_toppar_t *rktp;
        rd_kafka_broker_t *rkb;

	s_rktp = rd_kafka_toppar_get(rd_kafka_topic_a2i(app_rkt),
                                     partition, 0/*no ua-on-miss*/);
	if (unlikely(!s_rktp))
		return 0;

        rktp = rd_kafka_toppar_s2i(s_rktp);
        rkb = rd_kafka_toppar_broker(rktp, 1/*proper broker*/);
        avail = rkb ? 1 : 0;
        if (rkb)
                rd_kafka_broker_destroy(rkb);
	rd_kafka_toppar_destroy(s_rktp);
	return avail;
}


void *rd_kafka_topic_opaque (const rd_kafka_topic_t *app_rkt) {
        return rd_kafka_topic_a2i(app_rkt)->rkt_conf.opaque;
}

int rd_kafka_topic_info_cmp (const void *_a, const void *_b) {
	const rd_kafka_topic_info_t *a = _a, *b = _b;
	int r;

	if ((r = strcmp(a->topic, b->topic)))
		return r;

        return RD_CMP(a->partition_cnt, b->partition_cnt);
}


/**
 * Allocate new topic_info.
 * \p topic is copied.
 */
rd_kafka_topic_info_t *rd_kafka_topic_info_new (const char *topic,
						int partition_cnt) {
	rd_kafka_topic_info_t *ti;
	size_t tlen = strlen(topic) + 1;

	/* Allocate space for the topic along with the struct */
	ti = rd_malloc(sizeof(*ti) + tlen);
	ti->topic = (char *)(ti+1);
	memcpy((char *)ti->topic, topic, tlen);
	ti->partition_cnt = partition_cnt;

	return ti;
}

/**
 * Destroy/free topic_info
 */
void rd_kafka_topic_info_destroy (rd_kafka_topic_info_t *ti) {
	rd_free(ti);
}


/**
 * @brief Match \p topic to \p pattern.
 *
 * If pattern begins with "^" it is considered a regexp,
 * otherwise a simple string comparison is performed.
 *
 * @returns 1 on match, else 0.
 */
int rd_kafka_topic_match (rd_kafka_t *rk, const char *pattern,
			  const char *topic) {
	char errstr[128];

	if (*pattern == '^') {
		int r = rd_regex_match(pattern, topic, errstr, sizeof(errstr));
		if (unlikely(r == -1))
			rd_kafka_dbg(rk, TOPIC, "TOPICREGEX",
				     "Topic \"%s\" regex \"%s\" "
				     "matching failed: %s",
				     topic, pattern, errstr);
		return r == 1;
	} else
		return !strcmp(pattern, topic);
}









/**
 * @brief Trigger broker metadata query for topic leader.
 *
 * @locks none
 */
void rd_kafka_topic_leader_query0 (rd_kafka_t *rk, rd_kafka_itopic_t *rkt,
                                   int do_rk_lock) {
        rd_list_t topics;

        rd_list_init(&topics, 1, rd_free);
        rd_list_add(&topics, rd_strdup(rkt->rkt_topic->str));

        rd_kafka_metadata_refresh_topics(rk, NULL, &topics,
                                         0/*dont force*/, "leader query");

        rd_list_destroy(&topics);
}



/**
 * @brief Populate list \p topics with the topic names (strdupped char *) of
 *        all locally known topics.
 *
 * @remark \p rk lock MUST NOT be held
 */
void rd_kafka_local_topics_to_list (rd_kafka_t *rk, rd_list_t *topics) {
        rd_kafka_itopic_t *rkt;

        rd_kafka_rdlock(rk);
        rd_list_grow(topics, rk->rk_topic_cnt);
        TAILQ_FOREACH(rkt, &rk->rk_topics, rkt_link)
                rd_list_add(topics, rd_strdup(rkt->rkt_topic->str));
        rd_kafka_rdunlock(rk);
}


/**
 * @brief Unit test helper to set a topic's state to EXISTS
 *        with the given number of partitions.
 */
void rd_ut_kafka_topic_set_topic_exists (rd_kafka_itopic_t *rkt,
                                         int partition_cnt,
                                         int32_t leader_id) {
        struct rd_kafka_metadata_topic mdt = {
                .topic = (char *)rkt->rkt_topic->str,
                .partition_cnt = partition_cnt
        };
        int i;

        mdt.partitions = rd_alloca(sizeof(*mdt.partitions) * partition_cnt);

        for (i = 0 ; i < partition_cnt ; i++) {
                memset(&mdt.partitions[i], 0, sizeof(mdt.partitions[i]));
                mdt.partitions[i].id = i;
                mdt.partitions[i].leader = leader_id;
        }

        rd_kafka_wrlock(rkt->rkt_rk);
        rd_kafka_metadata_cache_topic_update(rkt->rkt_rk, &mdt);
        rd_kafka_topic_metadata_update(rkt, &mdt, rd_clock());
        rd_kafka_wrunlock(rkt->rkt_rk);
}
