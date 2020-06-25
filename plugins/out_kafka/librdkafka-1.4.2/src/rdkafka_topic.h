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

#ifndef _RDKAFKA_TOPIC_H_
#define _RDKAFKA_TOPIC_H_

#include "rdlist.h"

extern const char *rd_kafka_topic_state_names[];


/* rd_kafka_itopic_t: internal representation of a topic */
struct rd_kafka_itopic_s {
	TAILQ_ENTRY(rd_kafka_itopic_s) rkt_link;

	rd_refcnt_t        rkt_refcnt;

	rwlock_t           rkt_lock;
	rd_kafkap_str_t   *rkt_topic;

	shptr_rd_kafka_toppar_t  *rkt_ua;  /* unassigned partition */
	shptr_rd_kafka_toppar_t **rkt_p;
	int32_t            rkt_partition_cnt;

        rd_list_t          rkt_desp;              /* Desired partitions
                                                   * that are not yet seen
                                                   * in the cluster. */

	rd_ts_t            rkt_ts_metadata; /* Timestamp of last metadata
					     * update for this topic. */

        mtx_t              rkt_app_lock;    /* Protects rkt_app_* */
        rd_kafka_topic_t *rkt_app_rkt;      /* A shared topic pointer
                                             * to be used for callbacks
                                             * to the application. */

	int               rkt_app_refcnt;   /* Number of active rkt's new()ed
					     * by application. */

	enum {
		RD_KAFKA_TOPIC_S_UNKNOWN,   /* No cluster information yet */
		RD_KAFKA_TOPIC_S_EXISTS,    /* Topic exists in cluster */
		RD_KAFKA_TOPIC_S_NOTEXISTS, /* Topic is not known in cluster */
	} rkt_state;

        int               rkt_flags;
#define RD_KAFKA_TOPIC_F_LEADER_UNAVAIL   0x1 /* Leader lost/unavailable
                                               * for at least one partition. */

	rd_kafka_t       *rkt_rk;

        rd_avg_t          rkt_avg_batchsize; /**< Average batch size */
        rd_avg_t          rkt_avg_batchcnt;  /**< Average batch message count */

        shptr_rd_kafka_itopic_t *rkt_shptr_app; /* Application's topic_new() */

	rd_kafka_topic_conf_t rkt_conf;
};

#define rd_kafka_topic_rdlock(rkt)     rwlock_rdlock(&(rkt)->rkt_lock)
#define rd_kafka_topic_wrlock(rkt)     rwlock_wrlock(&(rkt)->rkt_lock)
#define rd_kafka_topic_rdunlock(rkt)   rwlock_rdunlock(&(rkt)->rkt_lock)
#define rd_kafka_topic_wrunlock(rkt)   rwlock_wrunlock(&(rkt)->rkt_lock)


/* Converts a shptr..itopic_t to an internal itopic_t */
#define rd_kafka_topic_s2i(s_rkt) rd_shared_ptr_obj(s_rkt)

/* Converts an application topic_t (a shptr topic) to an internal itopic_t */
#define rd_kafka_topic_a2i(app_rkt) \
        rd_kafka_topic_s2i((shptr_rd_kafka_itopic_t *)app_rkt)

/* Converts a shptr..itopic_t to an app topic_t (they are the same thing) */
#define rd_kafka_topic_s2a(s_rkt) ((rd_kafka_topic_t *)(s_rkt))

/* Converts an app topic_t to a shptr..itopic_t (they are the same thing) */
#define rd_kafka_topic_a2s(app_rkt) ((shptr_rd_kafka_itopic_t *)(app_rkt))





/**
 * Returns a shared pointer for the topic.
 */
#define rd_kafka_topic_keep(rkt) \
        rd_shared_ptr_get(rkt, &(rkt)->rkt_refcnt, shptr_rd_kafka_itopic_t)

/* Same, but casts to an app topic_t */
#define rd_kafka_topic_keep_a(rkt)                                      \
        ((rd_kafka_topic_t *)rd_shared_ptr_get(rkt, &(rkt)->rkt_refcnt, \
                                               shptr_rd_kafka_itopic_t))

void rd_kafka_topic_destroy_final (rd_kafka_itopic_t *rkt);


/**
 * Frees a shared pointer previously returned by ..topic_keep()
 */
static RD_INLINE RD_UNUSED void
rd_kafka_topic_destroy0 (shptr_rd_kafka_itopic_t *s_rkt) {
        rd_shared_ptr_put(s_rkt,
                          &rd_kafka_topic_s2i(s_rkt)->rkt_refcnt,
                          rd_kafka_topic_destroy_final(
                                  rd_kafka_topic_s2i(s_rkt)));
}


shptr_rd_kafka_itopic_t *rd_kafka_topic_new0 (rd_kafka_t *rk, const char *topic,
                                              rd_kafka_topic_conf_t *conf,
                                              int *existing, int do_lock);

shptr_rd_kafka_itopic_t *rd_kafka_topic_find_fl (const char *func, int line,
                                                 rd_kafka_t *rk,
                                                 const char *topic,
                                                 int do_lock);
shptr_rd_kafka_itopic_t *rd_kafka_topic_find0_fl (const char *func, int line,
                                                  rd_kafka_t *rk,
                                                  const rd_kafkap_str_t *topic);
#define rd_kafka_topic_find(rk,topic,do_lock)                           \
        rd_kafka_topic_find_fl(__FUNCTION__,__LINE__,rk,topic,do_lock)
#define rd_kafka_topic_find0(rk,topic)                                  \
        rd_kafka_topic_find0_fl(__FUNCTION__,__LINE__,rk,topic)
int rd_kafka_topic_cmp_s_rkt (const void *_a, const void *_b);

void rd_kafka_topic_partitions_remove (rd_kafka_itopic_t *rkt);

void rd_kafka_topic_metadata_none (rd_kafka_itopic_t *rkt);

int rd_kafka_topic_metadata_update2 (rd_kafka_broker_t *rkb,
                                     const struct rd_kafka_metadata_topic *mdt);

void rd_kafka_topic_scan_all (rd_kafka_t *rk, rd_ts_t now);


typedef struct rd_kafka_topic_info_s {
	const char *topic;          /**< Allocated along with struct */
	int   partition_cnt;
} rd_kafka_topic_info_t;


int rd_kafka_topic_info_cmp (const void *_a, const void *_b);
rd_kafka_topic_info_t *rd_kafka_topic_info_new (const char *topic,
						int partition_cnt);
void rd_kafka_topic_info_destroy (rd_kafka_topic_info_t *ti);

int rd_kafka_topic_match (rd_kafka_t *rk, const char *pattern,
			  const char *topic);

int rd_kafka_toppar_broker_update (rd_kafka_toppar_t *rktp,
                                   int32_t broker_id, rd_kafka_broker_t *rkb,
                                   const char *reason);

int rd_kafka_toppar_delegate_to_leader (rd_kafka_toppar_t *rktp);

rd_kafka_resp_err_t
rd_kafka_topics_leader_query_sync (rd_kafka_t *rk, int all_topics,
                                   const rd_list_t *topics, int timeout_ms);
void rd_kafka_topic_leader_query0 (rd_kafka_t *rk, rd_kafka_itopic_t *rkt,
                                   int do_rk_lock);
#define rd_kafka_topic_leader_query(rk,rkt) \
        rd_kafka_topic_leader_query0(rk,rkt,1/*lock*/)

#define rd_kafka_topic_fast_leader_query(rk) \
        rd_kafka_metadata_fast_leader_query(rk)

void rd_kafka_local_topics_to_list (rd_kafka_t *rk, rd_list_t *topics);

void rd_ut_kafka_topic_set_topic_exists (rd_kafka_itopic_t *rkt,
                                         int partition_cnt,
                                         int32_t leader_id);

#endif /* _RDKAFKA_TOPIC_H_ */
