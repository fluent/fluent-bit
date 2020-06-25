/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2013, Magnus Edenhill
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
#include "rdkafka_topic.h"
#include "rdkafka_broker.h"
#include "rdkafka_request.h"
#include "rdkafka_metadata.h"

#include <string.h>
/**
 * @{
 *
 * @brief Metadata cache
 *
 * The metadata cache consists of cached topic metadata as
 * retrieved from the cluster using MetadataRequest.
 *
 * The topic cache entries are made up \c struct rd_kafka_metadata_cache_entry
 * each containing the topic name, a copy of the topic's metadata
 * and a cache expiry time.
 *
 * On update any previous entry for the topic are removed and replaced
 * with a new entry.
 *
 * The cache is also populated when the topic metadata is being requested
 * for specific topics, this will not interfere with existing cache entries
 * for topics, but for any topics not currently in the cache a new
 * entry will be added with a flag (RD_KAFKA_METADATA_CACHE_VALID(rkmce))
 * indicating that the entry is waiting to be populated by the MetadataResponse.
 *
 * The cache is locked in its entirety with rd_kafka_wr/rdlock() by the caller
 * and the returned cache entry must only be accessed during the duration
 * of the lock.
 *
 */

static void rd_kafka_metadata_cache_propagate_changes (rd_kafka_t *rk);


/**
 * @brief Remove and free cache entry.
 *
 * @remark The expiry timer is not updated, for simplicity.
 * @locks rd_kafka_wrlock()
 */
static RD_INLINE void
rd_kafka_metadata_cache_delete (rd_kafka_t *rk,
                                struct rd_kafka_metadata_cache_entry *rkmce,
                                int unlink_avl) {
        if (unlink_avl)
                RD_AVL_REMOVE_ELM(&rk->rk_metadata_cache.rkmc_avl, rkmce);
        TAILQ_REMOVE(&rk->rk_metadata_cache.rkmc_expiry, rkmce, rkmce_link);
        rd_kafka_assert(NULL, rk->rk_metadata_cache.rkmc_cnt > 0);
        rk->rk_metadata_cache.rkmc_cnt--;

        rd_free(rkmce);
}

/**
 * @brief Delete cache entry by topic name
 * @locks rd_kafka_wrlock()
 * @returns 1 if entry was found and removed, else 0.
 */
static int rd_kafka_metadata_cache_delete_by_name (rd_kafka_t *rk,
                                                    const char *topic) {
        struct rd_kafka_metadata_cache_entry *rkmce;

        rkmce = rd_kafka_metadata_cache_find(rk, topic, 1);
        if (rkmce)
                rd_kafka_metadata_cache_delete(rk, rkmce, 1);
        return rkmce ? 1 : 0;
}

static int rd_kafka_metadata_cache_evict (rd_kafka_t *rk);

/**
 * @brief Cache eviction timer callback.
 * @locality rdkafka main thread
 * @locks NOT rd_kafka_*lock()
 */
static void rd_kafka_metadata_cache_evict_tmr_cb (rd_kafka_timers_t *rkts,
                                                  void *arg) {
        rd_kafka_t *rk = arg;

        rd_kafka_wrlock(rk);
        rd_kafka_metadata_cache_evict(rk);
        rd_kafka_wrunlock(rk);
}


/**
 * @brief Evict timed out entries from cache and rearm timer for
 *        next expiry.
 *
 * @returns the number of entries evicted.
 *
 * @locks rd_kafka_wrlock()
 */
static int rd_kafka_metadata_cache_evict (rd_kafka_t *rk) {
        int cnt = 0;
        rd_ts_t now = rd_clock();
        struct rd_kafka_metadata_cache_entry *rkmce;

        while ((rkmce = TAILQ_FIRST(&rk->rk_metadata_cache.rkmc_expiry)) &&
               rkmce->rkmce_ts_expires <= now) {
                rd_kafka_metadata_cache_delete(rk, rkmce, 1);
                cnt++;
        }

        if (rkmce)
                rd_kafka_timer_start(&rk->rk_timers,
                                     &rk->rk_metadata_cache.rkmc_expiry_tmr,
                                     rkmce->rkmce_ts_expires - now,
                                     rd_kafka_metadata_cache_evict_tmr_cb,
                                     rk);
        else
                rd_kafka_timer_stop(&rk->rk_timers,
                                    &rk->rk_metadata_cache.rkmc_expiry_tmr, 1);

        rd_kafka_dbg(rk, METADATA, "METADATA",
                     "Expired %d entries from metadata cache "
                     "(%d entries remain)",
                     cnt, rk->rk_metadata_cache.rkmc_cnt);

        if (cnt)
                rd_kafka_metadata_cache_propagate_changes(rk);

        return cnt;
}


/**
 * @brief Find cache entry by topic name
 *
 * @param valid: entry must be valid (not hint)
 *
 * @locks rd_kafka_*lock()
 */
struct rd_kafka_metadata_cache_entry *
rd_kafka_metadata_cache_find (rd_kafka_t *rk, const char *topic, int valid) {
        struct rd_kafka_metadata_cache_entry skel, *rkmce;
        skel.rkmce_mtopic.topic = (char *)topic;
        rkmce = RD_AVL_FIND(&rk->rk_metadata_cache.rkmc_avl, &skel);
        if (rkmce && (!valid || RD_KAFKA_METADATA_CACHE_VALID(rkmce)))
                return rkmce;
        return NULL;
}


/**
 * @brief Partition (id) comparator
 */
int rd_kafka_metadata_partition_id_cmp (const void *_a,
                                        const void *_b) {
        const rd_kafka_metadata_partition_t *a = _a, *b = _b;
        return RD_CMP(a->id, b->id);
}


/**
 * @brief Add (and replace) cache entry for topic.
 *
 * This makes a copy of \p topic
 *
 * @locks rd_kafka_wrlock()
 */
static struct rd_kafka_metadata_cache_entry *
rd_kafka_metadata_cache_insert (rd_kafka_t *rk,
                                const rd_kafka_metadata_topic_t *mtopic,
                                rd_ts_t now, rd_ts_t ts_expires) {
        struct rd_kafka_metadata_cache_entry *rkmce, *old;
        size_t topic_len;
        rd_tmpabuf_t tbuf;
        int i;

        /* Metadata is stored in one contigious buffer where structs and
         * and pointed-to fields are layed out in a memory aligned fashion.
         * rd_tmpabuf_t provides the infrastructure to do this.
         * Because of this we copy all the structs verbatim but
         * any pointer fields needs to be copied explicitly to update
         * the pointer address. */
        topic_len = strlen(mtopic->topic) + 1;
        rd_tmpabuf_new(&tbuf,
                       RD_ROUNDUP(sizeof(*rkmce), 8) +
                       RD_ROUNDUP(topic_len, 8) +
                       (mtopic->partition_cnt *
                        RD_ROUNDUP(sizeof(*mtopic->partitions), 8)),
                       1/*assert on fail*/);

        rkmce = rd_tmpabuf_alloc(&tbuf, sizeof(*rkmce));

        rkmce->rkmce_mtopic = *mtopic;

        /* Copy topic name and update pointer */
        rkmce->rkmce_mtopic.topic = rd_tmpabuf_write_str(&tbuf, mtopic->topic);

        /* Copy partition array and update pointer */
        rkmce->rkmce_mtopic.partitions =
                rd_tmpabuf_write(&tbuf, mtopic->partitions,
                                 mtopic->partition_cnt *
                                 sizeof(*mtopic->partitions));

        /* Clear uncached fields. */
        for (i = 0 ; i < mtopic->partition_cnt ; i++) {
                rkmce->rkmce_mtopic.partitions[i].replicas = NULL;
                rkmce->rkmce_mtopic.partitions[i].replica_cnt = 0;
                rkmce->rkmce_mtopic.partitions[i].isrs = NULL;
                rkmce->rkmce_mtopic.partitions[i].isr_cnt = 0;
        }

        /* Sort partitions for future bsearch() lookups. */
        qsort(rkmce->rkmce_mtopic.partitions,
              rkmce->rkmce_mtopic.partition_cnt,
              sizeof(*rkmce->rkmce_mtopic.partitions),
              rd_kafka_metadata_partition_id_cmp);

        TAILQ_INSERT_TAIL(&rk->rk_metadata_cache.rkmc_expiry,
                          rkmce, rkmce_link);
        rk->rk_metadata_cache.rkmc_cnt++;
        rkmce->rkmce_ts_expires = ts_expires;
        rkmce->rkmce_ts_insert = now;

        /* Insert (and replace existing) entry. */
        old = RD_AVL_INSERT(&rk->rk_metadata_cache.rkmc_avl, rkmce,
                            rkmce_avlnode);
        if (old)
                rd_kafka_metadata_cache_delete(rk, old, 0);

        /* Explicitly not freeing the tmpabuf since rkmce points to its
         * memory. */
        return rkmce;
}


/**
 * @brief Purge the metadata cache
 *
 * @locks rd_kafka_wrlock()
 */
static void rd_kafka_metadata_cache_purge (rd_kafka_t *rk) {
        struct rd_kafka_metadata_cache_entry *rkmce;
        int was_empty = TAILQ_EMPTY(&rk->rk_metadata_cache.rkmc_expiry);

        while ((rkmce = TAILQ_FIRST(&rk->rk_metadata_cache.rkmc_expiry)))
                rd_kafka_metadata_cache_delete(rk, rkmce, 1);

        rd_kafka_timer_stop(&rk->rk_timers,
                            &rk->rk_metadata_cache.rkmc_expiry_tmr, 1);

        if (!was_empty)
                rd_kafka_metadata_cache_propagate_changes(rk);
}


/**
 * @brief Start or update the cache expiry timer.
 *        Typically done after a series of cache_topic_update()
 *
 * @locks rd_kafka_wrlock()
 */
void rd_kafka_metadata_cache_expiry_start (rd_kafka_t *rk) {
        struct rd_kafka_metadata_cache_entry *rkmce;

        if ((rkmce = TAILQ_FIRST(&rk->rk_metadata_cache.rkmc_expiry)))
                rd_kafka_timer_start(&rk->rk_timers,
                                     &rk->rk_metadata_cache.rkmc_expiry_tmr,
                                     rkmce->rkmce_ts_expires - rd_clock(),
                                     rd_kafka_metadata_cache_evict_tmr_cb,
                                     rk);
}

/**
 * @brief Update the metadata cache for a single topic
 *        with the provided metadata.
 *        If the topic has an error the existing entry is removed
 *        and no new entry is added, which avoids the topic to be
 *        suppressed in upcoming metadata requests because being in the cache.
 *        In other words: we want to re-query errored topics.
 *
 * @remark The cache expiry timer will not be updated/started,
 *         call rd_kafka_metadata_cache_expiry_start() instead.
 *
 * @locks rd_kafka_wrlock()
 */
void
rd_kafka_metadata_cache_topic_update (rd_kafka_t *rk,
                                      const rd_kafka_metadata_topic_t *mdt) {
        rd_ts_t now = rd_clock();
        rd_ts_t ts_expires = now + (rk->rk_conf.metadata_max_age_ms * 1000);
        int changed = 1;

        if (!mdt->err)
                rd_kafka_metadata_cache_insert(rk, mdt, now, ts_expires);
        else
                changed = rd_kafka_metadata_cache_delete_by_name(rk,
                                                                 mdt->topic);

        if (changed)
                rd_kafka_metadata_cache_propagate_changes(rk);
}


/**
 * @brief Update the metadata cache with the provided metadata.
 *
 * @param abs_update int: absolute update: purge cache before updating.
 *
 * @locks rd_kafka_wrlock()
 */
void rd_kafka_metadata_cache_update (rd_kafka_t *rk,
                                     const rd_kafka_metadata_t *md,
                                     int abs_update) {
        struct rd_kafka_metadata_cache_entry *rkmce;
        rd_ts_t now = rd_clock();
        rd_ts_t ts_expires = now + (rk->rk_conf.metadata_max_age_ms * 1000);
        int i;

        rd_kafka_dbg(rk, METADATA, "METADATA",
                     "%s of metadata cache with %d topic(s)",
                     abs_update ? "Absolute update" : "Update",
                     md->topic_cnt);

        if (abs_update)
                rd_kafka_metadata_cache_purge(rk);


        for (i = 0 ; i < md->topic_cnt ; i++)
                rd_kafka_metadata_cache_insert(rk, &md->topics[i], now,
                                               ts_expires);

        /* Update expiry timer */
        if ((rkmce = TAILQ_FIRST(&rk->rk_metadata_cache.rkmc_expiry)))
                rd_kafka_timer_start(&rk->rk_timers,
                                     &rk->rk_metadata_cache.rkmc_expiry_tmr,
                                     rkmce->rkmce_ts_expires - now,
                                     rd_kafka_metadata_cache_evict_tmr_cb,
                                     rk);

        if (md->topic_cnt > 0)
                rd_kafka_metadata_cache_propagate_changes(rk);
}


/**
 * @brief Remove cache hints for topics in \p topics
 *        This is done when the Metadata response has been parsed and
 *        replaced hints with existing topic information, thus this will
 *        only remove unmatched topics from the cache.
 *
 * @locks rd_kafka_wrlock()
 */
void rd_kafka_metadata_cache_purge_hints (rd_kafka_t *rk,
                                          const rd_list_t *topics) {
        const char *topic;
        int i;
        int cnt = 0;

        RD_LIST_FOREACH(topic, topics, i) {
                struct rd_kafka_metadata_cache_entry *rkmce;

                if (!(rkmce = rd_kafka_metadata_cache_find(rk, topic,
                                                           0/*any*/)) ||
                    RD_KAFKA_METADATA_CACHE_VALID(rkmce))
                        continue;

                rd_kafka_metadata_cache_delete(rk, rkmce, 1/*unlink avl*/);
                cnt++;
        }

        if (cnt > 0) {
                rd_kafka_dbg(rk, METADATA, "METADATA",
                             "Purged %d/%d cached topic hint(s)",
                             cnt, rd_list_cnt(topics));
                rd_kafka_metadata_cache_propagate_changes(rk);
        }
}


/**
 * @brief Inserts a non-valid entry for topics in \p topics indicating
 *        that a MetadataRequest is in progress.
 *        This avoids sending multiple MetadataRequests for the same topics
 *        if there are already outstanding requests, see
 *        \c rd_kafka_metadata_refresh_topics().
 *
 * @remark These non-valid cache entries' expire time is set to the
 *         MetadataRequest timeout.
 *
 * @param dst rd_list_t(char *topicname): if not NULL: populated with
 *        topics that were added as hints to cache, e.q., topics to query.
 * @param topics rd_list_t(char *topicname)
 * @param replace int: replace existing valid entries
 *
 * @returns the number of topic hints inserted.
 *
 * @locks rd_kafka_wrlock()
 */
int rd_kafka_metadata_cache_hint (rd_kafka_t *rk,
                                  const rd_list_t *topics, rd_list_t *dst,
                                  int replace) {
        const char *topic;
        rd_ts_t now = rd_clock();
        rd_ts_t ts_expires = now + (rk->rk_conf.socket_timeout_ms * 1000);
        int i;
        int cnt = 0;

        RD_LIST_FOREACH(topic, topics, i) {
                rd_kafka_metadata_topic_t mtopic = {
                        .topic = (char *)topic,
                        .err = RD_KAFKA_RESP_ERR__WAIT_CACHE
                };
                const struct rd_kafka_metadata_cache_entry *rkmce;

                /* !replace: Dont overwrite valid entries */
                if (!replace &&
                    (rkmce =
                     rd_kafka_metadata_cache_find(rk, topic, 0/*any*/))) {
                        if (RD_KAFKA_METADATA_CACHE_VALID(rkmce) || dst)
                                continue;
                        /* FALLTHRU */
                }

                rd_kafka_metadata_cache_insert(rk, &mtopic, now, ts_expires);
                cnt++;

                if (dst)
                        rd_list_add(dst, rd_strdup(topic));

        }

        if (cnt > 0)
                rd_kafka_dbg(rk, METADATA, "METADATA",
                             "Hinted cache of %d/%d topic(s) being queried",
                             cnt, rd_list_cnt(topics));

        return cnt;
}


/**
 * @brief Same as rd_kafka_metadata_cache_hint() but takes
 *        a topic+partition list as input instead.
 */
int rd_kafka_metadata_cache_hint_rktparlist (
        rd_kafka_t *rk,
        const rd_kafka_topic_partition_list_t *rktparlist,
        rd_list_t *dst,
        int replace) {
        rd_list_t topics;
        int r;

        rd_list_init(&topics, rktparlist->cnt, rd_free);
        rd_kafka_topic_partition_list_get_topic_names(rktparlist, &topics,
                                                      0/*dont include regex*/);
        r = rd_kafka_metadata_cache_hint(rk, &topics, dst, replace);
        rd_list_destroy(&topics);
        return r;
}


/**
 * @brief Cache entry comparator (on topic name)
 */
static int rd_kafka_metadata_cache_entry_cmp (const void *_a, const void *_b) {
        const struct rd_kafka_metadata_cache_entry *a = _a, *b = _b;
        return strcmp(a->rkmce_mtopic.topic, b->rkmce_mtopic.topic);
}


/**
 * @brief Initialize the metadata cache
 *
 * @locks rd_kafka_wrlock()
 */
void rd_kafka_metadata_cache_init (rd_kafka_t *rk) {
        rd_avl_init(&rk->rk_metadata_cache.rkmc_avl,
                    rd_kafka_metadata_cache_entry_cmp, 0);
        TAILQ_INIT(&rk->rk_metadata_cache.rkmc_expiry);
        mtx_init(&rk->rk_metadata_cache.rkmc_full_lock, mtx_plain);
        mtx_init(&rk->rk_metadata_cache.rkmc_cnd_lock, mtx_plain);
        cnd_init(&rk->rk_metadata_cache.rkmc_cnd);

}

/**
 * @brief Purge and destroy metadata cache
 *
 * @locks rd_kafka_wrlock()
 */
void rd_kafka_metadata_cache_destroy (rd_kafka_t *rk) {
        rd_kafka_timer_stop(&rk->rk_timers,
                            &rk->rk_metadata_cache.rkmc_query_tmr, 1/*lock*/);
        rd_kafka_metadata_cache_purge(rk);
        mtx_destroy(&rk->rk_metadata_cache.rkmc_full_lock);
        mtx_destroy(&rk->rk_metadata_cache.rkmc_cnd_lock);
        cnd_destroy(&rk->rk_metadata_cache.rkmc_cnd);
        rd_avl_destroy(&rk->rk_metadata_cache.rkmc_avl);
}


/**
 * @brief Wait for cache update, or timeout.
 *
 * @returns 1 on cache update or 0 on timeout.
 * @locks none
 * @locality any
 */
int rd_kafka_metadata_cache_wait_change (rd_kafka_t *rk, int timeout_ms) {
        int r;
#if ENABLE_DEVEL
        rd_ts_t ts_start = rd_clock();
#endif
        mtx_lock(&rk->rk_metadata_cache.rkmc_cnd_lock);
        r = cnd_timedwait_ms(&rk->rk_metadata_cache.rkmc_cnd,
                             &rk->rk_metadata_cache.rkmc_cnd_lock,
                             timeout_ms);
        mtx_unlock(&rk->rk_metadata_cache.rkmc_cnd_lock);

#if ENABLE_DEVEL
        rd_kafka_dbg(rk, METADATA, "CACHEWAIT",
                     "%s wait took %dms: %s",
                     __FUNCTION__, (int)((rd_clock() - ts_start)/1000),
                     r == thrd_success ? "succeeded" : "timed out");
#endif
        return r == thrd_success;
}

/**
 * @brief Propagate that the cache changed (but not what changed) to
 *        any cnd listeners.
 * @locks none
 * @locality any
 */
static void rd_kafka_metadata_cache_propagate_changes (rd_kafka_t *rk) {
        mtx_lock(&rk->rk_metadata_cache.rkmc_cnd_lock);
        cnd_broadcast(&rk->rk_metadata_cache.rkmc_cnd);
        mtx_unlock(&rk->rk_metadata_cache.rkmc_cnd_lock);
}

/**
 * @returns the shared metadata for a topic, or NULL if not found in
 *          cache.
 *
 * @locks rd_kafka_*lock()
 */
const rd_kafka_metadata_topic_t *
rd_kafka_metadata_cache_topic_get (rd_kafka_t *rk, const char *topic,
                                   int valid) {
        struct rd_kafka_metadata_cache_entry *rkmce;

        if (!(rkmce = rd_kafka_metadata_cache_find(rk, topic, valid)))
                return NULL;

        return &rkmce->rkmce_mtopic;
}




/**
 * @brief Looks up the shared metadata for a partition along with its topic.
 *
 * @param mtopicp: pointer to topic metadata
 * @param mpartp: pointer to partition metadata
 * @param valid: only return valid entries (no hints)
 *
 * @returns -1 if topic was not found in cache, 0 if topic was found
 *          but not the partition, 1 if both topic and partition was found.
 *
 * @locks rd_kafka_*lock()
 */
int rd_kafka_metadata_cache_topic_partition_get (
        rd_kafka_t *rk,
        const rd_kafka_metadata_topic_t **mtopicp,
        const rd_kafka_metadata_partition_t **mpartp,
        const char *topic, int32_t partition, int valid) {

        const rd_kafka_metadata_topic_t *mtopic;
        const rd_kafka_metadata_partition_t *mpart;
        rd_kafka_metadata_partition_t skel = { .id = partition };

        *mtopicp = NULL;
        *mpartp = NULL;

        if (!(mtopic = rd_kafka_metadata_cache_topic_get(rk, topic, valid)))
                return -1;

        *mtopicp = mtopic;

        /* Partitions array may be sparse so use bsearch lookup. */
        mpart = bsearch(&skel, mtopic->partitions,
                        mtopic->partition_cnt,
                        sizeof(*mtopic->partitions),
                        rd_kafka_metadata_partition_id_cmp);

        if (!mpart)
                return 0;

        *mpartp = mpart;

        return 1;
}


/**
 * @returns the number of topics in \p topics that are in the cache.
 *
 * @param topics rd_list(const char *): topic names
 * @param metadata_agep: age of oldest entry will be returned.
 *
 * @locks rd_kafka_*lock()
 */
int rd_kafka_metadata_cache_topics_count_exists (rd_kafka_t *rk,
                                                 const rd_list_t *topics,
                                                 int *metadata_agep) {
        const char *topic;
        int i;
        int cnt = 0;
        int max_age = -1;

        RD_LIST_FOREACH(topic, topics, i) {
                const struct rd_kafka_metadata_cache_entry *rkmce;
                int age;

                if (!(rkmce = rd_kafka_metadata_cache_find(rk, topic,
                                                           1/*valid only*/)))
                        continue;

                age = (int)((rd_clock() - rkmce->rkmce_ts_insert)/1000);
                if (age > max_age)
                        max_age = age;
                cnt++;
        }

        *metadata_agep = max_age;

        return cnt;

}


/**
 * @brief Copies any topics in \p src to \p dst that have a valid cache
 *        entry, or not in the cache at all.
 *
 *        In other words; hinted non-valid topics will not copied to \p dst.
 *
 * @returns the number of topics copied
 *
 * @locks rd_kafka_*lock()
 */
int rd_kafka_metadata_cache_topics_filter_hinted (rd_kafka_t *rk,
                                                  rd_list_t *dst,
                                                  const rd_list_t *src) {
        const char *topic;
        int i;
        int cnt = 0;


        RD_LIST_FOREACH(topic, src, i) {
                const struct rd_kafka_metadata_cache_entry *rkmce;

                rkmce = rd_kafka_metadata_cache_find(rk, topic, 0/*any sort*/);
                if (rkmce && !RD_KAFKA_METADATA_CACHE_VALID(rkmce))
                        continue;

                rd_list_add(dst, rd_strdup(topic));
                cnt++;
        }

        return cnt;
}



/**
 * @brief Dump cache to \p fp
 *
 * @locks rd_kafka_*lock()
 */
void rd_kafka_metadata_cache_dump (FILE *fp, rd_kafka_t *rk) {
        const struct rd_kafka_metadata_cache *rkmc = &rk->rk_metadata_cache;
        const struct rd_kafka_metadata_cache_entry *rkmce;
        rd_ts_t now = rd_clock();

        fprintf(fp,
                "Metadata cache with %d entries:\n",
                rkmc->rkmc_cnt);
        TAILQ_FOREACH(rkmce, &rkmc->rkmc_expiry, rkmce_link) {
                fprintf(fp,
                        "  %s (inserted %dms ago, expires in %dms, "
                        "%d partition(s), %s)%s%s\n",
                        rkmce->rkmce_mtopic.topic,
                        (int)((now - rkmce->rkmce_ts_insert)/1000),
                        (int)((rkmce->rkmce_ts_expires - now)/1000),
                        rkmce->rkmce_mtopic.partition_cnt,
                        RD_KAFKA_METADATA_CACHE_VALID(rkmce) ? "valid":"hint",
                        rkmce->rkmce_mtopic.err ? " error: " : "",
                        rkmce->rkmce_mtopic.err ?
                        rd_kafka_err2str(rkmce->rkmce_mtopic.err) : "");
        }
}

/**@}*/
