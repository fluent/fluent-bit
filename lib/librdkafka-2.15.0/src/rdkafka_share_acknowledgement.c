/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2026, Confluent Inc.
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
#include "rdkafka_metadata.h"
#include "rdkafka_share_acknowledgement.h"

rd_kafka_share_ack_batch_entry_t *
rd_kafka_share_ack_batch_entry_new(int64_t start_offset,
                                   int64_t end_offset,
                                   int32_t types_cnt,
                                   int16_t delivery_count) {
        rd_kafka_share_ack_batch_entry_t *entry;

        entry                 = rd_calloc(1, sizeof(*entry));
        entry->start_offset   = start_offset;
        entry->end_offset     = end_offset;
        entry->size           = end_offset - start_offset + 1;
        entry->types_cnt      = types_cnt;
        entry->delivery_count = delivery_count;
        entry->types =
            rd_calloc((size_t)types_cnt,
                      sizeof(rd_kafka_share_internal_acknowledgement_type));
        return entry;
}

void rd_kafka_share_ack_batch_entry_destroy(
    rd_kafka_share_ack_batch_entry_t *entry) {
        if (!entry)
                return;
        rd_free(entry->types);
        rd_free(entry);
}

static void rd_kafka_share_ack_batch_entry_destroy_free(void *ptr) {
        rd_kafka_share_ack_batch_entry_destroy(
            (rd_kafka_share_ack_batch_entry_t *)ptr);
}

rd_bool_t
rd_kafka_share_acknowledgement_mode_is_implicit(rd_kafka_share_t *rkshare) {
        return rkshare->rkshare_rk->rk_conf.share.share_acknowledgement_mode &&
               !strcmp(rkshare->rkshare_rk->rk_conf.share
                           .share_acknowledgement_mode,
                       "implicit");
}

rd_bool_t
rd_kafka_share_acknowledgement_mode_is_explicit(rd_kafka_share_t *rkshare) {
        return rkshare->rkshare_rk->rk_conf.share.share_acknowledgement_mode &&
               !strcmp(rkshare->rkshare_rk->rk_conf.share
                           .share_acknowledgement_mode,
                       "explicit");
}

void rd_kafka_share_acknowledge_all_if_implicit(rd_kafka_share_t *rkshare) {
        if (rd_kafka_share_acknowledgement_mode_is_implicit(rkshare))
                rd_kafka_share_ack_all(rkshare);
}

rd_kafka_error_t *
rd_kafka_share_ensure_all_acknowledged_if_explicit(rd_kafka_share_t *rkshare) {
        if (rd_kafka_share_acknowledgement_mode_is_explicit(rkshare) &&
            rkshare->rkshare_unacked_cnt > 0)
                return rd_kafka_error_new(
                    RD_KAFKA_RESP_ERR__STATE,
                    "%" PRId64
                    " records from previous poll have not "
                    "been acknowledged",
                    rkshare->rkshare_unacked_cnt);
        return NULL;
}

rd_kafka_share_ack_batch_entry_t *rd_kafka_share_ack_batch_entry_copy(
    const rd_kafka_share_ack_batch_entry_t *src) {
        rd_kafka_share_ack_batch_entry_t *dst;

        dst = rd_kafka_share_ack_batch_entry_new(
            src->start_offset, src->end_offset, src->types_cnt,
            src->delivery_count);
        memcpy(dst->types, src->types,
               (size_t)src->types_cnt *
                   sizeof(rd_kafka_share_internal_acknowledgement_type));
        return dst;
}

static void *rd_kafka_share_ack_batch_entry_copy_void(const void *elem,
                                                      void *opaque) {
        return rd_kafka_share_ack_batch_entry_copy(
            (const rd_kafka_share_ack_batch_entry_t *)elem);
}

rd_kafka_share_ack_batches_t *rd_kafka_share_ack_batches_new_empty(void) {
        return rd_kafka_share_ack_batches_new(NULL, 0, 0);
}

rd_kafka_share_ack_batches_t *
rd_kafka_share_ack_batches_new(rd_kafka_topic_partition_t *rktpar,
                               int32_t response_leader_id,
                               int64_t response_acquired_offsets_count) {
        rd_kafka_share_ack_batches_t *batches;

        batches                     = rd_calloc(1, sizeof(*batches));
        batches->rktpar             = rktpar;
        batches->response_leader_id = response_leader_id;
        batches->response_acquired_offsets_count =
            response_acquired_offsets_count;
        rd_list_init(&batches->entries, 0,
                     rd_kafka_share_ack_batch_entry_destroy_free);
        return batches;
}

void rd_kafka_share_ack_batches_destroy(rd_kafka_share_ack_batches_t *batches) {
        rd_list_destroy(&batches->entries);
        if (batches->rktpar)
                rd_kafka_topic_partition_destroy(batches->rktpar);
        rd_free(batches);
}

void rd_kafka_share_ack_batches_destroy_free(void *ptr) {
        rd_kafka_share_ack_batches_destroy((rd_kafka_share_ack_batches_t *)ptr);
}

rd_kafka_share_ack_batches_t *
rd_kafka_share_ack_batches_copy(const rd_kafka_share_ack_batches_t *src) {
        rd_kafka_share_ack_batches_t *dst;

        dst = rd_kafka_share_ack_batches_new(
            src->rktpar ? rd_kafka_topic_partition_copy(src->rktpar) : NULL,
            src->response_leader_id, src->response_acquired_offsets_count);

        /* Deep copy all entries and preserve flags (e.g., RD_LIST_F_SORTED) */
        rd_list_copy_to(&dst->entries, &src->entries,
                        rd_kafka_share_ack_batch_entry_copy_void, NULL);
        dst->entries.rl_flags = src->entries.rl_flags;
        return dst;
}

void *rd_kafka_share_ack_batches_copy_void(const void *elem, void *opaque) {
        return rd_kafka_share_ack_batches_copy(
            (const rd_kafka_share_ack_batches_t *)elem);
}

/**
 * @brief Transfer inflight acks from response RKO into rkshare's inflight map.
 *
 * Takes each batch from the response's inflight_acks list and stores it in
 * the map (key = topic-partition). Ownership is transferred; the response
 * RKO must not free these when destroyed.
 * In the future, the map will be cleared per partition after acks are sent.
 *
 * @param rkshare Share consumer handle
 * @param response_rko The share fetch response RKO containing inflight_acks
 */
void rd_kafka_share_build_inflight_acks_map(rd_kafka_share_t *rkshare,
                                            rd_kafka_op_t *response_rko) {
        rd_list_t *list =
            response_rko->rko_u.share_fetch_response.inflight_acks;

        while (rd_list_cnt(list) > 0) {
                rd_kafka_share_ack_batches_t *batches = rd_list_pop(list);
                rd_kafka_topic_partition_t *key;
                rd_kafka_share_ack_batch_entry_t *entry;
                int i, k;

                rd_dassert(batches->rktpar != NULL);

                key = rd_kafka_topic_partition_new_with_id_and_name(
                    rd_kafka_topic_partition_get_topic_id(batches->rktpar),
                    batches->rktpar->topic, batches->rktpar->partition);

                /* Each topic-partition is always a new entry (no overwrites).
                 */
                RD_MAP_SET(&rkshare->rkshare_inflight_acks, key, batches);

                /* Count ACQUIRED types for unacked tracking */
                RD_LIST_FOREACH(entry, &batches->entries, i) {
                        for (k = 0; k < entry->types_cnt; k++) {
                                if (entry->types[k] ==
                                    RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED)
                                        rkshare->rkshare_unacked_cnt++;
                        }
                }
        }
}

/**
 * @brief Create a new collated batch entry with a single acknowledgement type.
 *
 * Creates an entry where size=1 and types[0] holds the single ack type
 * for the entire offset range [start_offset, end_offset].
 *
 * @param start_offset First offset in the range
 * @param end_offset Last offset in the range (inclusive)
 * @param type The acknowledgement type for the entire range
 *
 * @returns Newly allocated collated entry (caller must free)
 */
static rd_kafka_share_ack_batch_entry_t *
rd_kafka_share_ack_batch_entry_collated_new(
    int64_t start_offset,
    int64_t end_offset,
    rd_kafka_share_internal_acknowledgement_type type,
    int16_t delivery_count) {
        rd_kafka_share_ack_batch_entry_t *entry =
            rd_kafka_share_ack_batch_entry_new(start_offset, end_offset, 1,
                                               delivery_count);
        entry->types[0] = type;
        return entry;
}

/**
 * @brief Implicit acknowledgement: convert all ACQUIRED types to ACCEPT.
 *
 * In implicit ack mode, all records delivered to the application are
 * automatically acknowledged as ACCEPT on the next poll(). This function
 * walks through all entries in the inflight map and changes ACQUIRED
 * types to ACCEPT so that rd_kafka_share_build_ack_details() will
 * extract them for sending to the broker.
 *
 * @param rkshare Share consumer handle
 */
void rd_kafka_share_ack_all(rd_kafka_share_t *rkshare) {
        const rd_kafka_topic_partition_t *tp_key;
        rd_kafka_share_ack_batches_t *inflight_batches;

        RD_MAP_FOREACH(tp_key, inflight_batches,
                       &rkshare->rkshare_inflight_acks) {
                rd_kafka_share_ack_batch_entry_t *entry;
                int i;
                rd_kafka_dbg(rkshare->rkshare_rk, CGRP, "SHAREACK",
                             "Implicit ack: converting ACQUIRED to ACCEPT "
                             "for %s [%" PRId32 "]",
                             tp_key->topic, tp_key->partition);
                RD_LIST_FOREACH(entry, &inflight_batches->entries, i) {
                        int k;
                        for (k = 0; k < entry->types_cnt; k++) {
                                if (entry->types[k] ==
                                    RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED)
                                        entry->types[k] =
                                            RD_KAFKA_SHARE_INTERNAL_ACK_ACCEPT;
                        }
                }
        }
}

/**
 * @brief Free an ack details batch, its entries, and its owned rktpar.
 *
 * Used as rd_list_t free callback for ack_details output lists where
 * each batch owns a copy of its rktpar.
 */
static void rd_kafka_share_ack_details_batch_destroy(void *ptr) {
        rd_kafka_share_ack_batches_t *batch = ptr;
        rd_kafka_share_ack_batches_destroy(batch);
}

/**
 * @brief Find an existing ack batch for the same topic-partition in a list.
 *
 * @param ack_list List of rd_kafka_share_ack_batches_t*
 * @param rktpar Topic-partition to match (by topic id and partition)
 *
 * @returns Matching batch, or NULL if not found.
 * @locality main thread
 */
rd_kafka_share_ack_batches_t *
rd_kafka_share_find_ack_batch(rd_list_t *ack_list,
                              const rd_kafka_topic_partition_t *rktpar) {
        rd_kafka_share_ack_batches_t *existing;
        int i;

        RD_LIST_FOREACH(existing, ack_list, i) {
                if (rd_kafka_topic_partition_by_id_cmp(existing->rktpar,
                                                       rktpar) == 0)
                        return existing;
        }
        return NULL;
}

/**
 * @brief Find an existing ack batch by topic id and partition.
 *
 * Same as rd_kafka_share_find_ack_batch but takes topic_id and
 * partition directly to avoid allocating a temporary
 * rd_kafka_topic_partition_t for the lookup.
 *
 * TODO KIP-932: Merge this with rd_kafka_share_find_ack_batch and use
 * rd_list_find with binary search once ack_list is kept sorted.
 *
 * @param ack_list List of rd_kafka_share_ack_batches_t*.
 * @param topic_id Topic UUID to match.
 * @param partition Partition id to match.
 *
 * @returns Matching batch, or NULL if not found.
 */
rd_kafka_share_ack_batches_t *
rd_kafka_share_find_ack_batch_by_id(rd_list_t *ack_list,
                                    rd_kafka_Uuid_t topic_id,
                                    int32_t partition) {
        rd_kafka_share_ack_batches_t *existing;
        int i;

        RD_LIST_FOREACH(existing, ack_list, i) {
                if (existing->rktpar->partition == partition &&
                    !rd_kafka_Uuid_cmp(
                        rd_kafka_topic_partition_get_topic_id(existing->rktpar),
                        topic_id))
                        return existing;
        }
        return NULL;
}

/**
 * @brief Reply to a SHARE_FETCH op with an error, propagating the
 *        error to each batch in ack_details.
 *
 * On top-level error (err != 0):
 *   - If err is BAD_MSG / __UNDERFLOW (wire-level parse failure):
 *     override every batch with INVALID_RECORD_STATE so the consumer
 *     treats these as "outcome unknown" and re-acquires; any
 *     per-partition err the parser may have written before failing
 *     could be a misaligned read and is no longer trustworthy.
 *   - Otherwise: propagate err to each batch still at _IN_PROGRESS,
 *     preserving any deliberately pre-set err and any per-partition
 *     err already written by the parser.
 *
 * On success (err == 0), the per-partition errors have already been
 * set by the response parser and we leave ack_details untouched.
 */
void rd_kafka_share_fetch_op_reply_and_update_ack_details_with_err(
    rd_kafka_op_t *rko,
    rd_kafka_resp_err_t err) {
        if (err && rko->rko_u.share_fetch.ack_details) {
                rd_kafka_share_ack_batches_t *batch;
                int i;

                if (likely(err != RD_KAFKA_RESP_ERR__BAD_MSG &&
                           err != RD_KAFKA_RESP_ERR__UNDERFLOW)) {

                        /* Propagate top-level err to each batch in
                         * ack_details, but only override the _IN_PROGRESS
                         * sentinel. This preserves:
                         *   - Deliberately pre-set err (e.g.
                         *     INVALID_SHARE_SESSION_EPOCH from the
                         *     epoch-0 strip path).
                         *   - Per-partition err already written by the
                         *     parser. */
                        RD_LIST_FOREACH(batch,
                                        rko->rko_u.share_fetch.ack_details, i) {
                                if (batch->rktpar->err ==
                                    RD_KAFKA_RESP_ERR__IN_PROGRESS)
                                        batch->rktpar->err = err;
                        }
                } else {
                        /* Wire-level parse failure: response framing is
                         * untrusted, so any per-partition err the parser
                         * may have written before failing could be a
                         * misaligned read. */
                        RD_LIST_FOREACH(batch,
                                        rko->rko_u.share_fetch.ack_details, i) {
                                batch->rktpar->err = err;
                        }
                }
        }
        rd_kafka_op_reply(rko, err);
}

/**
 * @brief Whether the leader cached for the partition has diverged
 *        from the leader at which \p batch's records were acquired.
 */
static rd_bool_t
rd_kafka_share_ack_batch_leader_stale(rd_kafka_share_ack_batches_t *batch,
                                      int32_t current_leader_id) {
        return current_leader_id != batch->response_leader_id;
}

/**
 * @brief Resolve the leader broker for an ack batch, or fail the
 *        batch locally with the appropriate error code.
 *
 *        Snapshots (rktp_leader, rktp_leader_id) under rktp_lock to
 *        avoid racing with concurrent leader-state clearing on the
 *        broker thread. On success, returns a kept broker handle;
 *        the caller MUST rd_kafka_broker_destroy() it after use.
 *        On failure returns NULL with \p *errp set.
 *
 * @locality main thread
 */
static rd_kafka_broker_t *rd_kafka_share_ack_batch_resolve_leader_or_fail_acks(
    rd_kafka_t *rk,
    rd_kafka_share_ack_batches_t *batch,
    rd_kafka_resp_err_t *errp) {
        rd_kafka_toppar_t *rktp;
        rd_kafka_broker_t *leader_rkb;
        int32_t leader_id;

        rktp = rd_kafka_topic_partition_toppar(rk, batch->rktpar);

        /* Defensive: in production the rktp is always attached to the
         * batch by the ShareFetch reply parser via toppar_keep, so
         * this branch should never fire. Trigger a cluster-wide
         * metadata refresh to recover if it ever does. */
        if (unlikely(!rktp)) {
                rd_kafka_dbg(rk, CGRP, "SHARE",
                             "Ack batch for partition %" PRId32
                             " dropped: toppar not found "
                             "(should be unreachable)",
                             batch->rktpar->partition);
                rd_kafka_metadata_refresh_known_topics(
                    rk, NULL, rd_false /*don't force*/,
                    "shareack toppar not found");
                *errp = RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;
                return NULL;
        }

        /* Snapshot (rktp_leader, rktp_leader_id) under rktp_lock to
         * avoid racing with concurrent leader-state clearing on the
         * broker thread. */
        rd_kafka_toppar_lock(rktp);
        leader_rkb = rktp->rktp_leader;
        leader_id  = rktp->rktp_leader_id;
        if (leader_rkb)
                rd_kafka_broker_keep(leader_rkb);
        rd_kafka_toppar_unlock(rktp);

        /* Cached leader differs from the leader at which records
         * were acquired. The session for these records lives on the
         * original broker which no longer leads this partition. No
         * metadata refresh - the cached current leader is already
         * the new one (that's how this check fired). */
        if (unlikely(rd_kafka_share_ack_batch_leader_stale(batch, leader_id))) {
                rd_kafka_dbg(rk, CGRP, "SHARE",
                             "Ack batch for %s [%" PRId32
                             "] dropped locally: leader changed "
                             "since records were acquired "
                             "(was %" PRId32 ", now %" PRId32 ")",
                             batch->rktpar->topic, batch->rktpar->partition,
                             batch->response_leader_id, leader_id);
                if (leader_rkb)
                        rd_kafka_broker_destroy(leader_rkb);
                *errp = RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER;
                return NULL;
        }

        /* Defensive: no cached leader. Unreachable in practice
         * because leader-stale fires first when the cached leader id
         * is -1, but kept to make the intent explicit and survive
         * future invariant changes. Trigger a metadata refresh and
         * surface NOT_LEADER_OR_FOLLOWER. */
        if (unlikely(!leader_rkb)) {
                rd_kafka_dbg(rk, CGRP, "SHARE",
                             "Ack batch for %s [%" PRId32
                             "] dropped: no cached leader, "
                             "triggering metadata refresh",
                             batch->rktpar->topic, batch->rktpar->partition);
                rd_kafka_toppar_leader_unavailable(
                    rktp, "shareack", RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER);
                *errp = RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER;
                return NULL;
        }

        /* Cached leader broker is being decommissioned or the
         * instance is terminating. Surface NOT_LEADER_OR_FOLLOWER and
         * trigger a metadata refresh so the next request finds the
         * new leader. */
        if (unlikely(rd_kafka_broker_or_instance_terminating(leader_rkb))) {
                rd_kafka_dbg(
                    rk, CGRP, "SHARE",
                    "Ack batch for %s [%" PRId32 "] dropped: broker %" PRId32
                    " is terminating, "
                    "triggering metadata refresh",
                    batch->rktpar->topic, batch->rktpar->partition, leader_id);
                rd_kafka_toppar_leader_unavailable(
                    rktp, "shareack", RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER);
                rd_kafka_broker_destroy(leader_rkb);
                *errp = RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER;
                return NULL;
        }

        *errp = RD_KAFKA_RESP_ERR_NO_ERROR;
        return leader_rkb;
}


/**
 * @brief Segregate sync ack batches by partition leader into
 *        each broker's pending_commit_sync list.
 *
 * Phase 1 of sync dispatch: puts ALL acks into rkb_pending_commit_sync
 * regardless of whether the broker is free or busy. Updates the
 * commit_sync results for partitions with no available leader.
 *
 * @param rk Client instance.
 * @param rkcg Consumer group handle.
 * @param ack_batches List of ack batches from the SYNC_FANOUT op.
 *                    Elements are moved to broker lists; container destroyed.
 * @param abs_timeout Absolute timeout for the commit_sync request.
 *
 * @locality main thread
 */
void rd_kafka_share_segregate_sync_acks_by_leader(rd_kafka_t *rk,
                                                  rd_kafka_cgrp_t *rkcg,
                                                  rd_list_t *ack_batches,
                                                  rd_ts_t abs_timeout) {
        rd_kafka_share_ack_batches_t *batch;
        int batch_cnt = rd_list_cnt(ack_batches);

        while ((batch = rd_list_pop(ack_batches))) {
                rd_kafka_broker_t *leader_rkb;
                rd_kafka_share_ack_batches_t *existing;
                rd_kafka_topic_partition_t *result_rktpar;
                rd_kafka_resp_err_t fail_err;

                leader_rkb =
                    rd_kafka_share_ack_batch_resolve_leader_or_fail_acks(
                        rk, batch, &fail_err);
                if (!leader_rkb) {
                        result_rktpar = rd_kafka_topic_partition_list_find(
                            rkcg->rkcg_commit_sync_request.results,
                            batch->rktpar->topic, batch->rktpar->partition);
                        if (result_rktpar)
                                result_rktpar->err = fail_err;
                        else
                                rd_kafka_dbg(rk, CGRP, "SHARE",
                                             "Sync ack batch for %s [%" PRId32
                                             "]: partition not found in "
                                             "commit_sync results",
                                             batch->rktpar->topic,
                                             batch->rktpar->partition);

                        rd_kafka_share_enqueue_ack_commit_cb_op(rk, batch,
                                                                fail_err);
                        rd_kafka_share_ack_batches_destroy(batch);
                        continue;
                }

                /* Put all acks into pending_commit_sync */
                if (!leader_rkb->rkb_pending_commit_sync.sync_ack_details)
                        leader_rkb->rkb_pending_commit_sync.sync_ack_details =
                            rd_list_new(
                                batch_cnt,
                                rd_kafka_share_ack_batches_destroy_free);

                existing = rd_kafka_share_find_ack_batch(
                    leader_rkb->rkb_pending_commit_sync.sync_ack_details,
                    batch->rktpar);
                if (existing) {
                        rd_kafka_share_ack_batch_entry_t *entry;
                        int j;
                        RD_LIST_FOREACH(entry, &batch->entries, j) {
                                rd_list_add(
                                    &existing->entries,
                                    rd_kafka_share_ack_batch_entry_copy(entry));
                        }
                        rd_list_sort(&existing->entries,
                                     rd_kafka_share_ack_entries_sort_cmp_ptr);
                        rd_kafka_share_ack_batches_destroy(batch);
                } else {
                        rd_list_add(leader_rkb->rkb_pending_commit_sync
                                        .sync_ack_details,
                                    batch);
                }

                leader_rkb->rkb_pending_commit_sync.abs_timeout = abs_timeout;
                leader_rkb->rkb_pending_commit_sync.commit_sync_request_id =
                    rkcg->rkcg_commit_sync_request.id;

                rd_kafka_broker_destroy(leader_rkb);
        }

        rd_list_destroy(ack_batches);
}


/**
 * @brief Segregate ack batches from a FANOUT op by partition leader.
 *
 * For each ack batch, looks up the current leader broker via the
 * toppar reference in batch->rktpar, and merges the batch into that
 * broker's rkb_share_async_ack_details list. If the broker already
 * has cached acks for the same topic-partition, the entries are
 * appended to the existing batch.
 *
 * @param rk Client instance
 * @param ack_batches List of rd_kafka_share_ack_batches_t* from FANOUT op.
 *                    Elements whose leader is found are moved to broker
 *                    ack_details; remaining elements are not freed.
 *
 * @locality main thread
 */
void rd_kafka_share_segregate_acks_by_leader(rd_kafka_t *rk,
                                             rd_list_t *ack_batches) {
        rd_kafka_share_ack_batches_t *batch;
        int batch_cnt = rd_list_cnt(ack_batches);

        while ((batch = rd_list_pop(ack_batches))) {
                rd_kafka_broker_t *leader_rkb;
                rd_kafka_share_ack_batches_t *existing;
                rd_kafka_resp_err_t fail_err;

                leader_rkb =
                    rd_kafka_share_ack_batch_resolve_leader_or_fail_acks(
                        rk, batch, &fail_err);
                if (!leader_rkb) {
                        rd_kafka_share_enqueue_ack_commit_cb_op(rk, batch,
                                                                fail_err);
                        rd_kafka_share_ack_batches_destroy(batch);
                        continue;
                }

                /* Allocate list on first use with incoming batch count
                 * as initial capacity hint */
                if (!leader_rkb->rkb_share_async_ack_details)
                        leader_rkb->rkb_share_async_ack_details = rd_list_new(
                            batch_cnt, rd_kafka_share_ack_batches_destroy_free);

                /* Check if there's already a batch for this topic-partition.
                 * If so, merge entries; otherwise add as new. */
                existing = rd_kafka_share_find_ack_batch(
                    leader_rkb->rkb_share_async_ack_details, batch->rktpar);

                if (existing) {
                        /* Merge: deep-copy entries from new batch into
                         * existing, preserving order. The source batch
                         * is then fully destroyed (freeing its entries). */
                        rd_kafka_share_ack_batch_entry_t *entry;
                        int j;
                        RD_LIST_FOREACH(entry, &batch->entries, j) {
                                rd_list_add(
                                    &existing->entries,
                                    rd_kafka_share_ack_batch_entry_copy(entry));
                        }
                        rd_kafka_share_ack_batches_destroy(batch);
                } else {
                        rd_list_add(leader_rkb->rkb_share_async_ack_details,
                                    batch);
                }

                rd_kafka_broker_destroy(leader_rkb);
        }
}

/**
 * @brief Extract acknowledged (non-ACQUIRED) records from inflight map.
 *
 * Iterates through the inflight acknowledgement map and separates each
 * entry's per-offset types into:
 *   - Non-ACQUIRED offsets: collated into ack_details for sending to broker
 *     (consecutive same-type offsets merged into single entry with 1 type)
 *   - ACQUIRED offsets: kept in the map as new entries (per-offset types)
 *
 * Map entries with no remaining ACQUIRED offsets are removed.
 * If the map becomes empty after processing, it is cleared.
 *
 * @param rkshare Share consumer handle
 * @returns Allocated list of rd_kafka_share_ack_batches_t*, or NULL if
 *          there are no ack details to send. Caller must destroy.
 * TODO KIP-932: Change name.
 */
rd_list_t *rd_kafka_share_build_ack_details(rd_kafka_share_t *rkshare) {
        const rd_kafka_topic_partition_t *tp_key;
        rd_kafka_share_ack_batches_t *inflight_batches;
        rd_list_t keys_to_delete;
        rd_list_t *ack_details = NULL;
        int i;
        rd_kafka_topic_partition_t *del_key;

        rd_list_init(&keys_to_delete, 0, NULL);

        rkshare->rkshare_unacked_cnt = 0;

        RD_MAP_FOREACH(tp_key, inflight_batches,
                       &rkshare->rkshare_inflight_acks) {
                rd_kafka_share_ack_batches_t *ack_batch = NULL;
                rd_kafka_share_ack_batch_entry_t *entry;
                rd_list_t new_entries;
                int ei;

                rd_kafka_dbg(rkshare->rkshare_rk, CGRP, "SHAREACK",
                             "Building ack details for %s [%" PRId32 "]",
                             tp_key->topic, tp_key->partition);

                rd_list_init(&new_entries, 0,
                             rd_kafka_share_ack_batch_entry_destroy_free);

                RD_LIST_FOREACH(entry, &inflight_batches->entries, ei) {
                        int64_t j = 0;

                        while (j < entry->types_cnt) {
                                rd_kafka_share_internal_acknowledgement_type
                                    run_type      = entry->types[j];
                                int64_t run_start = entry->start_offset + j;
                                int64_t k         = j + 1;

                                /* Find end of consecutive same-type run */
                                while (k < entry->types_cnt &&
                                       entry->types[k] == run_type)
                                        k++;

                                int64_t run_end = entry->start_offset + k - 1;

                                if (run_type ==
                                    RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED) {
                                        /* ACQUIRED: keep in map */
                                        int32_t cnt = (int32_t)(k - j);
                                        rd_kafka_share_ack_batch_entry_t
                                            *new_entry =
                                                rd_kafka_share_ack_batch_entry_new(
                                                    run_start, run_end, cnt,
                                                    entry->delivery_count);
                                        int32_t m;
                                        for (m = 0; m < cnt; m++)
                                                new_entry->types[m] =
                                                    RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED;
                                        rd_list_add(&new_entries, new_entry);
                                        rkshare->rkshare_unacked_cnt += cnt;
                                } else {
                                        /* Non-ACQUIRED: add to ack_details
                                         */
                                        if (!ack_batch) {
                                                ack_batch =
                                                    rd_kafka_share_ack_batches_new(
                                                        rd_kafka_topic_partition_copy(
                                                            inflight_batches
                                                                ->rktpar),
                                                        inflight_batches
                                                            ->response_leader_id,
                                                        0);
                                                /* Sentinel: no reply path
                                                 * has touched this batch
                                                 * yet. Distinct from
                                                 * INVALID_RECORD_STATE
                                                 * (set in buf callback)
                                                 * which means "reply
                                                 * received but partition
                                                 * missing from response".
                                                 * Defensive check in main
                                                 * reply handler converts
                                                 * any remaining
                                                 * _IN_PROGRESS to the
                                                 * top-level rko_err so
                                                 * silent-destroy paths
                                                 * (q_enq disabled queue,
                                                 * helper bypassed) don't
                                                 * leak the sentinel to
                                                 * the app. */
                                                ack_batch->rktpar->err =
                                                    RD_KAFKA_RESP_ERR__IN_PROGRESS;
                                        }
                                        rd_kafka_dbg(
                                            rkshare->rkshare_rk, CGRP,
                                            "SHAREACK",
                                            "    Adding ack detail for offsets "
                                            "[%" PRId64 " - %" PRId64
                                            "] with type %d",
                                            run_start, run_end, run_type);
                                        /* Collated: 1 type for entire
                                         * range */
                                        rd_list_add(
                                            &ack_batch->entries,
                                            rd_kafka_share_ack_batch_entry_collated_new(
                                                run_start, run_end, run_type,
                                                entry->delivery_count));
                                }

                                j = k;
                        }
                }

                /**
                 * TODO KIP-932: Check if it can be optimized as these are
                 *               internal thread operations and they should
                 *               be as fast as possible as this will be called
                 *               again and again.
                 */
                if (rd_list_is_sorted(&new_entries,
                                      rd_kafka_share_ack_entries_sort_cmp_ptr))
                        new_entries.rl_flags |= RD_LIST_F_SORTED;

                /* Replace inflight entries with ACQUIRED-only entries */
                rd_list_destroy(&inflight_batches->entries);
                inflight_batches->entries = new_entries;

                /* If no ACQUIRED offsets remain, mark for removal */
                if (rd_list_cnt(&inflight_batches->entries) == 0) {
                        rd_kafka_topic_partition_t *del_key =
                            rd_kafka_topic_partition_new_with_id_and_name(
                                rd_kafka_topic_partition_get_topic_id(
                                    inflight_batches->rktpar),
                                inflight_batches->rktpar->topic,
                                inflight_batches->rktpar->partition);
                        rd_list_add(&keys_to_delete, del_key);
                }

                if (ack_batch) {
                        if (!ack_details)
                                ack_details = rd_list_new(
                                    0,
                                    rd_kafka_share_ack_details_batch_destroy);
                        rd_list_add(ack_details, ack_batch);
                }
        }

        /* Remove map entries with no remaining ACQUIRED offsets */
        RD_LIST_FOREACH(del_key, &keys_to_delete, i) {
                RD_MAP_DELETE(&rkshare->rkshare_inflight_acks, del_key);
                rd_kafka_topic_partition_destroy(del_key);
        }
        rd_list_destroy(&keys_to_delete);

        /* Clear map if empty */
        if (RD_MAP_CNT(&rkshare->rkshare_inflight_acks) == 0)
                RD_MAP_CLEAR(&rkshare->rkshare_inflight_acks);

        return ack_details;
}

/**
 * @brief Update acknowledgement type for a specific offset within an entry.
 *
 * Handles the transition from ACQUIRED state by decrementing the unacked count.
 *
 * @param rkshare Share consumer handle.
 * @param entry The batch entry containing the offset.
 * @param idx Index within the entry's types array.
 * @param type New acknowledgement type.
 */
static void rd_kafka_share_update_acknowledgement_type(
    rd_kafka_share_t *rkshare,
    rd_kafka_share_ack_batch_entry_t *entry,
    int64_t idx,
    rd_kafka_share_AcknowledgeType_t type) {
        /* Decrement unacked count when transitioning from ACQUIRED */
        if (entry->types[idx] == RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED)
                rkshare->rkshare_unacked_cnt--;

        /* Update the type */
        entry->types[idx] = (rd_kafka_share_internal_acknowledgement_type)type;
}

/**
 * @brief Comparator for sorting/checking entries by start_offset.
 *
 * Used with rd_list_sort() and rd_list_is_sorted().
 */
int rd_kafka_share_ack_entries_sort_cmp_ptr(const void *_a, const void *_b) {
        const rd_kafka_share_ack_batch_entry_t *a =
            (const rd_kafka_share_ack_batch_entry_t *)_a;
        const rd_kafka_share_ack_batch_entry_t *b =
            (const rd_kafka_share_ack_batch_entry_t *)_b;

        if (a->start_offset < b->start_offset)
                return -1;
        if (a->start_offset > b->start_offset)
                return 1;
        return 0;
}

/**
 * @brief Comparator for finding an entry containing a given offset.
 *
 * Used with rd_list_find() for binary search when RD_LIST_F_SORTED is set.
 *
 * @param _offset Pointer to the offset being searched (int64_t *)
 * @param _entry Pointer to the batch entry (rd_kafka_share_ack_batch_entry_t *)
 *
 * @returns negative if offset < entry->start_offset
 * @returns positive if offset > entry->end_offset
 * @returns 0 if offset is within [start_offset, end_offset]
 */
static int rd_kafka_share_ack_entries_offset_find_cmp_ptr(const void *_offset,
                                                          const void *_entry) {
        const int64_t *offset = (const int64_t *)_offset;
        const rd_kafka_share_ack_batch_entry_t *entry =
            (const rd_kafka_share_ack_batch_entry_t *)_entry;

        if (*offset < entry->start_offset)
                return -1;
        if (*offset > entry->end_offset)
                return 1;
        return 0;
}

/**
 * @brief Look up a batch entry containing the given offset.
 *
 * Finds the partition in the inflight_acks map and locates the entry
 * containing the specified offset using binary search.
 *
 * @param rkshare Share consumer handle.
 * @param topic Topic name.
 * @param partition Partition id.
 * @param offset Offset to find.
 * @param entry_out Output parameter for the found entry.
 * @param idx_out Output parameter for the index within the entry.
 *
 * @returns RD_KAFKA_RESP_ERR_NO_ERROR on success,
 *          RD_KAFKA_RESP_ERR__STATE if partition or offset not found.
 */
static rd_kafka_resp_err_t
rd_kafka_share_find_ack_entry(rd_kafka_share_t *rkshare,
                              const char *topic,
                              int32_t partition,
                              int64_t offset,
                              rd_kafka_share_ack_batch_entry_t **entry_out,
                              int64_t *idx_out) {
        rd_kafka_topic_partition_t *lookup_key;
        rd_kafka_share_ack_batches_t *batches;
        rd_kafka_share_ack_batch_entry_t *entry;

        /* Find partition in inflight_acks map */
        lookup_key = rd_kafka_topic_partition_new(topic, partition);
        batches    = RD_MAP_GET(&rkshare->rkshare_inflight_acks, lookup_key);
        rd_kafka_topic_partition_destroy(lookup_key);
        if (!batches)
                return RD_KAFKA_RESP_ERR__STATE;

        /* Find entry containing offset using binary search.
         * Entries are sorted by start_offset and don't overlap. */
        entry = rd_list_find(&batches->entries, &offset,
                             rd_kafka_share_ack_entries_offset_find_cmp_ptr);
        if (!entry)
                return RD_KAFKA_RESP_ERR__STATE;

        *entry_out = entry;
        *idx_out   = offset - entry->start_offset;

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}

/**
 * @brief Internal acknowledge-offset helper.
 *
 * Performs argument validation, inflight-map lookup, and type update.
 * Does NOT take the share consumer access gate — callers must call
 * rd_kafka_share_acquire() / rd_kafka_share_release() around this.
 */
static rd_kafka_resp_err_t
rd_kafka_share_acknowledge_offset0(rd_kafka_share_t *rkshare,
                                   const char *topic,
                                   int32_t partition,
                                   int64_t offset,
                                   rd_kafka_share_AcknowledgeType_t type) {
        rd_kafka_share_ack_batch_entry_t *entry;
        int64_t idx;
        rd_kafka_resp_err_t err;

        if (unlikely((err = rd_kafka_share_consumer_closed_err(rkshare))))
                return err;

        if (!topic || partition < 0 || offset < 0)
                return RD_KAFKA_RESP_ERR__INVALID_ARG;

        /* Explicit acknowledge APIs require explicit acknowledgement mode */
        if (rd_kafka_share_acknowledgement_mode_is_implicit(rkshare))
                return RD_KAFKA_RESP_ERR__STATE;

        /* Validate type - ACCEPT, RELEASE, REJECT allowed */
        if (type < RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT ||
            type > RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_REJECT)
                return RD_KAFKA_RESP_ERR__INVALID_ARG;

        /* Find partition and entry containing the offset */
        err = rd_kafka_share_find_ack_entry(rkshare, topic, partition, offset,
                                            &entry, &idx);
        if (err)
                return err;

        /* GAP records cannot be acknowledged */
        if (entry->types[idx] == RD_KAFKA_SHARE_INTERNAL_ACK_GAP)
                return RD_KAFKA_RESP_ERR__STATE;

        rd_kafka_share_update_acknowledgement_type(rkshare, entry, idx, type);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}

rd_kafka_resp_err_t
rd_kafka_share_acknowledge(rd_kafka_share_t *rkshare,
                           const rd_kafka_message_t *rkmessage) {
        return rd_kafka_share_acknowledge_type(
            rkshare, rkmessage, RD_KAFKA_SHARE_ACKNOWLEDGE_TYPE_ACCEPT);
}

rd_kafka_resp_err_t
rd_kafka_share_acknowledge_type(rd_kafka_share_t *rkshare,
                                const rd_kafka_message_t *rkmessage,
                                rd_kafka_share_AcknowledgeType_t type) {
        rd_kafka_resp_err_t err;
        rd_kafka_error_t *error = NULL;

        if (unlikely((error = rd_kafka_share_acquire(rkshare)) != NULL)) {
                err = rd_kafka_error_code(error);
                rd_kafka_error_destroy(error);
                return err;
        }

        if (!rkmessage) {
                err = RD_KAFKA_RESP_ERR__INVALID_ARG;
                goto done;
        }

        if (!rkmessage->rkt) {
                err = RD_KAFKA_RESP_ERR__STATE;
                goto done;
        }

        err = rd_kafka_share_acknowledge_offset0(
            rkshare, rd_kafka_topic_name(rkmessage->rkt), rkmessage->partition,
            rkmessage->offset, type);

done:
        rd_kafka_share_release(rkshare);
        return err;
}

rd_kafka_resp_err_t
rd_kafka_share_acknowledge_offset(rd_kafka_share_t *rkshare,
                                  const char *topic,
                                  int32_t partition,
                                  int64_t offset,
                                  rd_kafka_share_AcknowledgeType_t type) {
        rd_kafka_resp_err_t err;
        rd_kafka_error_t *error = NULL;

        if (unlikely((error = rd_kafka_share_acquire(rkshare)) != NULL)) {
                err = rd_kafka_error_code(error);
                rd_kafka_error_destroy(error);
                return err;
        }

        err = rd_kafka_share_acknowledge_offset0(rkshare, topic, partition,
                                                 offset, type);

        rd_kafka_share_release(rkshare);
        return err;
}


/**
 * @brief Initialize a partition offsets element with topicid,topic, partition,
 * and offsets.
 *
 * @param topic_id Topic UUID.
 * @param topic Topic name (will be duplicated).
 * @param partition Partition id.
 * @param offsets_cnt Number of offsets to allocate space for.
 */
static rd_kafka_share_partition_offsets_t *
rd_kafka_share_partition_offsets_new(rd_kafka_topic_partition_t *tp,
                                     size_t offsets_cnt) {
        rd_kafka_share_partition_offsets_t *elem;
        size_t size;

        /* Allocate struct + flexible array in one allocation */
        size = sizeof(*elem) + (offsets_cnt * sizeof(int64_t));
        elem = rd_calloc(1, size);

        elem->partition = rd_kafka_topic_partition_new_with_id_and_name(
            rd_kafka_topic_partition_get_topic_id(tp), tp->topic,
            tp->partition);
        elem->cnt = offsets_cnt;

        return elem;
}

/**
 * @brief Destroy a partition offsets element.
 *
 * @param elem Element to destroy.
 */
static void rd_kafka_share_partition_offsets_destroy(
    rd_kafka_share_partition_offsets_t *elem) {
        if (!elem)
                return;
        rd_kafka_topic_partition_destroy(elem->partition);
        rd_free(elem);
}

/**
 * @brief Allocate and initialize a partition offsets list with given capacity.
 *
 * @param capacity Number of elements to allocate space for.
 * @returns Newly allocated list, or NULL if capacity is 0.
 *          Caller must destroy with
 *          rd_kafka_share_partition_offsets_list_destroy().
 */
static rd_kafka_share_partition_offsets_list_t *
rd_kafka_share_partition_offsets_list_new(size_t capacity) {
        rd_kafka_share_partition_offsets_list_t *list;
        size_t size;

        /* Allocate list + flexible array in one allocation */
        size = sizeof(*list) +
               (capacity * sizeof(rd_kafka_share_partition_offsets_t *));
        list = rd_calloc(1, size);

        return list;
}

rd_kafka_share_partition_offsets_list_t *
rd_kafka_share_build_partition_offsets_list(
    rd_kafka_share_ack_batches_t *batches) {
        rd_kafka_share_partition_offsets_list_t *list;
        rd_kafka_share_partition_offsets_t *elem;
        rd_kafka_share_ack_batch_entry_t *entry;
        int total_offsets = 0;
        int offset_idx    = 0;
        int j;

        /* Count total offsets */
        RD_LIST_FOREACH(entry, &batches->entries, j) {
                total_offsets +=
                    (int)(entry->end_offset - entry->start_offset + 1);
        }

        list = rd_kafka_share_partition_offsets_list_new(1);

        /* Allocate elements */
        elem = rd_kafka_share_partition_offsets_new(batches->rktpar,
                                                    total_offsets);

        list->cnt      = 1;
        list->elems[0] = elem;

        /* Fill offsets array */
        RD_LIST_FOREACH(entry, &batches->entries, j) {
                int64_t off;
                for (off = entry->start_offset; off <= entry->end_offset;
                     off++) {
                        elem->offsets[offset_idx++] = off;
                }
        }

        return list;
}


void rd_kafka_share_enqueue_ack_commit_cb_op(
    rd_kafka_t *rk,
    rd_kafka_share_ack_batches_t *batches,
    rd_kafka_resp_err_t err) {
        rd_kafka_op_t *cb_rko;
        rd_kafka_share_partition_offsets_list_t *partitions;

        /* Check if a runtime callback is registered.
         * Locality: main thread - reads flag owned by main thread.
         * No race because the flag is only modified by the main thread
         * via RD_KAFKA_OP_SHARE_ACK_COMMIT_CB_REGISTER op handler. */
        if (!rk->rk_rkshare ||
            !rk->rk_share_consumer.acknowledgement_commit_cb_registered)
                return;

        partitions = rd_kafka_share_build_partition_offsets_list(batches);

        cb_rko = rd_kafka_op_new(RD_KAFKA_OP_SHARE_ACK_COMMIT_CB_EXECUTE);
        cb_rko->rko_err                                      = err;
        cb_rko->rko_u.share_ack_commit_cb_execute.partitions = partitions;

        rd_kafka_q_enq(rk->rk_rep, cb_rko);
}


size_t rd_kafka_share_partition_offsets_list_count(
    const rd_kafka_share_partition_offsets_list_t *list) {
        return list->cnt;
}


const rd_kafka_share_partition_offsets_t *
rd_kafka_share_partition_offsets_list_get(
    const rd_kafka_share_partition_offsets_list_t *list,
    size_t index) {
        return list->elems[index];
}


void rd_kafka_share_partition_offsets_list_destroy(
    rd_kafka_share_partition_offsets_list_t *list) {
        size_t i;

        if (!list)
                return;

        /* Free each element */
        for (i = 0; i < list->cnt; i++) {
                rd_kafka_share_partition_offsets_destroy(list->elems[i]);
        }
        /* Free the list (elems array is inline via FAM) */
        rd_free(list);
}


const rd_kafka_topic_partition_t *rd_kafka_share_partition_offsets_partition(
    const rd_kafka_share_partition_offsets_t *partition_offsets) {
        return partition_offsets->partition;
}


const int64_t *rd_kafka_share_partition_offsets_offsets(
    const rd_kafka_share_partition_offsets_t *partition_offsets) {
        return partition_offsets->offsets;
}


size_t rd_kafka_share_partition_offsets_offsets_cnt(
    const rd_kafka_share_partition_offsets_t *partition_offsets) {
        return partition_offsets->cnt;
}


/**
 * @brief Translate librdkafka-internal err sentinels into the broker-equivalent
 *        codes the application is expected to handle.
 */
static rd_kafka_resp_err_t
rd_kafka_share_translate_app_err(rd_kafka_resp_err_t err) {
        switch (err) {
        case RD_KAFKA_RESP_ERR__TIMED_OUT:
        case RD_KAFKA_RESP_ERR__TIMED_OUT_QUEUE:
                return RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT;
        case RD_KAFKA_RESP_ERR__DESTROY:
        case RD_KAFKA_RESP_ERR__DESTROY_BROKER:
                return RD_KAFKA_RESP_ERR__TRANSPORT;
        case RD_KAFKA_RESP_ERR__BAD_MSG:
                return RD_KAFKA_RESP_ERR_INVALID_MSG;
        case RD_KAFKA_RESP_ERR__AUTHENTICATION:
                return RD_KAFKA_RESP_ERR_SASL_AUTHENTICATION_FAILED;
        default:
                return err;
        }
}

void rd_kafka_share_dispatch_ack_callbacks(rd_kafka_t *rk,
                                           rd_list_t *ack_details) {
        rd_kafka_share_ack_batches_t *ack_batch;
        int k;

        /* Locality: main thread - checks runtime-set registration flag. */
        /**
         * TODO KIP-932: Check if we want to send individual ops or 1 op.
         */
        if (!rk->rk_share_consumer.acknowledgement_commit_cb_registered ||
            !ack_details || rd_list_cnt(ack_details) == 0)
                return;

        /* Use per-partition error from each batch, translating internal
         * sentinels to their broker-equivalent codes before the app sees
         * them. */
        RD_LIST_FOREACH(ack_batch, ack_details, k) {
                ack_batch->rktpar->err =
                    rd_kafka_share_translate_app_err(ack_batch->rktpar->err);
                rd_kafka_share_enqueue_ack_commit_cb_op(rk, ack_batch,
                                                        ack_batch->rktpar->err);
        }
}

/**
 * @brief Send commit_sync response to the app thread and clear state.
 *
 * Creates a SHARE_COMMIT_SYNC_FANOUT reply op with the per-partition
 * results and enqueues it on the app thread's temp queue. Clears the
 * commit_sync request state.
 *
 * @param rkcg Consumer group handle.
 *
 * @locality main thread
 */
void rd_kafka_share_commit_sync_send_response(rd_kafka_cgrp_t *rkcg) {
        rd_kafka_op_t *rko_reply;
        rd_kafka_topic_partition_list_t *results =
            rkcg->rkcg_commit_sync_request.results;
        int i;

        /* Translate internal sentinels to broker-equivalent codes before
         * the app sees them. This is the unique fan-in for every
         * commit_sync result: every writer (apply_result, segregate-fail,
         * api-timer-cb, broker decommission) lands its err in this list
         * before we ship it back to the caller. */
        for (i = 0; i < results->cnt; i++)
                results->elems[i].err =
                    rd_kafka_share_translate_app_err(results->elems[i].err);

        rko_reply = rd_kafka_op_new(RD_KAFKA_OP_SHARE_COMMIT_SYNC_FANOUT_REPLY);
        rko_reply->rko_u.share_commit_sync_fanout_reply.results = results;

        rd_kafka_q_enq(rkcg->rkcg_commit_sync_request.replyq, rko_reply);
        rd_kafka_q_destroy(rkcg->rkcg_commit_sync_request.replyq);

        rkcg->rkcg_commit_sync_request.id                          = 0;
        rkcg->rkcg_commit_sync_request.results                     = NULL;
        rkcg->rkcg_commit_sync_request.replyq                      = NULL;
        rkcg->rkcg_commit_sync_request.abs_timeout                 = 0;
        rkcg->rkcg_commit_sync_request.brokers_awaiting_result_cnt = 0;
}

/**
 * @brief Check if all broker results are in and send response if done.
 *
 * Called after each broker reply arrives. If brokers_awaiting_result_cnt
 * reaches zero, stops the timeout timer and sends the response op
 * to the app thread's temp queue.
 *
 * @param rk Client instance.
 * @param rkcg Consumer group handle.
 *
 * @locality main thread
 */
void rd_kafka_share_commit_sync_maybe_complete(rd_kafka_t *rk,
                                               rd_kafka_cgrp_t *rkcg) {
        if (rkcg->rkcg_commit_sync_request.brokers_awaiting_result_cnt > 0)
                return;

        rd_kafka_dbg(rk, CGRP, "SHARE",
                     "Commit sync request %" PRId64
                     " complete; all broker replies received, "
                     "sending response",
                     rkcg->rkcg_commit_sync_request.id);

        rd_kafka_timer_stop(&rk->rk_timers, &rkcg->rkcg_commit_sync_request.tmr,
                            1);

        rd_kafka_share_commit_sync_send_response(rkcg);
}

/**
 * @brief Apply a broker's commit_sync result: copy each batch's
 *        per-partition err onto the corresponding entry in
 *        rkcg_commit_sync_request.results, decrement the count of
 *        brokers still awaiting reply, and complete the commit_sync
 *        if this was the last broker outstanding.
 *
 * The caller is responsible for setting batch->rktpar->err on each
 * batch before invoking this (either from the broker reply path or
 * from a synthetic failure path like broker decommission).
 *
 * @locality main thread.
 */
void rd_kafka_share_commit_sync_apply_result(rd_kafka_t *rk,
                                             rd_kafka_cgrp_t *rkcg,
                                             rd_list_t *ack_batches) {
        if (ack_batches) {
                rd_kafka_share_ack_batches_t *batch;
                int k;

                RD_LIST_FOREACH(batch, ack_batches, k) {
                        rd_kafka_topic_partition_t *dst =
                            rd_kafka_topic_partition_list_find(
                                rkcg->rkcg_commit_sync_request.results,
                                batch->rktpar->topic, batch->rktpar->partition);
                        if (dst)
                                dst->err = batch->rktpar->err;
                }
        }

        rkcg->rkcg_commit_sync_request.brokers_awaiting_result_cnt--;
        rd_kafka_share_commit_sync_maybe_complete(rk, rkcg);
}


void rd_kafka_share_acks_clear_during_broker_decommission(
    rd_kafka_t *rk,
    rd_kafka_broker_t *rkb) {
        rd_kafka_share_ack_batches_t *batch;
        int k;

        /* Async acks: stamp SHARE_SESSION_NOT_FOUND on each batch and
         * fire the share-ack callback so the application sees the
         * failure. */
        if (rkb->rkb_share_async_ack_details) {
                rd_rkb_dbg(rkb, BROKER, "TERM",
                           "Clearing %d pending async ack batch(es); "
                           "dispatching ack callbacks with "
                           "SHARE_SESSION_NOT_FOUND",
                           rd_list_cnt(rkb->rkb_share_async_ack_details));

                RD_LIST_FOREACH(batch, rkb->rkb_share_async_ack_details, k) {
                        batch->rktpar->err =
                            RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND;
                }

                rd_kafka_share_dispatch_ack_callbacks(
                    rk, rkb->rkb_share_async_ack_details);

                rd_list_destroy(rkb->rkb_share_async_ack_details);
                rkb->rkb_share_async_ack_details = NULL;
        }

        /* Sync acks: stamp SHARE_SESSION_NOT_FOUND on each batch and
         * apply the result to the in-flight commit_sync request (copies
         * err into the cgrp's result list, decrements awaiting count,
         * completes the sync if this was the last broker outstanding). */
        if (rkb->rkb_pending_commit_sync.sync_ack_details) {
                rd_kafka_cgrp_t *rkcg = rd_kafka_cgrp_get(rk);

                rd_rkb_dbg(
                    rkb, BROKER, "TERM",
                    "Clearing %d pending commit sync ack batch(es); "
                    "dispatching ack callbacks and "
                    "stamping SHARE_SESSION_NOT_FOUND on commit_sync result "
                    "for this broker's partitions",
                    rd_list_cnt(rkb->rkb_pending_commit_sync.sync_ack_details));

                RD_LIST_FOREACH(
                    batch, rkb->rkb_pending_commit_sync.sync_ack_details, k) {
                        batch->rktpar->err =
                            RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND;
                }

                rd_kafka_share_commit_sync_apply_result(
                    rk, rkcg, rkb->rkb_pending_commit_sync.sync_ack_details);

                rd_kafka_share_dispatch_ack_callbacks(
                    rk, rkb->rkb_pending_commit_sync.sync_ack_details);

                rd_list_destroy(rkb->rkb_pending_commit_sync.sync_ack_details);
                rkb->rkb_pending_commit_sync.sync_ack_details = NULL;
        }
}
