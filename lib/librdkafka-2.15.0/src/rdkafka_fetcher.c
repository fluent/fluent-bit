/*
 * librdkafka - The Apache Kafka C/C++ library
 *
 * Copyright (c) 2022, Magnus Edenhill
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


/**
 * @name Fetcher
 *
 */

#include "rdkafka_int.h"
#include "rdkafka_offset.h"
#include "rdkafka_msgset.h"
#include "rdkafka_fetcher.h"
#include "rdkafka_request.h"
#include "rdkafka_share_acknowledgement.h"


/**
 * Backoff the next Fetch request (due to error).
 */
static void rd_kafka_broker_fetch_backoff(rd_kafka_broker_t *rkb,
                                          rd_kafka_resp_err_t err) {
        int backoff_ms            = rkb->rkb_rk->rk_conf.fetch_error_backoff_ms;
        rkb->rkb_ts_fetch_backoff = rd_clock() + (backoff_ms * 1000);
        rd_rkb_dbg(rkb, FETCH, "BACKOFF", "Fetch backoff for %dms: %s",
                   backoff_ms, rd_kafka_err2str(err));
}

/**
 * @brief Backoff the next Fetch for specific partition
 *
 * @returns the absolute backoff time (the current time for no backoff).
 */
static rd_ts_t rd_kafka_toppar_fetch_backoff(rd_kafka_broker_t *rkb,
                                             rd_kafka_toppar_t *rktp,
                                             rd_kafka_resp_err_t err) {
        int backoff_ms;

        /* Don't back off on reaching end of partition */
        if (err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
                rktp->rktp_ts_fetch_backoff = 0;
                return rd_clock(); /* Immediate: No practical backoff */
        }

        if (err == RD_KAFKA_RESP_ERR__QUEUE_FULL)
                backoff_ms = rkb->rkb_rk->rk_conf.fetch_queue_backoff_ms;
        else
                backoff_ms = rkb->rkb_rk->rk_conf.fetch_error_backoff_ms;

        if (unlikely(!backoff_ms)) {
                rktp->rktp_ts_fetch_backoff = 0;
                return rd_clock(); /* Immediate: No practical backoff */
        }

        /* Certain errors that may require manual intervention should have
         * a longer backoff time. */
        if (err == RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED)
                backoff_ms = RD_MAX(1000, backoff_ms * 10);

        rktp->rktp_ts_fetch_backoff = rd_clock() + (backoff_ms * 1000);

        rd_rkb_dbg(rkb, FETCH, "BACKOFF",
                   "%s [%" PRId32 "]: Fetch backoff for %dms%s%s",
                   rktp->rktp_rkt->rkt_topic->str, rktp->rktp_partition,
                   backoff_ms, err ? ": " : "",
                   err ? rd_kafka_err2str(err) : "");

        return rktp->rktp_ts_fetch_backoff;
}

/**
 * @brief Handle preferred replica in fetch response.
 *
 * @locks rd_kafka_toppar_lock(rktp) and
 *        rd_kafka_rdlock(rk) must NOT be held.
 *
 * @locality broker thread
 */
static void rd_kafka_fetch_preferred_replica_handle(rd_kafka_toppar_t *rktp,
                                                    rd_kafka_buf_t *rkbuf,
                                                    rd_kafka_broker_t *rkb,
                                                    int32_t preferred_id) {
        const rd_ts_t one_minute   = 60 * 1000 * 1000;
        const rd_ts_t five_seconds = 5 * 1000 * 1000;
        rd_kafka_broker_t *preferred_rkb;
        rd_kafka_t *rk = rktp->rktp_rkt->rkt_rk;
        rd_ts_t new_intvl =
            rd_interval_immediate(&rktp->rktp_new_lease_intvl, one_minute, 0);

        if (new_intvl < 0) {
                /* In lieu of KIP-320, the toppar is delegated back to
                 * the leader in the event of an offset out-of-range
                 * error (KIP-392 error case #4) because this scenario
                 * implies the preferred replica is out-of-sync.
                 *
                 * If program execution reaches here, the leader has
                 * relatively quickly instructed the client back to
                 * a preferred replica, quite possibly the same one
                 * as before (possibly resulting from stale metadata),
                 * so we back off the toppar to slow down potential
                 * back-and-forth.
                 */

                if (rd_interval_immediate(&rktp->rktp_new_lease_log_intvl,
                                          one_minute, 0) > 0)
                        rd_rkb_log(rkb, LOG_NOTICE, "FETCH",
                                   "%.*s [%" PRId32
                                   "]: preferred replica "
                                   "(%" PRId32
                                   ") lease changing too quickly "
                                   "(%" PRId64
                                   "s < 60s): possibly due to "
                                   "unavailable replica or stale cluster "
                                   "state: backing off next fetch",
                                   RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                                   rktp->rktp_partition, preferred_id,
                                   (one_minute - -new_intvl) / (1000 * 1000));

                rd_kafka_toppar_fetch_backoff(rkb, rktp,
                                              RD_KAFKA_RESP_ERR_NO_ERROR);
        }

        rd_kafka_rdlock(rk);
        preferred_rkb = rd_kafka_broker_find_by_nodeid(rk, preferred_id);
        rd_kafka_rdunlock(rk);

        if (preferred_rkb) {
                rd_interval_reset_to_now(&rktp->rktp_lease_intvl, 0);
                rd_kafka_toppar_lock(rktp);
                rd_kafka_toppar_broker_update(rktp, preferred_id, preferred_rkb,
                                              "preferred replica updated");
                rd_kafka_toppar_unlock(rktp);
                rd_kafka_broker_destroy(preferred_rkb);
                return;
        }

        if (rd_interval_immediate(&rktp->rktp_metadata_intvl, five_seconds, 0) >
            0) {
                rd_rkb_log(rkb, LOG_NOTICE, "FETCH",
                           "%.*s [%" PRId32 "]: preferred replica (%" PRId32
                           ") "
                           "is unknown: refreshing metadata",
                           RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                           rktp->rktp_partition, preferred_id);

                rd_kafka_metadata_refresh_brokers(
                    rktp->rktp_rkt->rkt_rk, NULL,
                    "preferred replica unavailable");
        }

        rd_kafka_toppar_fetch_backoff(rkb, rktp,
                                      RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE);
}


/**
 * @brief Handle partition-specific Fetch error.
 */
static void rd_kafka_fetch_reply_handle_partition_error(
    rd_kafka_broker_t *rkb,
    rd_kafka_toppar_t *rktp,
    const struct rd_kafka_toppar_ver *tver,
    rd_kafka_resp_err_t err,
    int64_t HighwaterMarkOffset) {

        rd_rkb_dbg(rkb, FETCH, "FETCHERR",
                   "%.*s [%" PRId32 "]: Fetch failed at %s: %s",
                   RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                   rktp->rktp_partition,
                   rd_kafka_fetch_pos2str(rktp->rktp_offsets.fetch_pos),
                   rd_kafka_err2name(err));

        /* Some errors should be passed to the
         * application while some handled by rdkafka */
        switch (err) {
                /* Errors handled by rdkafka */
        case RD_KAFKA_RESP_ERR_OFFSET_NOT_AVAILABLE:
        case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART:
        case RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE:
        case RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER:
        case RD_KAFKA_RESP_ERR_BROKER_NOT_AVAILABLE:
        case RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE:
        case RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR:
        case RD_KAFKA_RESP_ERR_UNKNOWN_LEADER_EPOCH:
        case RD_KAFKA_RESP_ERR_FENCED_LEADER_EPOCH:
        case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_ID:
                if (err == RD_KAFKA_RESP_ERR_OFFSET_NOT_AVAILABLE) {
                        /* Occurs when:
                         *   - Msg exists on broker but
                         *     offset > HWM, or:
                         *   - HWM is >= offset, but msg not
                         *     yet available at that offset
                         *     (replica is out of sync).
                         *   - partition leader is out of sync.
                         *
                         * Handle by requesting metadata update, changing back
                         * to the leader, and then retrying FETCH
                         * (with backoff).
                         */
                        rd_rkb_dbg(rkb, MSG, "FETCH",
                                   "Topic %s [%" PRId32
                                   "]: %s not "
                                   "available on broker %" PRId32
                                   " (leader %" PRId32
                                   "): updating metadata and retrying",
                                   rktp->rktp_rkt->rkt_topic->str,
                                   rktp->rktp_partition,
                                   rd_kafka_fetch_pos2str(
                                       rktp->rktp_offsets.fetch_pos),
                                   rktp->rktp_broker_id, rktp->rktp_leader_id);
                }

                if (err == RD_KAFKA_RESP_ERR_UNKNOWN_LEADER_EPOCH) {
                        rd_rkb_dbg(rkb, MSG | RD_KAFKA_DBG_CONSUMER, "FETCH",
                                   "Topic %s [%" PRId32
                                   "]: Fetch failed at %s: %s: broker %" PRId32
                                   "has not yet caught up on latest metadata: "
                                   "retrying",
                                   rktp->rktp_rkt->rkt_topic->str,
                                   rktp->rktp_partition,
                                   rd_kafka_fetch_pos2str(
                                       rktp->rktp_offsets.fetch_pos),
                                   rd_kafka_err2str(err), rktp->rktp_broker_id);
                }

                if (rktp->rktp_broker_id != rktp->rktp_leader_id) {
                        rd_kafka_toppar_delegate_to_leader(rktp);
                }
                /* Request metadata information update*/
                rd_kafka_toppar_leader_unavailable(rktp, "fetch", err);
                break;

        case RD_KAFKA_RESP_ERR_OFFSET_OUT_OF_RANGE: {
                rd_kafka_fetch_pos_t err_pos;

                if (rktp->rktp_broker_id != rktp->rktp_leader_id &&
                    rktp->rktp_offsets.fetch_pos.offset > HighwaterMarkOffset) {
                        rd_kafka_log(rkb->rkb_rk, LOG_WARNING, "FETCH",
                                     "Topic %s [%" PRId32
                                     "]: %s "
                                     " out of range (HighwaterMark %" PRId64
                                     " fetching from "
                                     "broker %" PRId32 " (leader %" PRId32
                                     "): reverting to leader",
                                     rktp->rktp_rkt->rkt_topic->str,
                                     rktp->rktp_partition,
                                     rd_kafka_fetch_pos2str(
                                         rktp->rktp_offsets.fetch_pos),
                                     HighwaterMarkOffset, rktp->rktp_broker_id,
                                     rktp->rktp_leader_id);

                        /* Out of range error cannot be taken as definitive
                         * when fetching from follower.
                         * Revert back to the leader in lieu of KIP-320.
                         */
                        rd_kafka_toppar_delegate_to_leader(rktp);
                        break;
                }

                /* Application error */
                err_pos = rktp->rktp_offsets.fetch_pos;
                rktp->rktp_offsets.fetch_pos.offset = RD_KAFKA_OFFSET_INVALID;
                rktp->rktp_offsets.fetch_pos.leader_epoch = -1;
                rd_kafka_offset_reset(rktp, rd_kafka_broker_id(rkb), err_pos,
                                      err,
                                      "fetch failed due to requested offset "
                                      "not available on the broker");
        } break;

        case RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED:
                /* If we're not authorized to access the
                 * topic mark it as errored to deny
                 * further Fetch requests. */
                if (rktp->rktp_last_error != err) {
                        rd_kafka_consumer_err(
                            rktp->rktp_fetchq, rd_kafka_broker_id(rkb), err,
                            tver->version, NULL, rktp,
                            rktp->rktp_offsets.fetch_pos.offset,
                            "Fetch from broker %" PRId32 " failed: %s",
                            rd_kafka_broker_id(rkb), rd_kafka_err2str(err));
                        rktp->rktp_last_error = err;
                }
                break;


                /* Application errors */
        case RD_KAFKA_RESP_ERR__PARTITION_EOF:
                if (rkb->rkb_rk->rk_conf.enable_partition_eof)
                        rd_kafka_consumer_err(
                            rktp->rktp_fetchq, rd_kafka_broker_id(rkb), err,
                            tver->version, NULL, rktp,
                            rktp->rktp_offsets.fetch_pos.offset,
                            "Fetch from broker %" PRId32
                            " reached end of "
                            "partition at offset %" PRId64
                            " (HighwaterMark %" PRId64 ")",
                            rd_kafka_broker_id(rkb),
                            rktp->rktp_offsets.fetch_pos.offset,
                            HighwaterMarkOffset);
                break;

        case RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE:
        default: /* and all other errors */
                rd_dassert(tver->version > 0);
                rd_kafka_consumer_err(
                    rktp->rktp_fetchq, rd_kafka_broker_id(rkb), err,
                    tver->version, NULL, rktp,
                    rktp->rktp_offsets.fetch_pos.offset,
                    "Fetch from broker %" PRId32 " failed at %s: %s",
                    rd_kafka_broker_id(rkb),
                    rd_kafka_fetch_pos2str(rktp->rktp_offsets.fetch_pos),
                    rd_kafka_err2str(err));
                break;
        }

        /* Back off the next fetch for this partition */
        rd_kafka_toppar_fetch_backoff(rkb, rktp, err);
}

static void rd_kafkap_Fetch_reply_tags_set_topic_cnt(
    rd_kafkap_Fetch_reply_tags_t *reply_tags,
    int32_t TopicCnt) {
        reply_tags->TopicCnt = TopicCnt;
        rd_dassert(!reply_tags->Topics);
        reply_tags->Topics = rd_calloc(TopicCnt, sizeof(*reply_tags->Topics));
}

static void
rd_kafkap_Fetch_reply_tags_set_topic(rd_kafkap_Fetch_reply_tags_t *reply_tags,
                                     int TopicIdx,
                                     rd_kafka_Uuid_t TopicId,
                                     int32_t PartitionCnt) {
        reply_tags->Topics[TopicIdx].TopicId      = TopicId;
        reply_tags->Topics[TopicIdx].PartitionCnt = PartitionCnt;
        rd_dassert(!reply_tags->Topics[TopicIdx].Partitions);
        reply_tags->Topics[TopicIdx].Partitions = rd_calloc(
            PartitionCnt, sizeof(*reply_tags->Topics[TopicIdx].Partitions));
}


static void
rd_kafkap_Fetch_reply_tags_destroy(rd_kafkap_Fetch_reply_tags_t *reply_tags) {
        int i;
        for (i = 0; i < reply_tags->TopicCnt; i++) {
                RD_IF_FREE(reply_tags->Topics[i].Partitions, rd_free);
        }
        RD_IF_FREE(reply_tags->Topics, rd_free);
        RD_IF_FREE(reply_tags->NodeEndpoints.NodeEndpoints, rd_free);
}

static int rd_kafkap_Fetch_reply_tags_partition_parse(
    rd_kafka_buf_t *rkbuf,
    uint64_t tagtype,
    uint64_t taglen,
    rd_kafkap_Fetch_reply_tags_Topic_t *TopicTags,
    rd_kafkap_Fetch_reply_tags_Partition_t *PartitionTags) {
        switch (tagtype) {
        case 1: /* CurrentLeader */
                if (rd_kafka_buf_read_CurrentLeader(
                        rkbuf, &PartitionTags->CurrentLeader) == -1)
                        goto err_parse;
                TopicTags->partitions_with_leader_change_cnt++;
                return 1;
        default:
                return 0;
        }
err_parse:
        return -1;
}

static int
rd_kafkap_Fetch_reply_tags_parse(rd_kafka_buf_t *rkbuf,
                                 uint64_t tagtype,
                                 uint64_t taglen,
                                 rd_kafkap_Fetch_reply_tags_t *tags) {
        switch (tagtype) {
        case 0: /* NodeEndpoints */
                if (rd_kafka_buf_read_NodeEndpoints(rkbuf,
                                                    &tags->NodeEndpoints) == -1)
                        goto err_parse;
                return 1;
        default:
                return 0;
        }
err_parse:
        return -1;
}

static void
rd_kafka_handle_Fetch_metadata_update(rd_kafka_broker_t *rkb,
                                      rd_kafkap_Fetch_reply_tags_t *FetchTags) {
        if (FetchTags->topics_with_leader_change_cnt &&
            FetchTags->NodeEndpoints.NodeEndpoints) {
                rd_kafka_metadata_t *md           = NULL;
                rd_kafka_metadata_internal_t *mdi = NULL;
                rd_tmpabuf_t tbuf;
                int32_t nodeid;
                rd_kafka_op_t *rko;
                int i, changed_topic, changed_partition;

                rd_kafka_broker_lock(rkb);
                nodeid = rkb->rkb_nodeid;
                rd_kafka_broker_unlock(rkb);

                rd_tmpabuf_new(&tbuf, 0, rd_true /*assert on fail*/);
                rd_tmpabuf_add_alloc(&tbuf, sizeof(*mdi));
                rd_kafkap_leader_discovery_tmpabuf_add_alloc_brokers(
                    &tbuf, &FetchTags->NodeEndpoints);
                rd_kafkap_leader_discovery_tmpabuf_add_alloc_topics(
                    &tbuf, FetchTags->topics_with_leader_change_cnt);
                for (i = 0; i < FetchTags->TopicCnt; i++) {
                        if (!FetchTags->Topics[i]
                                 .partitions_with_leader_change_cnt)
                                continue;
                        rd_kafkap_leader_discovery_tmpabuf_add_alloc_topic(
                            &tbuf, NULL,
                            FetchTags->Topics[i]
                                .partitions_with_leader_change_cnt);
                }
                rd_tmpabuf_finalize(&tbuf);

                mdi = rd_tmpabuf_alloc(&tbuf, sizeof(*mdi));
                md  = &mdi->metadata;

                rd_kafkap_leader_discovery_metadata_init(mdi, nodeid);

                rd_kafkap_leader_discovery_set_brokers(
                    &tbuf, mdi, &FetchTags->NodeEndpoints);

                rd_kafkap_leader_discovery_set_topic_cnt(
                    &tbuf, mdi, FetchTags->topics_with_leader_change_cnt);

                changed_topic = 0;
                for (i = 0; i < FetchTags->TopicCnt; i++) {
                        int j;
                        if (!FetchTags->Topics[i]
                                 .partitions_with_leader_change_cnt)
                                continue;

                        rd_kafkap_leader_discovery_set_topic(
                            &tbuf, mdi, changed_topic,
                            FetchTags->Topics[i].TopicId, NULL,
                            FetchTags->Topics[i]
                                .partitions_with_leader_change_cnt);

                        changed_partition = 0;
                        for (j = 0; j < FetchTags->Topics[i].PartitionCnt;
                             j++) {
                                if (FetchTags->Topics[i]
                                        .Partitions[j]
                                        .CurrentLeader.LeaderId < 0)
                                        continue;

                                rd_kafkap_Fetch_reply_tags_Partition_t
                                    *Partition =
                                        &FetchTags->Topics[i].Partitions[j];
                                rd_kafkap_leader_discovery_set_CurrentLeader(
                                    &tbuf, mdi, changed_topic,
                                    changed_partition, Partition->Partition,
                                    &Partition->CurrentLeader);
                                changed_partition++;
                        }
                        changed_topic++;
                }

                rko = rd_kafka_op_new(RD_KAFKA_OP_METADATA_UPDATE);
                rko->rko_u.metadata.md  = md;
                rko->rko_u.metadata.mdi = mdi;
                rd_kafka_q_enq(rkb->rkb_rk->rk_ops, rko);
        }
}

/**
 * @brief Per-partition FetchResponse parsing and handling.
 *
 * @returns an error on buffer parse failure, else RD_KAFKA_RESP_ERR_NO_ERROR.
 */
static rd_kafka_resp_err_t rd_kafka_fetch_reply_handle_partition(
    rd_kafka_broker_t *rkb,
    const rd_kafkap_str_t *topic,
    rd_kafka_topic_t *rkt /*possibly NULL*/,
    rd_kafka_buf_t *rkbuf,
    rd_kafka_buf_t *request,
    int16_t ErrorCode,
    rd_kafkap_Fetch_reply_tags_Topic_t *TopicTags,
    rd_kafkap_Fetch_reply_tags_Partition_t *PartitionTags) {
        const int log_decode_errors = LOG_ERR;
        struct rd_kafka_toppar_ver *tver, tver_skel;
        rd_kafka_toppar_t *rktp               = NULL;
        rd_kafka_aborted_txns_t *aborted_txns = NULL;
        rd_slice_t save_slice;
        int32_t fetch_version;
        struct {
                int32_t Partition;
                int16_t ErrorCode;
                int64_t HighwaterMarkOffset;
                int64_t LastStableOffset; /* v4 */
                int64_t LogStartOffset;   /* v5 */
                int32_t MessageSetSize;
                int32_t PreferredReadReplica; /* v11 */
        } hdr;
        rd_kafka_resp_err_t err;
        int64_t end_offset;

        rd_kafka_buf_read_i32(rkbuf, &hdr.Partition);
        rd_kafka_buf_read_i16(rkbuf, &hdr.ErrorCode);
        if (PartitionTags)
                PartitionTags->Partition = hdr.Partition;
        if (ErrorCode)
                hdr.ErrorCode = ErrorCode;
        rd_kafka_buf_read_i64(rkbuf, &hdr.HighwaterMarkOffset);

        end_offset = hdr.HighwaterMarkOffset;

        hdr.LastStableOffset = RD_KAFKA_OFFSET_INVALID;
        hdr.LogStartOffset   = RD_KAFKA_OFFSET_INVALID;
        if (rd_kafka_buf_ApiVersion(request) >= 4) {
                int32_t AbortedTxnCnt;
                int k;
                rd_kafka_buf_read_i64(rkbuf, &hdr.LastStableOffset);
                if (rd_kafka_buf_ApiVersion(request) >= 5)
                        rd_kafka_buf_read_i64(rkbuf, &hdr.LogStartOffset);

                rd_kafka_buf_read_arraycnt(rkbuf, &AbortedTxnCnt,
                                           RD_KAFKAP_ABORTED_TRANSACTIONS_MAX);

                if (rkb->rkb_rk->rk_conf.isolation_level ==
                    RD_KAFKA_READ_UNCOMMITTED) {

                        if (unlikely(AbortedTxnCnt > 0)) {
                                rd_rkb_log(rkb, LOG_ERR, "FETCH",
                                           "%.*s [%" PRId32
                                           "]: "
                                           "%" PRId32
                                           " aborted transaction(s) "
                                           "encountered in READ_UNCOMMITTED "
                                           "fetch response: ignoring.",
                                           RD_KAFKAP_STR_PR(topic),
                                           hdr.Partition, AbortedTxnCnt);
                                for (k = 0; k < AbortedTxnCnt; k++) {
                                        rd_kafka_buf_skip(rkbuf, (8 + 8));
                                        /* AbortedTransaction tags */
                                        rd_kafka_buf_skip_tags(rkbuf);
                                }
                        }
                } else {
                        /* Older brokers may return LSO -1,
                         * in which case we use the HWM. */
                        if (hdr.LastStableOffset >= 0)
                                end_offset = hdr.LastStableOffset;

                        if (AbortedTxnCnt > 0) {
                                aborted_txns =
                                    rd_kafka_aborted_txns_new(AbortedTxnCnt);
                                for (k = 0; k < AbortedTxnCnt; k++) {
                                        int64_t PID;
                                        int64_t FirstOffset;
                                        rd_kafka_buf_read_i64(rkbuf, &PID);
                                        rd_kafka_buf_read_i64(rkbuf,
                                                              &FirstOffset);
                                        /* AbortedTransaction tags */
                                        rd_kafka_buf_skip_tags(rkbuf);
                                        rd_kafka_aborted_txns_add(
                                            aborted_txns, PID, FirstOffset);
                                }
                                rd_kafka_aborted_txns_sort(aborted_txns);
                        }
                }
        }

        if (rd_kafka_buf_ApiVersion(request) >= 11)
                rd_kafka_buf_read_i32(rkbuf, &hdr.PreferredReadReplica);
        else
                hdr.PreferredReadReplica = -1;
        /* Compact Records Array */
        rd_kafka_buf_read_arraycnt(rkbuf, &hdr.MessageSetSize, -1);

        if (unlikely(hdr.MessageSetSize < 0))
                rd_kafka_buf_parse_fail(
                    rkbuf,
                    "%.*s [%" PRId32 "]: invalid MessageSetSize %" PRId32,
                    RD_KAFKAP_STR_PR(topic), hdr.Partition, hdr.MessageSetSize);

        /* Look up topic+partition */
        if (likely(rkt != NULL)) {
                rd_kafka_topic_rdlock(rkt);
                rktp = rd_kafka_toppar_get(rkt, hdr.Partition,
                                           0 /*no ua-on-miss*/);
                rd_kafka_topic_rdunlock(rkt);
        }

        if (unlikely(!rkt || !rktp)) {
                rd_rkb_dbg(rkb, TOPIC, "UNKTOPIC",
                           "Received Fetch response (error %hu) for unknown "
                           "topic %.*s [%" PRId32 "]: ignoring",
                           hdr.ErrorCode, RD_KAFKAP_STR_PR(topic),
                           hdr.Partition);
                rd_kafka_buf_skip(rkbuf, hdr.MessageSetSize);
                goto done;
        }

        rd_kafka_toppar_lock(rktp);
        rktp->rktp_lo_offset = hdr.LogStartOffset;
        rktp->rktp_hi_offset = hdr.HighwaterMarkOffset;
        /* Let the LastStable offset be the effective
         * end_offset based on protocol version, that is:
         * if connected to a broker that does not support
         * LastStableOffset we use the HighwaterMarkOffset. */
        rktp->rktp_ls_offset = end_offset;
        rd_kafka_toppar_unlock(rktp);

        if (hdr.PreferredReadReplica != -1) {

                rd_kafka_fetch_preferred_replica_handle(
                    rktp, rkbuf, rkb, hdr.PreferredReadReplica);

                if (unlikely(hdr.MessageSetSize != 0)) {
                        rd_rkb_log(rkb, LOG_WARNING, "FETCH",
                                   "%.*s [%" PRId32
                                   "]: Fetch response has both preferred read "
                                   "replica and non-zero message set size: "
                                   "%" PRId32 ": skipping messages",
                                   RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                                   rktp->rktp_partition, hdr.MessageSetSize);
                        rd_kafka_buf_skip(rkbuf, hdr.MessageSetSize);
                }
                goto done;
        }

        rd_kafka_toppar_lock(rktp);

        /* Make sure toppar hasn't moved to another broker
         * during the lifetime of the request. */
        if (unlikely(rktp->rktp_broker != rkb)) {
                rd_kafka_toppar_unlock(rktp);
                rd_rkb_dbg(rkb, MSG, "FETCH",
                           "%.*s [%" PRId32
                           "]: partition broker has changed: "
                           "discarding fetch response",
                           RD_KAFKAP_STR_PR(topic), hdr.Partition);
                rd_kafka_buf_skip(rkbuf, hdr.MessageSetSize);
                goto done;
        }

        fetch_version = rktp->rktp_fetch_version;
        rd_kafka_toppar_unlock(rktp);

        /* Check if this Fetch is for an outdated fetch version,
         * or the original rktp was removed and a new one
         * created (due to partition count decreasing and
         * then increasing again, which can happen in
         * desynchronized clusters): if so ignore it. */
        tver_skel.rktp = rktp;
        tver           = rd_list_find(request->rkbuf_rktp_vers, &tver_skel,
                                      rd_kafka_toppar_ver_cmp);
        rd_kafka_assert(NULL, tver);
        if (tver->rktp != rktp || tver->version < fetch_version) {
                rd_rkb_dbg(rkb, MSG, "DROP",
                           "%s [%" PRId32
                           "]: dropping outdated fetch response "
                           "(v%d < %d or old rktp)",
                           rktp->rktp_rkt->rkt_topic->str, rktp->rktp_partition,
                           tver->version, fetch_version);
                rd_atomic64_add(&rktp->rktp_c.rx_ver_drops, 1);
                rd_kafka_buf_skip(rkbuf, hdr.MessageSetSize);
                goto done;
        }

        rd_rkb_dbg(rkb, MSG, "FETCH",
                   "Topic %.*s [%" PRId32 "] MessageSet size %" PRId32
                   ", error \"%s\", MaxOffset %" PRId64 ", LSO %" PRId64
                   ", Ver %" PRId32 "/%" PRId32,
                   RD_KAFKAP_STR_PR(topic), hdr.Partition, hdr.MessageSetSize,
                   rd_kafka_err2str(hdr.ErrorCode), hdr.HighwaterMarkOffset,
                   hdr.LastStableOffset, tver->version, fetch_version);

        /* If this is the last message of the queue,
         * signal EOF back to the application. */
        if (end_offset == rktp->rktp_offsets.fetch_pos.offset &&
            rktp->rktp_offsets.eof_offset != end_offset) {
                hdr.ErrorCode = RD_KAFKA_RESP_ERR__PARTITION_EOF;
                rktp->rktp_offsets.eof_offset = end_offset;
        }

        if (unlikely(hdr.ErrorCode != RD_KAFKA_RESP_ERR_NO_ERROR)) {
                /* Handle partition-level errors. */
                rd_kafka_fetch_reply_handle_partition_error(
                    rkb, rktp, tver, hdr.ErrorCode, hdr.HighwaterMarkOffset);

                rd_kafka_buf_skip(rkbuf, hdr.MessageSetSize);
                goto done;
        }

        /* No error, clear any previous fetch error. */
        rktp->rktp_last_error = RD_KAFKA_RESP_ERR_NO_ERROR;

        if (unlikely(hdr.MessageSetSize <= 0))
                goto done;

        /**
         * Parse MessageSet
         */
        if (!rd_slice_narrow_relative(&rkbuf->rkbuf_reader, &save_slice,
                                      (size_t)hdr.MessageSetSize))
                rd_kafka_buf_check_len(rkbuf, hdr.MessageSetSize);

        /* Parse messages */
        err = rd_kafka_msgset_parse(rkbuf, request, rktp, aborted_txns, tver);


        rd_slice_widen(&rkbuf->rkbuf_reader, &save_slice);
        /* Continue with next partition regardless of
         * parse errors (which are partition-specific) */

        /* On error: back off the fetcher for this partition */
        if (unlikely(err))
                rd_kafka_toppar_fetch_backoff(rkb, rktp, err);

        goto done;

err_parse:
        if (aborted_txns)
                rd_kafka_aborted_txns_destroy(aborted_txns);
        if (rktp)
                rd_kafka_toppar_destroy(rktp); /*from get()*/
        return rkbuf->rkbuf_err;

done:
        if (aborted_txns)
                rd_kafka_aborted_txns_destroy(aborted_txns);
        if (likely(rktp != NULL))
                rd_kafka_toppar_destroy(rktp); /*from get()*/

        if (PartitionTags) {
                /* Set default LeaderId and LeaderEpoch */
                PartitionTags->CurrentLeader.LeaderId    = -1;
                PartitionTags->CurrentLeader.LeaderEpoch = -1;
        }
        rd_kafka_buf_read_tags(rkbuf,
                               rd_kafkap_Fetch_reply_tags_partition_parse,
                               TopicTags, PartitionTags);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}

/**
 * Parses and handles a Fetch reply.
 * Returns 0 on success or an error code on failure.
 */
static rd_kafka_resp_err_t
rd_kafka_fetch_reply_handle(rd_kafka_broker_t *rkb,
                            rd_kafka_buf_t *rkbuf,
                            rd_kafka_buf_t *request) {
        int32_t TopicArrayCnt;
        int i;
        const int log_decode_errors            = LOG_ERR;
        rd_kafka_topic_t *rkt                  = NULL;
        int16_t ErrorCode                      = RD_KAFKA_RESP_ERR_NO_ERROR;
        rd_kafkap_Fetch_reply_tags_t FetchTags = RD_ZERO_INIT;
        rd_bool_t has_fetch_tags               = rd_false;

        if (rd_kafka_buf_ApiVersion(request) >= 1) {
                int32_t Throttle_Time;
                rd_kafka_buf_read_i32(rkbuf, &Throttle_Time);

                rd_kafka_op_throttle_time(rkb, rkb->rkb_rk->rk_rep,
                                          Throttle_Time);
        }

        if (rd_kafka_buf_ApiVersion(request) >= 7) {
                int32_t SessionId;
                rd_kafka_buf_read_i16(rkbuf, &ErrorCode);
                rd_kafka_buf_read_i32(rkbuf, &SessionId);
        }

        rd_kafka_buf_read_arraycnt(rkbuf, &TopicArrayCnt, RD_KAFKAP_TOPICS_MAX);
        /* Verify that TopicArrayCnt seems to be in line with remaining size */
        rd_kafka_buf_check_len(rkbuf,
                               TopicArrayCnt * (3 /*topic min size*/ +
                                                4 /*PartitionArrayCnt*/ + 4 +
                                                2 + 8 + 4 /*inner header*/));

        if (rd_kafka_buf_ApiVersion(request) >= 12) {
                has_fetch_tags = rd_true;
                rd_kafkap_Fetch_reply_tags_set_topic_cnt(&FetchTags,
                                                         TopicArrayCnt);
        }

        for (i = 0; i < TopicArrayCnt; i++) {
                rd_kafkap_str_t topic    = RD_ZERO_INIT;
                rd_kafka_Uuid_t topic_id = RD_KAFKA_UUID_ZERO;
                int32_t PartitionArrayCnt;
                int j;

                if (rd_kafka_buf_ApiVersion(request) > 12) {
                        rd_kafka_buf_read_uuid(rkbuf, &topic_id);
                        rkt = rd_kafka_topic_find_by_topic_id(rkb->rkb_rk,
                                                              topic_id);
                        if (rkt)
                                topic = *rkt->rkt_topic;
                } else {
                        rd_kafka_buf_read_str(rkbuf, &topic);
                        rkt = rd_kafka_topic_find0(rkb->rkb_rk, &topic);
                }

                rd_kafka_buf_read_arraycnt(rkbuf, &PartitionArrayCnt,
                                           RD_KAFKAP_PARTITIONS_MAX);
                if (rd_kafka_buf_ApiVersion(request) >= 12) {
                        rd_kafkap_Fetch_reply_tags_set_topic(
                            &FetchTags, i, topic_id, PartitionArrayCnt);
                }

                for (j = 0; j < PartitionArrayCnt; j++) {
                        if (rd_kafka_fetch_reply_handle_partition(
                                rkb, &topic, rkt, rkbuf, request, ErrorCode,
                                has_fetch_tags ? &FetchTags.Topics[i] : NULL,
                                has_fetch_tags
                                    ? &FetchTags.Topics[i].Partitions[j]
                                    : NULL))
                                goto err_parse;
                }
                if (has_fetch_tags &&
                    FetchTags.Topics[i].partitions_with_leader_change_cnt) {
                        FetchTags.topics_with_leader_change_cnt++;
                }

                if (rkt) {
                        rd_kafka_topic_destroy0(rkt);
                        rkt = NULL;
                }
                /* Topic Tags */
                rd_kafka_buf_skip_tags(rkbuf);
        }

        /* Top level tags */
        rd_kafka_buf_read_tags(rkbuf, rd_kafkap_Fetch_reply_tags_parse,
                               &FetchTags);

        if (rd_kafka_buf_read_remain(rkbuf) != 0) {
                rd_kafka_buf_parse_fail(rkbuf,
                                        "Remaining data after message set "
                                        "parse: %" PRIusz " bytes",
                                        rd_kafka_buf_read_remain(rkbuf));
                RD_NOTREACHED();
        }
        rd_kafka_handle_Fetch_metadata_update(rkb, &FetchTags);
        rd_kafkap_Fetch_reply_tags_destroy(&FetchTags);

        return 0;

err_parse:
        if (rkt)
                rd_kafka_topic_destroy0(rkt);
        rd_kafkap_Fetch_reply_tags_destroy(&FetchTags);
        rd_rkb_dbg(rkb, MSG, "BADMSG",
                   "Bad message (Fetch v%d): "
                   "is broker.version.fallback incorrectly set?",
                   (int)request->rkbuf_reqhdr.ApiVersion);
        return rkbuf->rkbuf_err;
}

void rd_kafka_share_filter_acquired_records_and_update_ack_type(
    rd_kafka_q_t *temp_fetchq,
    rd_list_t *filtered_msgs,
    const int64_t *FirstOffsets,
    const int64_t *LastOffsets,
    const int16_t *DeliveryCounts,
    int32_t AcquiredRecordsArrayCnt) {

        rd_kafka_op_t *rko;

        /* Iterate through all messages in temp_fetchq and forward
         * only those whose offset falls within an acquired range.
         * Also set the ack type based on the op type. */
        while ((rko = rd_kafka_q_pop(temp_fetchq, RD_POLL_NOWAIT, 0)) != NULL) {
                int64_t rko_offset          = rd_kafka_op_get_offset(rko);
                rd_bool_t in_acquired_range = rd_false;
                int16_t delivery_count;
                int32_t range_idx;

                /* Check if this message's offset is within any acquired range
                 */
                for (range_idx = 0; range_idx < AcquiredRecordsArrayCnt;
                     range_idx++) {
                        if (rko_offset >= FirstOffsets[range_idx] &&
                            rko_offset <= LastOffsets[range_idx]) {
                                in_acquired_range = rd_true;
                                delivery_count    = DeliveryCounts[range_idx];
                                break;
                        }
                }

                if (in_acquired_range) {
                        /* Set ack type based on op type */
                        rd_kafka_msg_t *rkm = NULL;
                        if (unlikely(rd_kafka_op_is_ctrl_msg(rko))) {
                                rd_kafka_op_destroy(rko);
                                continue;
                        }
                        if (rko->rko_type == RD_KAFKA_OP_FETCH) {
                                rkm = &rko->rko_u.fetch.rkm;
                                rkm->rkm_u.consumer.ack_type =
                                    RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED;
                                rkm->rkm_u.consumer.delivery_count =
                                    delivery_count;
                        } else if (rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR) {
                                rkm = &rko->rko_u.err.rkm;
                                /* Set ack_type to RELEASE only if not already
                                 * set by rd_kafka_share_msgset_err_ops()
                                 * (which sets REJECT for CRC/unsupported
                                 * errors, RELEASE for decompression errors). */
                                if (rkm->rkm_u.consumer.ack_type ==
                                        RD_KAFKA_SHARE_INTERNAL_ACK_GAP ||
                                    rkm->rkm_u.consumer.ack_type ==
                                        RD_KAFKA_SHARE_INTERNAL_ACK_ACQUIRED)
                                        rkm->rkm_u.consumer.ack_type =
                                            RD_KAFKA_SHARE_INTERNAL_ACK_RELEASE;
                        }

                        /* Add to filtered messages list */
                        rd_list_add(filtered_msgs, rko);
                } else {
                        /* Discard message not in any acquired range */
                        rd_kafka_op_destroy(rko);
                }
        }
}


/**
 * @brief Comparator for sorting ops by offset.
 *
 * Note: rd_list_sort uses rd_list_cmp_trampoline which dereferences
 * the pointers before calling this comparator, so we receive
 * rd_kafka_op_t* directly, not rd_kafka_op_t**.
 */
static int rd_kafka_op_offset_cmp(const void *_a, const void *_b) {
        const rd_kafka_op_t *a = (const rd_kafka_op_t *)_a;
        const rd_kafka_op_t *b = (const rd_kafka_op_t *)_b;
        int64_t off_a          = rd_kafka_op_get_offset(a);
        int64_t off_b          = rd_kafka_op_get_offset(b);

        return (off_a > off_b) - (off_a < off_b);
}


/**
 * @brief Check if op matches the given topic-partition.
 *
 * Compares the rktp (toppar) reference to ensure both topic and partition
 * match, not just the partition number.
 */
static rd_bool_t rd_kafka_op_matches_toppar(const rd_kafka_op_t *rko,
                                            const rd_kafka_toppar_t *rktp) {
        return rko->rko_rktp == rktp;
}

/**
 * @brief Find the batch entry that contains the given offset.
 *
 * @returns The entry, or NULL if no entry contains the offset.
 */
static rd_kafka_share_ack_batch_entry_t *
rd_kafka_share_find_entry_for_offset(rd_kafka_share_ack_batches_t *batches,
                                     int64_t offset) {
        rd_kafka_share_ack_batch_entry_t *entry;
        int ei;

        RD_LIST_FOREACH(entry, &batches->entries, ei) {
                if (offset >= entry->start_offset &&
                    offset <= entry->end_offset)
                        return entry;
        }
        return NULL;
}

/**
 * @brief Get ack type from a message op (FETCH or CONSUMER_ERR).
 */
static rd_kafka_share_internal_acknowledgement_type
rd_kafka_share_ack_type_from_msg_op(rd_kafka_op_t *msg_rko) {
        rd_kafka_msg_t *rkm;

        if (msg_rko->rko_type == RD_KAFKA_OP_FETCH)
                rkm = &msg_rko->rko_u.fetch.rkm;
        else
                rkm = &msg_rko->rko_u.err.rkm;
        return rkm->rkm_u.consumer.ack_type;
}

/**
 * @brief Build share fetch response RKO with messages and update inflight acks.
 *
 * All entry types are pre-initialized to GAP in the reply handler. This
 * function overwrites ACQUIRED/REJECT for each offset that has a message
 * (RD_KAFKA_OP_FETCH or RD_KAFKA_OP_CONSUMER_ERR), and adds those messages
 * to the response. Moves inflight_acks batches to the response RKO.
 *
 * @param rkb Broker handle
 * @param filtered_msgs List of filtered message ops (with ack types already
 * set)
 * @param inflight_acks List of rd_kafka_share_ack_batches_t* (ownership
 *                      transferred to RKO)
 *
 * @returns New rko containing messages and inflight_acks, or NULL if empty
 */
static rd_kafka_op_t *
rd_kafka_share_build_response_rko(rd_kafka_broker_t *rkb,
                                  rd_list_t *filtered_msgs,
                                  rd_list_t *inflight_acks) {

        rd_kafka_op_t *response_rko;
        rd_kafka_share_ack_batches_t *batches;
        int32_t msg_cnt           = 0;
        int32_t inflight_acks_cnt = rd_list_cnt(inflight_acks);
        int pi, i;
        int total_msgs        = rd_list_cnt(filtered_msgs);
        int msg_start_idx     = 0;
        int64_t total_offsets = 0;

        /* Create response rko */
        response_rko = rd_kafka_op_new(RD_KAFKA_OP_SHARE_FETCH_RESPONSE);
        response_rko->rko_rk = rkb->rkb_rk;

        response_rko->rko_u.share_fetch_response.message_rkos =
            rd_list_new(0, NULL);
        response_rko->rko_u.share_fetch_response.inflight_acks =
            rd_list_new(0, rd_kafka_share_ack_batches_destroy_free);

        /* Process each partition: set types for message offsets, add messages.
         * Messages in filtered_msgs are grouped by partition in the same order
         * as inflight_acks. Types are already GAP; we set ACQUIRED/REJECT only
         * where we have a message. */
        RD_LIST_FOREACH(batches, inflight_acks, pi) {

                total_offsets += batches->response_acquired_offsets_count;

                rd_kafka_topic_partition_private_t *parpriv =
                    (rd_kafka_topic_partition_private_t *)
                        batches->rktpar->_private;
                rd_kafka_toppar_t *rktp = parpriv->rktp;

                rd_list_t partition_msgs;
                rd_list_init(&partition_msgs, 0, NULL);

                while (msg_start_idx < total_msgs) {
                        rd_kafka_op_t *candidate =
                            rd_list_elem(filtered_msgs, msg_start_idx);
                        if (!rd_kafka_op_matches_toppar(candidate, rktp))
                                break;
                        rd_list_add(&partition_msgs, candidate);
                        msg_start_idx++;
                }

                rd_list_sort(&partition_msgs, rd_kafka_op_offset_cmp);

                int partition_msg_cnt = rd_list_cnt(&partition_msgs);
                for (i = 0; i < partition_msg_cnt; i++) {
                        rd_kafka_op_t *msg_rko =
                            rd_list_elem(&partition_msgs, i);
                        int64_t offset = rd_kafka_op_get_offset(msg_rko);
                        rd_kafka_share_ack_batch_entry_t *entry =
                            rd_kafka_share_find_entry_for_offset(batches,
                                                                 offset);

                        if (unlikely(!entry)) {
                                rd_rkb_dbg(
                                    rkb, FETCH, "SHAREFETCH",
                                    "No ack entry found for offset %" PRId64
                                    " on %s [%" PRId32 "], skipping",
                                    offset, batches->rktpar->topic,
                                    batches->rktpar->partition);
                                rd_kafka_op_destroy(msg_rko);
                                continue;
                        }

                        entry->types[offset - entry->start_offset] =
                            rd_kafka_share_ack_type_from_msg_op(msg_rko);

                        /**
                         * The per message error ops (Decompression error, CRC
                         * error, or MagicByte Errors are tracked in the same
                         * list of messages as the successful messages.
                         * TODO KIP-932: Check if we need a new op for record
                         * level message errors: RD_KAFKA_OP_CONSUMER_MSG_ERR.
                         */
                        if (msg_rko->rko_type == RD_KAFKA_OP_FETCH ||
                            msg_rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR) {
                                rd_list_add(
                                    response_rko->rko_u.share_fetch_response
                                        .message_rkos,
                                    msg_rko);
                                msg_cnt++;
                        }
                }

                rd_list_destroy(&partition_msgs);
                rd_list_add(
                    response_rko->rko_u.share_fetch_response.inflight_acks,
                    rd_kafka_share_ack_batches_copy(batches));
        }

        if (msg_cnt == 0 && inflight_acks_cnt == 0) {
                rd_kafka_op_destroy(response_rko);
                return NULL;
        }

        rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                   "Built share fetch response rko with %d messages, "
                   "%d gaps, and %d partitions",
                   msg_cnt, (int32_t)(total_offsets - msg_cnt),
                   inflight_acks_cnt);

        return response_rko;
}


/**
 * @brief Handle a per-partition fetch error from a ShareFetch response.
 *
 * @locality broker thread
 */
static void rd_kafka_share_fetch_reply_handle_partition_error(
    rd_kafka_broker_t *rkb,
    rd_kafka_toppar_t *rktp,
    const rd_kafkap_str_t *topic,
    int32_t partition,
    rd_kafka_resp_err_t err,
    const rd_kafkap_str_t *err_msg) {

        /* TODO KIP-932: Verify whether the SURFACE-only arms below
         * (CORRUPT_MESSAGE, default unknown err) should also emit an
         * explicit warn-level log here. They currently rely on the
         * downstream OP_CONSUMER_ERR being surfaced to the app via
         * consume_batch. */
        /* TODO KIP-932: write test cases for each per-partition error
         * arm below once the mock cluster exposes a per-partition
         * error-injection API (e.g.
         * rd_kafka_mock_partition_push_share_fetch_error). Today only
         * the leader-change errors are exercised via
         * rd_kafka_mock_partition_set_leader; the remaining arms
         * (KAFKA_STORAGE_ERROR, OFFSET_NOT_AVAILABLE,
         * REPLICA_NOT_AVAILABLE, UNKNOWN_TOPIC_OR_PART,
         * UNKNOWN_TOPIC_ID, INCONSISTENT_TOPIC_ID,
         * TOPIC_AUTHORIZATION_FAILED, UNKNOWN_LEADER_EPOCH,
         * UNKNOWN_SERVER_ERROR, CORRUPT_MESSAGE, and the default)
         * have no deterministic mock trigger. */
        switch (err) {
        case RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER:
        case RD_KAFKA_RESP_ERR_FENCED_LEADER_EPOCH:
        case RD_KAFKA_RESP_ERR_KAFKA_STORAGE_ERROR:
        case RD_KAFKA_RESP_ERR_OFFSET_NOT_AVAILABLE:
        case RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE:
                rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                           "%.*s [%" PRId32
                           "]: ShareFetch failed: %s: %.*s: "
                           "triggering metadata refresh",
                           RD_KAFKAP_STR_PR(topic), partition,
                           rd_kafka_err2name(err), RD_KAFKAP_STR_PR(err_msg));
                rd_kafka_toppar_leader_unavailable(rktp, "sharefetch", err);
                break;

        case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART:
        case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_ID:
        case RD_KAFKA_RESP_ERR_INCONSISTENT_TOPIC_ID:
                /* No per-partition recovery action; left for the next
                 * metadata refresh / heartbeat reconciliation to resolve. */
                rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                           "%.*s [%" PRId32 "]: ShareFetch failed: %s: %.*s",
                           RD_KAFKAP_STR_PR(topic), partition,
                           rd_kafka_err2name(err), RD_KAFKAP_STR_PR(err_msg));
                break;

        case RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED:
                rd_rkb_log(rkb, LOG_WARNING, "SHAREFETCH",
                           "%.*s [%" PRId32 "]: Not authorized to read: %.*s",
                           RD_KAFKAP_STR_PR(topic), partition,
                           RD_KAFKAP_STR_PR(err_msg));
                rd_kafka_consumer_err(
                    rkb->rkb_rk->rk_cgrp->rkcg_q, rd_kafka_broker_id(rkb), err,
                    0, NULL, rktp, RD_KAFKA_OFFSET_INVALID,
                    "ShareFetch failed for %.*s [%" PRId32 "]: %.*s",
                    RD_KAFKAP_STR_PR(topic), partition,
                    RD_KAFKAP_STR_PR(err_msg));
                break;

        case RD_KAFKA_RESP_ERR_UNKNOWN_LEADER_EPOCH:
                rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                           "%.*s [%" PRId32 "]: ShareFetch failed: %s: %.*s",
                           RD_KAFKAP_STR_PR(topic), partition,
                           rd_kafka_err2name(err), RD_KAFKAP_STR_PR(err_msg));
                break;

        case RD_KAFKA_RESP_ERR_UNKNOWN:
                rd_rkb_log(rkb, LOG_WARNING, "SHAREFETCH",
                           "%.*s [%" PRId32 "]: ShareFetch failed: %s: %.*s",
                           RD_KAFKAP_STR_PR(topic), partition,
                           rd_kafka_err2name(err), RD_KAFKAP_STR_PR(err_msg));
                break;

        case RD_KAFKA_RESP_ERR_INVALID_MSG:
                rd_kafka_consumer_err(
                    rkb->rkb_rk->rk_cgrp->rkcg_q, rd_kafka_broker_id(rkb), err,
                    0, NULL, rktp, RD_KAFKA_OFFSET_INVALID,
                    "Encountered corrupt message when fetching "
                    "topic-partition %.*s-%" PRId32 ": %.*s",
                    RD_KAFKAP_STR_PR(topic), partition,
                    RD_KAFKAP_STR_PR(err_msg));
                break;

        default:
                rd_kafka_consumer_err(
                    rkb->rkb_rk->rk_cgrp->rkcg_q, rd_kafka_broker_id(rkb), err,
                    0, NULL, rktp, RD_KAFKA_OFFSET_INVALID,
                    "Unexpected error code %" PRId16
                    " (%s) while fetching from topic-partition "
                    "%.*s-%" PRId32 ": %.*s",
                    (int16_t)err, rd_kafka_err2name(err),
                    RD_KAFKAP_STR_PR(topic), partition,
                    RD_KAFKAP_STR_PR(err_msg));
                break;
        }
}


/**
 * @brief Parse a partition from ShareFetch response and build inflight_acks.
 *
 * Creates rd_kafka_share_ack_batches_t directly with per-offset tracking.
 * All offsets are initialized to ACQUIRED state; types will be updated
 * later when matching with actual messages (GAP for missing, REJECT for
 * errors).
 *
 * @param rkb Broker handle
 * @param topic Topic name
 * @param topic_id Topic UUID
 * @param rkt Topic handle (possibly NULL)
 * @param rkbuf Response buffer
 * @param request Request buffer
 * @param temp_appq Queue to forward filtered messages
 * @param batches_out Output: inflight acks batches for this partition
 *
 * @returns Error code or RD_KAFKA_RESP_ERR_NO_ERROR on success
 *
 * TODO KIP-932: Check if we can reduce the number of args in this method.
 * Can we remove the topic field from the args, since it is a derived value
 * from rkt and initialize a topic variable inside this function?
 */
static rd_kafka_resp_err_t rd_kafka_share_fetch_reply_handle_partition(
    rd_kafka_broker_t *rkb,
    const rd_kafkap_str_t *topic,
    rd_kafka_Uuid_t topic_id,
    rd_kafka_topic_t *rkt /*possibly NULL*/,
    rd_kafka_buf_t *rkbuf,
    rd_kafka_buf_t *request,
    rd_list_t *filtered_msgs,
    rd_kafka_share_ack_batches_t *batches_out,
    rd_list_t *request_ack_details) {

        int32_t PartitionId;
        int16_t PartitionFetchErrorCode;
        rd_kafkap_str_t PartitionFetchErrorStr =
            RD_KAFKAP_STR_INITIALIZER_EMPTY;
        int16_t AcknowledgementErrorCode;
        rd_kafkap_str_t AcknowledgementErrorStr =
            RD_KAFKAP_STR_INITIALIZER_EMPTY;
        rd_kafkap_CurrentLeader_t CurrentLeader;
        int32_t MessageSetSize;
        rd_kafka_toppar_t *rktp = NULL;
        struct rd_kafka_toppar_ver tver;
        rd_slice_t save_slice;
        const int log_decode_errors = LOG_ERR;
        rd_kafka_resp_err_t err     = RD_KAFKA_RESP_ERR_NO_ERROR;
        int32_t AcquiredRecordsArrayCnt;
        int64_t *FirstOffsets     = NULL;
        int64_t *LastOffsets      = NULL;
        int16_t *DeliveryCounts   = NULL;
        rd_kafka_q_t *temp_fetchq = rd_kafka_q_new(rkb->rkb_rk);
        int i;
        rd_bool_t is_sorted     = rd_true;
        int64_t prev_end_offset = -1, size, j;
        rd_kafka_share_ack_batch_entry_t *entry;
        rd_kafka_topic_partition_private_t *parpriv;
        char *topic_str;

        rd_kafka_buf_read_i32(rkbuf, &PartitionId);  // Partition
        rd_kafka_buf_read_i16(rkbuf,
                              &PartitionFetchErrorCode);  // PartitionFetchError
        rd_kafka_buf_read_str(rkbuf, &PartitionFetchErrorStr);  // ErrorString
        rd_kafka_buf_read_i16(
            rkbuf, &AcknowledgementErrorCode);  // AcknowledgementError
        rd_kafka_buf_read_str(
            rkbuf, &AcknowledgementErrorStr);  // AcknowledgementErrorString

        /* Set the AcknowledgementErrorCode on the matching ack batch
         * in request_ack_details, so the main thread can map
         * per-partition ack errors to commit_sync results /
         * acknowledgement callback. PartitionFetchErrorCode is for
         * fetch-level errors and is handled separately. The partition
         * may be present in the response but absent from
         * request_ack_details (e.g. fetch-only partitions from
         * toppars_to_add) — silently skip those.
         *
         * Conditional on _IN_PROGRESS preserves any deliberately
         * pre-set err on the batch (e.g. INVALID_SHARE_SESSION_EPOCH
         * from the epoch-0 strip path) — those partitions were never
         * actually sent to the broker, so the broker's
         * AcknowledgementErrorCode (typically NO_ERROR) is not the
         * authoritative result for them. */
        if (request_ack_details) {
                rd_kafka_share_ack_batches_t *batch =
                    rd_kafka_share_find_ack_batch_by_id(request_ack_details,
                                                        topic_id, PartitionId);
                if (batch &&
                    batch->rktpar->err == RD_KAFKA_RESP_ERR__IN_PROGRESS)
                        batch->rktpar->err = AcknowledgementErrorCode;
        }

        if (AcknowledgementErrorCode != RD_KAFKA_RESP_ERR_NO_ERROR) {
                rd_rkb_dbg(rkb, FETCH, "SHAREACK",
                           "ShareFetch response for %.*s [%" PRId32
                           "]: AcknowledgementError %" PRId16 " (%s)",
                           RD_KAFKAP_STR_PR(topic), PartitionId,
                           AcknowledgementErrorCode,
                           rd_kafka_err2str(AcknowledgementErrorCode));
        }

        rd_kafka_buf_read_CurrentLeader(rkbuf,
                                        &CurrentLeader);  // CurrentLeader

        /* Compact Records Array */
        rd_kafka_buf_read_arraycnt(rkbuf, &MessageSetSize, -1);

        if (unlikely(MessageSetSize < 0))
                rd_kafka_buf_parse_fail(
                    rkbuf,
                    "%.*s [%" PRId32 "]: invalid MessageSetSize %" PRId32,
                    RD_KAFKAP_STR_PR(topic), PartitionId, MessageSetSize);

        /* Look up topic+partition */
        if (likely(rkt != NULL)) {
                rd_kafka_topic_rdlock(rkt);
                rktp =
                    rd_kafka_toppar_get(rkt, PartitionId, 0 /*no ua-on-miss*/);
                rd_kafka_topic_rdunlock(rkt);
        }

        if (unlikely(!rkt || !rktp || PartitionFetchErrorCode)) {
                int64_t tmp_first, tmp_last;
                int16_t tmp_delivery;

                if (!rkt) {
                        /* TODO KIP-932: Recheck this branch once the
                         * topic-recreate session-bookkeeping bug is fixed
                         * (broker session may stop carrying old topic_ids
                         * that no longer match any local rkt). */
                        rd_rkb_dbg(rkb, TOPIC, "UNKTOPIC",
                                   "Received Fetch response (error %hu) for "
                                   "unknown topic %.*s [%" PRId32 "]: ignoring",
                                   PartitionFetchErrorCode,
                                   RD_KAFKAP_STR_PR(topic), PartitionId);
                } else if (!rktp) {
                        /* TODO KIP-932: Verify this handling against expected
                         * behavior. librdkafka requires rktp to route records;
                         * partitions with no local rktp are silently dropped.
                         */
                        rd_rkb_dbg(rkb, TOPIC, "UNKTOPIC",
                                   "Received Fetch response (error %hu) for "
                                   "unknown partition %.*s [%" PRId32
                                   "]: ignoring",
                                   PartitionFetchErrorCode,
                                   RD_KAFKAP_STR_PR(topic), PartitionId);
                } else {
                        rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                                   "%.*s [%" PRId32
                                   "]: per-partition fetch error %s",
                                   RD_KAFKAP_STR_PR(topic), PartitionId,
                                   rd_kafka_err2name(PartitionFetchErrorCode));
                        rd_kafka_share_fetch_reply_handle_partition_error(
                            rkb, rktp, topic, PartitionId,
                            PartitionFetchErrorCode, &PartitionFetchErrorStr);
                }

                rd_kafka_buf_skip(rkbuf, MessageSetSize);
                /* TODO KIP-932: Consider tracking total byte size of the
                 * AcquiredRecords array in the protocol to allow a single
                 * rd_kafka_buf_skip() here instead of per-entry parsing. */
                rd_kafka_buf_read_arraycnt(rkbuf, &AcquiredRecordsArrayCnt,
                                           -1);  // AcquiredRecordsArrayCnt
                for (i = 0; i < AcquiredRecordsArrayCnt; i++) {
                        rd_kafka_buf_read_i64(rkbuf,
                                              &tmp_first);        // FirstOffset
                        rd_kafka_buf_read_i64(rkbuf, &tmp_last);  // LastOffset
                        rd_kafka_buf_read_i16(rkbuf,
                                              &tmp_delivery);  // DeliveryCount
                        rd_kafka_buf_skip_tags(rkbuf);  // AcquiredRecords tags
                }
                /* No records to track for this partition. Leave
                 * batches_out->rktpar as NULL so the caller skips
                 * adding this batch to inflight_acks. */
                rd_kafka_buf_skip_tags(rkbuf);
                goto done;
        }

        tver.rktp = rktp;
        /* There is no versioning/barrier of the records/partitions in
         * share consumer case. */
        tver.version = 0;

        if (MessageSetSize > 0) {
                /**
                 * Parse MessageSet
                 */
                if (!rd_slice_narrow_relative(&rkbuf->rkbuf_reader, &save_slice,
                                              (size_t)MessageSetSize))
                        rd_kafka_buf_check_len(rkbuf, MessageSetSize);

                /*
                 * Parse messages
                 */
                err = rd_kafka_share_msgset_parse(rkbuf, rktp, NULL, &tver,
                                                  temp_fetchq);

                rd_slice_widen(&rkbuf->rkbuf_reader, &save_slice);
                /* Continue with next partition regardless of
                 * parse errors (which are partition-specific) */

                /**
                 * Only inner-record parsing errors (RD_KAFKA_RESP_ERR__BAD_MSG
                 * / RD_KAFKA_RESP_ERR__UNDERFLOW) propagate out of
                 * rd_kafka_share_msgset_parse for share consumers — per-batch
                 * codec / CRC / unsupported-MagicByte failures are handled
                 * inline by emitting per-offset RELEASE/REJECT ops and are
                 * swallowed by the v2 reader (msgset_reader.c). When a true
                 * parse error bubbles up the wire data is corrupt and we can no
                 * longer trust the buffer position or any per-batch metadata.
                 * Stop processing the rest of this ShareFetch response and
                 * propagate the error to the caller, which aborts the whole
                 * response handling.
                 */
                if (err)
                        goto done;
        }

        rd_kafka_buf_read_arraycnt(rkbuf, &AcquiredRecordsArrayCnt,
                                   -1);  // AcquiredRecordsArrayCnt
        rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                   "%.*s [%" PRId32 "] : AcquiredRecordsArrayCnt: %d",
                   RD_KAFKAP_STR_PR(topic), PartitionId,
                   AcquiredRecordsArrayCnt);

        /* Allocate and initialize the topic partition */
        topic_str = RD_KAFKAP_STR_DUP(topic);
        batches_out->rktpar =
            rd_kafka_topic_partition_new(topic_str, PartitionId);
        rd_free(topic_str);

        /* Allocate and fill the private structure */
        parpriv                       = rd_kafka_topic_partition_private_new();
        parpriv->rktp                 = rd_kafka_toppar_keep(rktp);
        parpriv->topic_id             = topic_id;
        batches_out->rktpar->_private = parpriv;

        /* Record the broker from which records were acquired so the
         * acknowledgement is sent back to the same broker. The wire
         * CurrentLeader hint is only set when the broker signals a
         * leader change, so we use the responding broker. */
        batches_out->response_leader_id              = rkb->rkb_nodeid;
        batches_out->response_acquired_offsets_count = 0;
        /* Pre-allocate capacity without re-initializing the list.
         * batches_out->entries was already initialized by
         * rd_kafka_share_ack_batches_new() with the proper
         * entry destructor. */
        if (AcquiredRecordsArrayCnt > 0)
                rd_list_grow(&batches_out->entries, AcquiredRecordsArrayCnt);

        if (AcquiredRecordsArrayCnt > 0) {
                FirstOffsets =
                    rd_malloc(sizeof(*FirstOffsets) * AcquiredRecordsArrayCnt);
                LastOffsets =
                    rd_malloc(sizeof(*LastOffsets) * AcquiredRecordsArrayCnt);
                DeliveryCounts = rd_malloc(sizeof(*DeliveryCounts) *
                                           AcquiredRecordsArrayCnt);

                /**
                 * TODO KIP-932: There could be an improvement where we
                 * segregate the records while reading the FirstOffsets and
                 * LastOffsets, so that we can avoid mallocs above and directly
                 * create the batches and fill the entries.
                 */
                for (i = 0; i < AcquiredRecordsArrayCnt; i++) {
                        rd_kafka_buf_read_i64(rkbuf, &FirstOffsets[i]);
                        rd_kafka_buf_read_i64(rkbuf, &LastOffsets[i]);
                        rd_kafka_buf_read_i16(rkbuf, &DeliveryCounts[i]);
                        rd_kafka_buf_skip_tags(rkbuf);

                        size = LastOffsets[i] - FirstOffsets[i] + 1;

                        rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                                   "%.*s [%" PRId32
                                   "]: Acquired Records from offset %" PRId64
                                   " to %" PRId64 ", DeliveryCount %" PRId16,
                                   RD_KAFKAP_STR_PR(topic), PartitionId,
                                   FirstOffsets[i], LastOffsets[i],
                                   DeliveryCounts[i]);

                        /* Track sortedness: entries must be non-overlapping
                         * and in ascending order by start_offset. */
                        if (is_sorted && FirstOffsets[i] <= prev_end_offset)
                                is_sorted = rd_false;
                        prev_end_offset = LastOffsets[i];

                        entry = rd_kafka_share_ack_batch_entry_new(
                            FirstOffsets[i], LastOffsets[i], (int32_t)size,
                            DeliveryCounts[i]);

                        /* Initialize all offsets to GAP; build_response_rko
                         * will set ACQUIRED/REJECT for offsets that have a
                         * message. */
                        for (j = 0; j < size; j++) {
                                entry->types[j] =
                                    RD_KAFKA_SHARE_INTERNAL_ACK_GAP;
                        }

                        rd_list_add(&batches_out->entries, entry);
                        batches_out->response_acquired_offsets_count +=
                            (int32_t)size;
                }

                /* Mark as sorted to enable binary search in rd_list_find(). */
                if (is_sorted)
                        batches_out->entries.rl_flags |= RD_LIST_F_SORTED;

                /* Filter and forward messages in acquired ranges */
                rd_kafka_share_filter_acquired_records_and_update_ack_type(
                    temp_fetchq, filtered_msgs, FirstOffsets, LastOffsets,
                    DeliveryCounts, AcquiredRecordsArrayCnt);
        } else {
                /* No acquired ranges: drop everything */
                rd_kafka_op_t *rko;
                while ((rko = rd_kafka_q_pop(temp_fetchq, RD_POLL_NOWAIT, 0)))
                        rd_kafka_op_destroy(rko);
        }

        rd_kafka_buf_skip_tags(rkbuf);  // Partition tags

        goto done;

err_parse:
        err = rkbuf->rkbuf_err;

done:
        RD_IF_FREE(FirstOffsets, rd_free);
        RD_IF_FREE(LastOffsets, rd_free);
        RD_IF_FREE(DeliveryCounts, rd_free);
        RD_IF_FREE(temp_fetchq, rd_kafka_q_destroy_owner);
        if (rktp)
                rd_kafka_toppar_destroy(rktp); /* from toppar_get() */
        return err;
}


/**
 * Parses and handles a ShareFetch reply.
 * Returns 0 on success or an error code on failure.
 *
 * TODO KIP-932: Change return type to proper error with message. See
 * `rd_kafka_error_t *`.
 */
static rd_kafka_resp_err_t
rd_kafka_share_fetch_reply_handle(rd_kafka_broker_t *rkb,
                                  rd_kafka_buf_t *rkbuf,
                                  rd_kafka_buf_t *request,
                                  rd_kafka_op_t **response_rko_out) {
        int32_t TopicArrayCnt;
        int i;
        const int log_decode_errors      = LOG_ERR;
        rd_kafka_topic_t *rkt            = NULL;
        int16_t ErrorCode                = RD_KAFKA_RESP_ERR_NO_ERROR;
        rd_kafkap_str_t ErrorStr         = RD_KAFKAP_STR_INITIALIZER_EMPTY;
        int32_t AcquisitionLockTimeoutMs = 0;
        rd_kafkap_NodeEndpoints_t NodeEndpoints;
        NodeEndpoints.NodeEndpoints   = NULL;
        NodeEndpoints.NodeEndpointCnt = 0;
        rd_list_t *filtered_msgs      = NULL;
        rd_list_t *inflight_acks      = NULL;
        rd_kafka_op_t *rko_orig       = request->rkbuf_opaque;
        rd_kafka_op_t *response_rko   = NULL;
        rd_kafka_resp_err_t err       = RD_KAFKA_RESP_ERR_NO_ERROR;
        rd_kafka_op_t *fetch_size_rko;
        int fetch_size_idx;
        int64_t total_fetch_size_bytes = 0;

        rd_kafka_buf_read_throttle_time(rkbuf);

        rd_kafka_buf_read_i16(rkbuf, &ErrorCode);
        rd_kafka_buf_read_str(rkbuf, &ErrorStr);

        if (ErrorCode) {
                rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                           "ShareFetch response error %s: '%.*s'",
                           rd_kafka_err2name(ErrorCode),
                           RD_KAFKAP_STR_PR(&ErrorStr));
                return ErrorCode;
        }

        /* Count this successful ShareFetch response for
         * consumer.share.fetch.manager.fetch.{total,rate}.
         * Fires only after top level error handling.
         *
         * TODO KIP-932: Revisit this sampling before GA. It fires here,
         * before the message set is parsed (rd_kafka_share_msgset_parse in
         * the partition loop below). If that parse fails with
         * RD_KAFKA_RESP_ERR__BAD_MSG / __UNDERFLOW the caller drops the
         * whole response, yet fetch.{total,rate} and fetch.latency have
         * already been counted here. */
        rd_atomic64_add(&rkb->rkb_rk->rk_telemetry.share_fetch_total, 1);

        /* rkbuf_ts_sent is already the request RTT here */
        rd_avg_add(
            &rkb->rkb_telemetry.rd_avg_current.rkb_avg_share_fetch_latency,
            request->rkbuf_ts_sent);

        rd_kafka_buf_read_i32(rkbuf, &AcquisitionLockTimeoutMs);

        rd_kafka_buf_read_arraycnt(rkbuf, &TopicArrayCnt, RD_KAFKAP_TOPICS_MAX);

        filtered_msgs = rd_list_new(0, NULL);
        inflight_acks = rd_list_new(0, rd_kafka_share_ack_batches_destroy_free);

        for (i = 0; i < TopicArrayCnt; i++) {
                rd_kafkap_str_t topic    = RD_ZERO_INIT;
                rd_kafka_Uuid_t topic_id = RD_KAFKA_UUID_ZERO;
                int32_t PartitionArrayCnt;
                int j;

                rd_kafka_buf_read_uuid(rkbuf, &topic_id);
                rkt = rd_kafka_topic_find_by_topic_id(rkb->rkb_rk, topic_id);
                if (rkt)
                        topic = *rkt->rkt_topic;

                rd_kafka_buf_read_arraycnt(rkbuf, &PartitionArrayCnt,
                                           RD_KAFKAP_PARTITIONS_MAX);

                for (j = 0; j < PartitionArrayCnt; j++) {
                        rd_kafka_share_ack_batches_t *batches =
                            rd_kafka_share_ack_batches_new_empty();

                        err = rd_kafka_share_fetch_reply_handle_partition(
                            rkb, &topic, topic_id, rkt, rkbuf, request,
                            filtered_msgs, batches,
                            rko_orig->rko_u.share_fetch.ack_details);

                        /*
                         * Only inner-record parsing errors
                         * (RD_KAFKA_RESP_ERR__BAD_MSG /
                         * RD_KAFKA_RESP_ERR__UNDERFLOW) reach this point —
                         * per-batch CRC / decompression / MagicByte failures
                         * are handled inline inside
                         * rd_kafka_share_msgset_parse by emitting per-offset
                         * RELEASE/REJECT ops and are swallowed, and
                         * per-partition broker errors are handled by
                         * rd_kafka_share_fetch_reply_handle_partition_error
                         * before MessageSet parsing begins. A parsing error
                         * means the wire data is corrupt and the buffer
                         * position can no longer be trusted for subsequent
                         * partitions, so abort the whole response.
                         */
                        if (err) {
                                rd_kafka_share_ack_batches_destroy(batches);
                                goto done;
                        }

                        /* Skip unknown topics - don't add to inflight_acks */
                        if (batches->rktpar == NULL) {
                                rd_kafka_share_ack_batches_destroy(batches);
                                continue;
                        }

                        if (rd_list_cnt(&batches->entries) > 0) {
                                rd_list_add(inflight_acks, batches);
                        } else {
                                rd_kafka_share_ack_batches_destroy(batches);
                        }
                }

                if (rkt) {
                        rd_kafka_topic_destroy0(rkt);
                        rkt = NULL;
                }
                /* Topic Tags */
                rd_kafka_buf_skip_tags(rkbuf);
        }

        rd_kafka_buf_read_NodeEndpoints(rkbuf, &NodeEndpoints);

        /* Sum per-record wire bytes across acquired records for
         * consumer.share.fetch.manager.fetch.size.{avg,max} and
         * .bytes.consumed.{total,rate}. */
        RD_LIST_FOREACH(fetch_size_rko, filtered_msgs, fetch_size_idx) {
                if (fetch_size_rko->rko_type == RD_KAFKA_OP_FETCH) {
                        rd_kafka_msg_t *rkm = &fetch_size_rko->rko_u.fetch.rkm;
                        total_fetch_size_bytes +=
                            (int64_t)rkm->rkm_u.consumer.wire_size;
                }
        }
        /* Update bytes per fetch metrics */
        rd_avg_add(&rkb->rkb_telemetry.rd_avg_current.rkb_avg_share_fetch_size,
                   total_fetch_size_bytes);

        /* Update total bytes consumed */
        rd_atomic64_add(&rkb->rkb_rk->rk_telemetry.share_bytes_consumed_total,
                        total_fetch_size_bytes);

        /* Build response rko with messages and inflight_acks */
        response_rko = rd_kafka_share_build_response_rko(rkb, filtered_msgs,
                                                         inflight_acks);

        rd_list_destroy(inflight_acks);
        inflight_acks = NULL;
        rd_list_destroy(filtered_msgs);
        filtered_msgs = NULL;

        /* Top level tags */
        rd_kafka_buf_skip_tags(rkbuf);

        /* Return response_rko to the caller instead of enqueueing here.
         * The caller enqueues it on rkcg_q AFTER sending the reply to
         * rk_ops, ensuring the main thread processes the reply (and
         * resets share_fetch_more_records) before the app thread can
         * wake up, poll again, and enqueue a new FANOUT. */
        *response_rko_out = response_rko;

        /* Signal main thread whether records were fetched */
        if (rko_orig)
                rko_orig->rko_u.share_fetch.records_fetched =
                    response_rko ? rd_true : rd_false;

        RD_IF_FREE(NodeEndpoints.NodeEndpoints, rd_free);
        RD_IF_FREE(rkt, rd_kafka_topic_destroy0);
        return RD_KAFKA_RESP_ERR_NO_ERROR;

err_parse:
        err = rkbuf->rkbuf_err;

done:
        /* Lists are NULLed on the success path after their inline destroy;
         * here they're only non-NULL on the error path. filtered_msgs uses a
         * NULL destructor, so any ops accumulated from earlier partitions
         * before err_parse fired must be destroyed explicitly. */
        RD_IF_FREE(inflight_acks, rd_list_destroy);
        if (filtered_msgs) {
                rd_kafka_op_t *rko;
                int li;
                RD_LIST_FOREACH(rko, filtered_msgs, li)
                rd_kafka_op_destroy(rko);
                rd_list_destroy(filtered_msgs);
        }

        RD_IF_FREE(response_rko, rd_kafka_op_destroy);
        *response_rko_out = NULL;

        if (rkt)
                rd_kafka_topic_destroy0(rkt);
        rd_rkb_dbg(rkb, MSG, "BADMSG", "Bad message (ShareFetch v%d): %s",
                   (int)request->rkbuf_reqhdr.ApiVersion,
                   rd_kafka_err2str(err));
        return err;
}


/**
 * @brief Reset the share fetch session for a broker.
 *
 * Called when the broker returns SHARE_SESSION_NOT_FOUND,
 * INVALID_SHARE_SESSION_EPOCH, or SHARE_SESSION_LIMIT_REACHED,
 * indicating the session is lost or cannot be created.
 * Resets the epoch to 0 and moves all toppars_in_session back
 * to toppars_to_add so the next request re-establishes the
 * full session.
 *
 * @param rkb Broker whose session is being reset.
 *
 * @locality broker thread
 */
static void rd_kafka_broker_session_reset(rd_kafka_broker_t *rkb) {
        rd_kafka_toppar_t *rktp;
        int i;

        rd_rkb_dbg(
            rkb, FETCH, "SHARESESSION",
            "Resetting share session: epoch %" PRId32
            " -> 0, "
            "moving %d toppars_in_session to toppars_to_add",
            rkb->rkb_share_fetch_session.epoch,
            rd_list_cnt(rkb->rkb_share_fetch_session.toppars_in_session));

        rkb->rkb_share_fetch_session.epoch = 0;

        /* Remove toppars_to_forget from toppars_in_session — these
         * were pending removal and should not be re-added to the
         * new session. */
        if (rkb->rkb_share_fetch_session.toppars_to_forget) {
                rd_kafka_toppar_t *forget_rktp;

                RD_LIST_FOREACH(forget_rktp,
                                rkb->rkb_share_fetch_session.toppars_to_forget,
                                i) {
                        rktp = rd_list_remove(
                            rkb->rkb_share_fetch_session.toppars_in_session,
                            forget_rktp);
                        if (rktp)
                                rd_kafka_toppar_destroy(rktp);
                }

                rd_list_destroy(rkb->rkb_share_fetch_session.toppars_to_forget);
                rkb->rkb_share_fetch_session.toppars_to_forget = NULL;
        }

        /* Move remaining toppars_in_session to toppars_to_add so they
         * get sent as new additions in the next request (epoch 0). */
        if (!rkb->rkb_share_fetch_session.toppars_to_add) {
                rkb->rkb_share_fetch_session.toppars_to_add =
                    rkb->rkb_share_fetch_session.toppars_in_session;
                rkb->rkb_share_fetch_session.toppars_in_session =
                    rd_list_new(0, rd_kafka_toppar_destroy_free);
        } else {
                while ((rktp = rd_list_pop(
                            rkb->rkb_share_fetch_session.toppars_in_session))) {
                        if (!rd_list_find(
                                rkb->rkb_share_fetch_session.toppars_to_add,
                                rktp, rd_list_cmp_ptr))
                                rd_list_add(
                                    rkb->rkb_share_fetch_session.toppars_to_add,
                                    rktp);
                        else
                                rd_kafka_toppar_destroy(rktp);
                }
        }
}

static void rd_kafka_broker_session_update_epoch(rd_kafka_broker_t *rkb) {
        int32_t prev_epoch = rkb->rkb_share_fetch_session.epoch;
        if (prev_epoch == -1) {
                rd_rkb_dbg(
                    rkb, FETCH, "SHARESESSION",
                    "Not updating next epoch for -1 as it should be -1 again.");
                return;
        }
        if (prev_epoch == INT32_MAX)
                rkb->rkb_share_fetch_session.epoch = 1;
        else
                rkb->rkb_share_fetch_session.epoch++;
        rd_rkb_dbg(rkb, FETCH, "SHARESESSION",
                   "share-fetch session epoch %" PRId32 " -> %" PRId32
                   " (wrap=%s)",
                   prev_epoch, rkb->rkb_share_fetch_session.epoch,
                   prev_epoch == INT32_MAX ? "yes" : "no");
}

static void rd_kafka_broker_session_add_partition_to_toppars_in_session(
    rd_kafka_broker_t *rkb,
    rd_kafka_toppar_t *rktp) {
        if (rd_list_find(rkb->rkb_share_fetch_session.toppars_in_session, rktp,
                         rd_list_cmp_ptr)) {
                rd_rkb_dbg(rkb, FETCH, "SHARESESSION",
                           "%s [%" PRId32 "]: already in ShareFetch session",
                           rktp->rktp_rkt->rkt_topic->str,
                           rktp->rktp_partition);
                return;
        }
        rd_rkb_dbg(rkb, FETCH, "SHARESESSION",
                   "%s [%" PRId32 "]: adding to ShareFetch session",
                   rktp->rktp_rkt->rkt_topic->str, rktp->rktp_partition);
        rd_kafka_toppar_keep(rktp);
        rd_list_add(rkb->rkb_share_fetch_session.toppars_in_session, rktp);
}

void rd_kafka_broker_session_remove_partition_from_toppars_in_session(
    rd_kafka_broker_t *rkb,
    rd_kafka_toppar_t *rktp) {
        rd_kafka_toppar_t *removed_rktp;
        removed_rktp = rd_list_remove(
            rkb->rkb_share_fetch_session.toppars_in_session, rktp);
        if (removed_rktp) {
                rd_kafka_toppar_destroy(removed_rktp);
                rd_rkb_dbg(rkb, FETCH, "SHARESESSION",
                           "%s [%" PRId32 "]: removed from ShareFetch session",
                           rktp->rktp_rkt->rkt_topic->str,
                           rktp->rktp_partition);
        } else {
                rd_rkb_dbg(rkb, FETCH, "SHARESESSION",
                           "%s [%" PRId32 "]: not found in ShareFetch session",
                           rktp->rktp_rkt->rkt_topic->str,
                           rktp->rktp_partition);
        }
}

static void
rd_kafka_broker_session_update_toppars_in_session(rd_kafka_broker_t *rkb,
                                                  rd_kafka_toppar_t *rktp,
                                                  rd_bool_t add) {
        if (add)
                rd_kafka_broker_session_add_partition_to_toppars_in_session(
                    rkb, rktp);
        else
                rd_kafka_broker_session_remove_partition_from_toppars_in_session(
                    rkb, rktp);
}

static void rd_kafka_broker_session_update_toppars_list(
    rd_kafka_broker_t *rkb,
    rd_list_t **request_toppars_ptr,
    rd_list_t **toppars_to_remove_from_ptr,
    rd_bool_t add) {
        size_t i;
        rd_kafka_toppar_t *rktp, *removed_rktp;
        rd_list_t *request_toppars        = *request_toppars_ptr;
        rd_list_t *toppars_to_remove_from = *toppars_to_remove_from_ptr;

        if (request_toppars == NULL || rd_list_cnt(request_toppars) == 0)
                return;

        rd_rkb_dbg(
            rkb, FETCH, "SHARESESSION",
            "%d toppars being %s the session:", rd_list_cnt(request_toppars),
            add ? "added to" : "removed from");

        RD_LIST_FOREACH(rktp, request_toppars, i) {
                rd_kafka_broker_session_update_toppars_in_session(rkb, rktp,
                                                                  add);
                if (toppars_to_remove_from) {
                        removed_rktp =
                            rd_list_remove(toppars_to_remove_from, rktp);
                        if (removed_rktp) {
                                rd_kafka_toppar_destroy(
                                    removed_rktp); /* from partitions list */
                                if (rd_list_empty(toppars_to_remove_from)) {
                                        rd_list_destroy(toppars_to_remove_from);
                                        toppars_to_remove_from      = NULL;
                                        *toppars_to_remove_from_ptr = NULL;
                                }
                        }
                }
        }
        rd_list_destroy(request_toppars);
        *request_toppars_ptr = NULL;
}

static void
rd_kafka_broker_session_update_added_partitions(rd_kafka_broker_t *rkb) {
        rd_kafka_broker_session_update_toppars_list(
            rkb, &rkb->rkb_share_fetch_session.adding_toppars,
            &rkb->rkb_share_fetch_session.toppars_to_add, rd_true);
}

static void
rd_kafka_broker_session_update_removed_partitions(rd_kafka_broker_t *rkb) {
        rd_kafka_broker_session_update_toppars_list(
            rkb, &rkb->rkb_share_fetch_session.forgetting_toppars,
            &rkb->rkb_share_fetch_session.toppars_to_forget, rd_false);
}

static void rd_kafka_broker_session_update_partitions(rd_kafka_broker_t *rkb) {
        rd_rkb_dbg(
            rkb, FETCH, "SHARESESSION",
            "applying session updates: adding_toppars=%d "
            "forgetting_toppars=%d toppars_in_session=%d epoch=%" PRId32,
            rkb->rkb_share_fetch_session.adding_toppars
                ? rd_list_cnt(rkb->rkb_share_fetch_session.adding_toppars)
                : 0,
            rkb->rkb_share_fetch_session.forgetting_toppars
                ? rd_list_cnt(rkb->rkb_share_fetch_session.forgetting_toppars)
                : 0,
            rkb->rkb_share_fetch_session.toppars_in_session
                ? rd_list_cnt(rkb->rkb_share_fetch_session.toppars_in_session)
                : 0,
            rkb->rkb_share_fetch_session.epoch);
        rd_kafka_broker_session_update_added_partitions(rkb);
        rd_kafka_broker_session_update_removed_partitions(rkb);
}


/**
 * Update ShareFetch session state after a Fetch or ShareFetch response.
 * TODO KIP-932: Improve efficiency of this function.
 */
static void rd_kafka_broker_session_update(rd_kafka_broker_t *rkb) {
        rd_kafka_broker_session_update_epoch(rkb);
        rd_kafka_broker_session_update_partitions(rkb);
}

/**
 * @brief Whether \p err is a per-partition ShareAcknowledge error
 *        whose CurrentLeader hint should trigger an inline metadata
 *        update.
 */
static rd_bool_t
rd_kafka_share_ack_err_is_leader_change(rd_kafka_resp_err_t err) {
        switch (err) {
        case RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER:
        case RD_KAFKA_RESP_ERR_FENCED_LEADER_EPOCH:
        case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART:
        case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_ID:
                return rd_true;
        default:
                return rd_false;
        }
}

/**
 * @brief Parse a ShareAcknowledge response.
 *
 * ShareAcknowledge response contains per-partition error codes for
 * acknowledgement results. Returns the top-level error code and sets
 * the err field on each matching batch in \p ack_details.
 *
 * TODO KIP-932: Consider using rd_kafka_error_t instead of
 * rd_kafka_resp_err_t for the per-partition result and
 * acknowledgement callback.
 *
 * @param rkb Broker handle.
 * @param rkbuf Response buffer.
 * @param request Original request buffer.
 * @param ack_details List of acknowledgement batches sent in the
 *                    request. Each matched batch's rktpar->err is
 *                    updated with the partition-level error code
 *                    from the response.
 *
 * @returns Top-level error code.
 * @locality broker thread
 */
static rd_kafka_resp_err_t
rd_kafka_share_acknowledge_reply_handle(rd_kafka_broker_t *rkb,
                                        rd_kafka_buf_t *rkbuf,
                                        rd_kafka_buf_t *request,
                                        rd_list_t *ack_details) {
        int32_t TopicArrayCnt;
        int i;
        const int log_decode_errors = LOG_ERR;
        int16_t ErrorCode           = RD_KAFKA_RESP_ERR_NO_ERROR;
        rd_kafkap_str_t ErrorStr    = RD_KAFKAP_STR_INITIALIZER_EMPTY;
        rd_kafkap_NodeEndpoints_t NodeEndpoints;
        rd_list_t *leader_changes     = NULL;
        NodeEndpoints.NodeEndpoints   = NULL;
        NodeEndpoints.NodeEndpointCnt = 0;

        rd_kafka_buf_read_throttle_time(rkbuf);

        rd_kafka_buf_read_i16(rkbuf, &ErrorCode);
        rd_kafka_buf_read_str(rkbuf, &ErrorStr);

        if (ErrorCode) {
                rd_rkb_dbg(rkb, FETCH, "SHAREACK",
                           "ShareAcknowledge response error %s: '%.*s'",
                           rd_kafka_err2name(ErrorCode),
                           RD_KAFKAP_STR_PR(&ErrorStr));
                return ErrorCode;
        }

        rd_kafka_buf_read_arraycnt(rkbuf, &TopicArrayCnt, RD_KAFKAP_TOPICS_MAX);

        for (i = 0; i < TopicArrayCnt; i++) {
                rd_kafka_Uuid_t topic_id = RD_KAFKA_UUID_ZERO;
                int32_t PartitionArrayCnt;
                int j;

                rd_kafka_buf_read_uuid(rkbuf, &topic_id);

                rd_kafka_buf_read_arraycnt(rkbuf, &PartitionArrayCnt,
                                           RD_KAFKAP_PARTITIONS_MAX);

                for (j = 0; j < PartitionArrayCnt; j++) {
                        int32_t Partition;
                        int16_t PartErrorCode;
                        rd_kafkap_str_t PartErrorStr;
                        rd_kafkap_CurrentLeader_t CurrentLeader;
                        rd_kafka_share_ack_batches_t *batch;
                        rd_kafkap_share_leader_change_t *lc;

                        rd_kafka_buf_read_i32(rkbuf, &Partition);
                        rd_kafka_buf_read_i16(rkbuf, &PartErrorCode);
                        rd_kafka_buf_read_str(rkbuf, &PartErrorStr);

                        /* CurrentLeader */
                        rd_kafka_buf_read_CurrentLeader(rkbuf, &CurrentLeader);

                        batch = rd_kafka_share_find_ack_batch_by_id(
                            ack_details, topic_id, Partition);
                        if (batch) {
                                /* Conditional on _IN_PROGRESS as a
                                 * defensive safety net — the broker's
                                 * per-partition PartErrorCode is the
                                 * authoritative result for partitions
                                 * actually sent in the request. */
                                if (batch->rktpar->err ==
                                    RD_KAFKA_RESP_ERR__IN_PROGRESS)
                                        batch->rktpar->err = PartErrorCode;
                        } else {
                                rd_rkb_log(
                                    rkb, LOG_ERR, "SHAREACK",
                                    "Invalid partition %" PRId32
                                    " received in ShareAcknowledge response",
                                    Partition);
                        }

                        if (PartErrorCode) {
                                /* TODO KIP-932: write test cases for each
                                 * per-partition ShareAcknowledge error code
                                 * once the mock cluster exposes a
                                 * per-partition error-injection API for
                                 * ShareAcknowledge responses. Today only
                                 * NOT_LEADER_OR_FOLLOWER (via
                                 * rd_kafka_mock_partition_set_leader) is
                                 * deterministically reachable; the other
                                 * leader-change errors
                                 * (FENCED_LEADER_EPOCH,
                                 * UNKNOWN_TOPIC_OR_PART,
                                 * UNKNOWN_TOPIC_ID),
                                 * INVALID_RECORD_STATE,
                                 * INVALID_REQUEST, KAFKA_STORAGE_ERROR
                                 * and the inline-leader-update path have
                                 * no deterministic mock trigger. */
                                rd_rkb_dbg(rkb, FETCH, "SHAREACK",
                                           "ShareAcknowledge partition %" PRId32
                                           " error %s: '%.*s'",
                                           Partition,
                                           rd_kafka_err2name(PartErrorCode),
                                           RD_KAFKAP_STR_PR(&PartErrorStr));

                                if (rd_kafka_share_ack_err_is_leader_change(
                                        PartErrorCode) &&
                                    CurrentLeader.LeaderId != -1 &&
                                    CurrentLeader.LeaderEpoch != -1) {
                                        if (!leader_changes)
                                                leader_changes =
                                                    rd_list_new(0, rd_free);
                                        lc = rd_calloc(1, sizeof(*lc));
                                        lc->topic_id       = topic_id;
                                        lc->partition      = Partition;
                                        lc->current_leader = CurrentLeader;
                                        rd_list_add(leader_changes, lc);
                                }
                        }

                        /* Partition tags */
                        rd_kafka_buf_skip_tags(rkbuf);
                }

                /* Topic tags */
                rd_kafka_buf_skip_tags(rkbuf);
        }

        rd_kafka_buf_read_NodeEndpoints(rkbuf, &NodeEndpoints);

        /* Top level tags */
        rd_kafka_buf_skip_tags(rkbuf);

        rd_kafkap_share_leader_changes_apply(rkb, leader_changes,
                                             &NodeEndpoints);

        RD_IF_FREE(leader_changes, rd_list_destroy);
        RD_IF_FREE(NodeEndpoints.NodeEndpoints, rd_free);
        return RD_KAFKA_RESP_ERR_NO_ERROR;

err_parse:
        RD_IF_FREE(leader_changes, rd_list_destroy);
        RD_IF_FREE(NodeEndpoints.NodeEndpoints, rd_free);
        rd_rkb_dbg(rkb, MSG, "BADMSG",
                   "Bad ShareAcknowledge response (v%d): parse error",
                   (int)request->rkbuf_reqhdr.ApiVersion);
        return rkbuf->rkbuf_err;
}


/**
 * @brief ShareAcknowledge response handling callback.
 *
 * @locality broker thread (or any thread if err == __DESTROY).
 */
static void rd_kafka_broker_share_acknowledge_reply(rd_kafka_t *rk,
                                                    rd_kafka_broker_t *rkb,
                                                    rd_kafka_resp_err_t err,
                                                    rd_kafka_buf_t *reply,
                                                    rd_kafka_buf_t *request,
                                                    void *opaque) {
        rd_kafka_op_t *rko_orig = opaque;

        /* Parse and handle the response (unless the request errored).
         * The parser writes per-partition err on matching batches in
         * ack_details (only on batches still at the _IN_PROGRESS
         * sentinel as a defensive safety net). DESTROY case falls
         * through here and is handled by the generic top-level error
         * path below.
         *
         * If the parser ran and succeeded (err remains 0), convert
         * any batch still at _IN_PROGRESS to INVALID_RECORD_STATE —
         * those partitions were sent in the request but missing from
         * the response.
         *
         * If the parser was skipped or failed (err != 0), leave
         * batches at _IN_PROGRESS so the helper at the end can
         * propagate the top-level err to them. */
        if (!err && reply) {
                err = rd_kafka_share_acknowledge_reply_handle(
                    rkb, reply, request,
                    rko_orig->rko_u.share_fetch.ack_details);
                if (!err && rko_orig->rko_u.share_fetch.ack_details) {
                        rd_kafka_share_ack_batches_t *batch;
                        int i;
                        RD_LIST_FOREACH(
                            batch, rko_orig->rko_u.share_fetch.ack_details, i) {
                                if (batch->rktpar->err ==
                                    RD_KAFKA_RESP_ERR__IN_PROGRESS)
                                        batch->rktpar->err =
                                            RD_KAFKA_RESP_ERR_INVALID_RECORD_STATE;
                        }
                }
        }

        rd_kafka_broker_session_update(rkb);

        if (unlikely(err)) {
                rd_rkb_log(rkb, LOG_INFO, "SHAREACK",
                           "ShareAcknowledge reply error: %s",
                           rd_kafka_err2str(err));
                switch (err) {
                case RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND:
                case RD_KAFKA_RESP_ERR_INVALID_SHARE_SESSION_EPOCH:
                case RD_KAFKA_RESP_ERR__TRANSPORT:
                case RD_KAFKA_RESP_ERR__TIMED_OUT:
                        /* __TRANSPORT means connection is already dead.
                         * On __TIMED_OUT the connection is torn down by the
                         * request-timeout scan (socket.max.fails is forced to
                         * 1 for share consumers and cannot be changed) and the
                         * broker reconnects via the share-serve persistent
                         * connection driver; here we only reset the session so
                         * it re-establishes at epoch 0. */
                        rd_kafka_broker_session_reset(rkb);
                        break;

                case RD_KAFKA_RESP_ERR__BAD_MSG:
                case RD_KAFKA_RESP_ERR__UNDERFLOW:
                        /* Wire-level parse failure: response envelope or
                         * an inner MessageSet/record was malformed or
                         * truncated. Indicates broker bug, on-the-wire
                         * corruption, or version mismatch — log loudly so
                         * the user notices, since the LOG_INFO top-level
                         * log can be easy to miss in production output. */
                        rd_rkb_log(
                            rkb, LOG_ERR, "SHAREACK",
                            "ShareAcknowledge response parse failure: %s "
                            "(ApiVersion %hd) — broker bug, wire "
                            "corruption, or version mismatch; "
                            "this response is being dropped",
                            rd_kafka_err2str(err),
                            request->rkbuf_reqhdr.ApiVersion);
                        break;

                default:
                        /* No retry for ShareAcknowledge RPC-level
                         * errors. The error semantics (partition
                         * moved, session state lost, etc.) make a
                         * blind retry unlikely to succeed and risk
                         * duplicating side effects. */
                        break;
                }
        }

        if (rko_orig->rko_u.share_fetch.should_leave)
                rd_kafka_broker_share_fetch_session_clear(rkb);

        /* ack_details is owned by the op and freed by the op destructor
         * after the main thread has processed the reply. */
        rd_kafka_share_fetch_op_reply_and_update_ack_details_with_err(rko_orig,
                                                                      err);
}


/**
 * @broker ShareFetchResponse handling.
 *
 * @locality broker thread  (or any thread if err == __DESTROY).
 */
static void rd_kafka_broker_share_fetch_reply(rd_kafka_t *rk,
                                              rd_kafka_broker_t *rkb,
                                              rd_kafka_resp_err_t err,
                                              rd_kafka_buf_t *reply,
                                              rd_kafka_buf_t *request,
                                              void *opaque) {

        rd_kafka_op_t *rko_orig     = opaque;
        rd_kafka_op_t *response_rko = NULL;

        /* Parse the response only if the network/broker layer didn't
         * report an error. If err is set (e.g. __TRANSPORT,
         * __TIMED_OUT, __DESTROY), the reply buffer is unusable so
         * we skip parsing. The parser writes per-partition err on
         * matching batches in ack_details (only on batches still at
         * the _IN_PROGRESS sentinel, so any deliberately pre-set
         * value such as INVALID_SHARE_SESSION_EPOCH is preserved).
         * The DESTROY/network error case falls through to the
         * generic top-level error path below.
         *
         * If the parser ran and succeeded (err remains 0), convert
         * any batch still at _IN_PROGRESS to INVALID_RECORD_STATE —
         * those partitions were sent in the request but missing from
         * the response.
         *
         * If the parser was skipped or failed (err != 0), leave
         * batches at _IN_PROGRESS so the helper at the end can
         * propagate the top-level err to them. */
        if (!err && reply) {
                err = rd_kafka_share_fetch_reply_handle(rkb, reply, request,
                                                        &response_rko);
                if (!err && rko_orig->rko_u.share_fetch.ack_details) {
                        rd_kafka_share_ack_batches_t *batch;
                        int i;
                        RD_LIST_FOREACH(
                            batch, rko_orig->rko_u.share_fetch.ack_details, i) {
                                if (batch->rktpar->err ==
                                    RD_KAFKA_RESP_ERR__IN_PROGRESS)
                                        batch->rktpar->err =
                                            RD_KAFKA_RESP_ERR_INVALID_RECORD_STATE;
                        }
                }
        }

        rd_kafka_broker_session_update(rkb);

        if (unlikely(err)) {
                rd_rkb_log(rkb, LOG_INFO, "SHAREFETCH",
                           "ShareFetch reply error: %s", rd_kafka_err2str(err));
                switch (err) {
                case RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND:
                case RD_KAFKA_RESP_ERR_INVALID_SHARE_SESSION_EPOCH:
                case RD_KAFKA_RESP_ERR_SHARE_SESSION_LIMIT_REACHED:
                case RD_KAFKA_RESP_ERR__TRANSPORT:
                case RD_KAFKA_RESP_ERR__TIMED_OUT:
                        /* Session is invalid, lost, cannot be created,
                         * or connection/request failed.
                         * Reset session state so the next request
                         * re-establishes a new session (epoch 0).
                         * __TRANSPORT means connection is already dead.
                         * On __TIMED_OUT the connection is torn down by the
                         * request-timeout scan (socket.max.fails is forced to
                         * 1 for share consumers and cannot be changed) and the
                         * broker reconnects via the share-serve persistent
                         * connection driver. */
                        rd_kafka_broker_session_reset(rkb);
                        break;

                case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_ID: {
                        char tmp[128];
                        rd_snprintf(tmp, sizeof(tmp), "ShareFetch failed: %s",
                                    rd_kafka_err2str(err));
                        rd_kafka_metadata_refresh_known_topics(
                            rkb->rkb_rk, NULL, rd_false /*!force*/, tmp);
                        break;
                }

                case RD_KAFKA_RESP_ERR__BAD_MSG:
                case RD_KAFKA_RESP_ERR__UNDERFLOW:
                        /* Wire-level parse failure: response envelope or
                         * an inner MessageSet/record was malformed or
                         * truncated. Indicates broker bug, on-the-wire
                         * corruption, or version mismatch — log loudly so
                         * the user notices, since the LOG_INFO top-level
                         * log can be easy to miss in production output. */
                        rd_rkb_log(rkb, LOG_ERR, "SHAREFETCH",
                                   "ShareFetch response parse failure: %s "
                                   "(ApiVersion %hd) — broker bug, wire "
                                   "corruption, or version mismatch; "
                                   "this response is being dropped",
                                   rd_kafka_err2str(err),
                                   request->rkbuf_reqhdr.ApiVersion);
                        break;

                default:
                        /* No error-specific handling at the request
                         * level. Non-session top-level errors are
                         * treated as transient — the main thread
                         * retries by selecting another broker. */
                        break;
                }

                /* There is no retry for ShareFetch RPC at the broker
                 * thread level. */
        }

        /* ack_details is owned by the op and freed by the op destructor
         * after the main thread has processed the reply. */
        rd_kafka_share_fetch_op_reply_and_update_ack_details_with_err(rko_orig,
                                                                      err);

        /* Enqueue the response for the app thread AFTER sending the
         * reply to the main thread.  This ensures the main thread
         * processes the reply (resetting share_fetch_more_records)
         * before the app thread wakes up and enqueues a new FANOUT. */
        if (response_rko)
                rd_kafka_q_enq(rkb->rkb_rk->rk_cgrp->rkcg_q, response_rko);
}

/**
 * @broker FetchResponse handling.
 *
 * @locality broker thread  (or any thread if err == __DESTROY).
 */
static void rd_kafka_broker_fetch_reply(rd_kafka_t *rk,
                                        rd_kafka_broker_t *rkb,
                                        rd_kafka_resp_err_t err,
                                        rd_kafka_buf_t *reply,
                                        rd_kafka_buf_t *request,
                                        void *opaque) {

        if (err == RD_KAFKA_RESP_ERR__DESTROY)
                return; /* Terminating */

        rd_kafka_assert(rkb->rkb_rk, rkb->rkb_fetching > 0);
        rkb->rkb_fetching = 0;

        /* Parse and handle the messages (unless the request errored) */
        if (!err && reply)
                err = rd_kafka_fetch_reply_handle(rkb, reply, request);

        if (unlikely(err)) {
                char tmp[128];

                rd_rkb_dbg(rkb, MSG, "FETCH", "Fetch reply: %s",
                           rd_kafka_err2str(err));
                switch (err) {
                case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART:
                case RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE:
                case RD_KAFKA_RESP_ERR_NOT_LEADER_FOR_PARTITION:
                case RD_KAFKA_RESP_ERR_BROKER_NOT_AVAILABLE:
                case RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE:
                case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_ID:
                        /* Request metadata information update */
                        rd_snprintf(tmp, sizeof(tmp), "FetchRequest failed: %s",
                                    rd_kafka_err2str(err));
                        rd_kafka_metadata_refresh_known_topics(
                            rkb->rkb_rk, NULL, rd_true /*force*/, tmp);
                        /* FALLTHRU */

                case RD_KAFKA_RESP_ERR__TRANSPORT:
                case RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT:
                case RD_KAFKA_RESP_ERR__MSG_TIMED_OUT:
                        /* The fetch is already intervalled from
                         * consumer_serve() so dont retry. */
                        break;

                default:
                        break;
                }

                rd_kafka_broker_fetch_backoff(rkb, err);
                /* FALLTHRU */
        }
}

/**
 * @brief Check if any toppars have a zero topic id.
 *
 */
static rd_bool_t can_use_topic_ids(rd_kafka_broker_t *rkb) {
        rd_kafka_toppar_t *rktp = rkb->rkb_active_toppar_next;
        do {
                if (RD_KAFKA_UUID_IS_ZERO(rktp->rktp_rkt->rkt_topic_id))
                        return rd_false;
        } while ((rktp = CIRCLEQ_LOOP_NEXT(&rkb->rkb_active_toppars, rktp,
                                           rktp_activelink)) !=
                 rkb->rkb_active_toppar_next);

        return rd_true;
}


/**
 * @brief Sum the total acknowledgement entries and records across all
 *        per-partition batches in \p ack_details.
 *
 * @param ack_details   List of rd_kafka_share_ack_batches_t, or NULL.
 * @param entries_out   Set to the total number of ack entries (offset ranges).
 * @param records_out   Set to the total number of acknowledged records
 *                      (sum of entry->size across all entries).
 */
static void rd_kafka_share_ack_details_totals(rd_list_t *ack_details,
                                              int *entries_out,
                                              int64_t *records_out) {
        rd_kafka_share_ack_batches_t *batches;
        rd_kafka_share_ack_batch_entry_t *entry;
        int k, j;
        int entries     = 0;
        int64_t records = 0;

        if (ack_details) {
                RD_LIST_FOREACH(batches, ack_details, k) {
                        entries += rd_list_cnt(&batches->entries);
                        RD_LIST_FOREACH(entry, &batches->entries, j) {
                                records += entry->size;
                        }
                }
        }

        *entries_out = entries;
        *records_out = records;
}


void rd_kafka_ShareFetchRequest(rd_kafka_broker_t *rkb,
                                const rd_kafkap_str_t *group_id,
                                const rd_kafkap_str_t *member_id,
                                int32_t share_session_epoch,
                                int32_t wait_max_ms,
                                int32_t min_bytes,
                                int32_t max_bytes,
                                int32_t max_records,
                                int32_t batch_size,
                                rd_list_t *toppars_to_add,
                                rd_list_t *toppars_to_forget,
                                rd_kafka_op_t *rko_orig,
                                rd_ts_t now) {
        rd_kafka_toppar_t *rktp;
        rd_kafka_buf_t *rkbuf;
        int cnt                     = 0;
        size_t of_TopicArrayCnt     = 0;
        int TopicArrayCnt           = 0;
        size_t of_PartitionArrayCnt = 0;
        int PartitionArrayCnt       = 0;
        rd_kafka_topic_t *rkt_last  = NULL;
        int16_t ApiVersion          = 0;
        size_t rkbuf_size           = 0;
        int toppars_to_add_cnt =
            toppars_to_add ? rd_list_cnt(toppars_to_add) : 0;
        int i;
        rd_list_t *ack_details =
            rko_orig ? rko_orig->rko_u.share_fetch.ack_details : NULL;
        int ack_details_cnt = ack_details ? rd_list_cnt(ack_details) : 0;
        /* TODO KIP-932: Ensure there is no intersection between toppars_to_add
         * and ack_details. A toppar should not appear in both lists. */
        int total_ack_entries     = 0;
        int64_t total_ack_records = 0;
        int toppars_to_forget_cnt =
            toppars_to_forget ? rd_list_cnt(toppars_to_forget) : 0;
        rd_bool_t is_fetching_messages = max_records > 0 ? rd_true : rd_false;
        /* FirstOffset + LastOffset + AcknowledgementType per ack entry */
        size_t acknowledgement_size = 8 + 8 + 1;

        rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                   "toppars_to_add_cnt=%d, ack_details_cnt=%d, "
                   "total_ack_entries=%d, toppars_to_forget_cnt=%d, "
                   "is_fetching_messages=%d",
                   toppars_to_add_cnt, ack_details_cnt, total_ack_entries,
                   toppars_to_forget_cnt, is_fetching_messages);

        /* Calculate buffer size */
        if (group_id)
                rkbuf_size += RD_KAFKAP_STR_SIZE(group_id);
        if (member_id)
                rkbuf_size += RD_KAFKAP_STR_SIZE(member_id);
        /* ShareSessionEpoch + WaitMaxMs + MinBytes + MaxBytes + MaxRecords +
         * BatchSize + TopicArrayCnt*/
        rkbuf_size += 4 + 4 + 4 + 4 + 4 + 4 + 4;
        /* N x (topic id + partition id) for topics to add */
        rkbuf_size += (toppars_to_add_cnt * (32 + 4));
        /* M x (topic id + partition id) for ack details partitions +
         * E x acknowledgement entries */

        rkbuf_size += (ack_details_cnt * (32 + 4));
        /* Sum total ack entries and total records across all
         * ack_details batches. */
        rd_kafka_share_ack_details_totals(ack_details, &total_ack_entries,
                                          &total_ack_records);
        /* Accumulate piggybacked record-level acknowledgements for
         * consumer.share.fetch.manager.acknowledgements.send.{total,rate}. */
        if (total_ack_records > 0)
                rd_atomic64_add(
                    &rkb->rkb_rk->rk_telemetry.acknowledgements_send_total,
                    total_ack_records);

        rkbuf_size += (total_ack_entries * acknowledgement_size);

        /* F x (topic id + partition id) for topics to forget */
        rkbuf_size += (toppars_to_forget_cnt * (32 + 4));

        ApiVersion = rd_kafka_broker_ApiVersion_supported(
            rkb, RD_KAFKAP_ShareFetch, 1, 1, NULL);

        rkbuf = rd_kafka_buf_new_flexver_request(rkb, RD_KAFKAP_ShareFetch, 1,
                                                 rkbuf_size, rd_true);

        if (rkb->rkb_features & RD_KAFKA_FEATURE_MSGVER2)
                rd_kafka_buf_ApiVersion_set(rkbuf, ApiVersion,
                                            RD_KAFKA_FEATURE_MSGVER2);
        else if (rkb->rkb_features & RD_KAFKA_FEATURE_MSGVER1)
                rd_kafka_buf_ApiVersion_set(rkbuf, ApiVersion,
                                            RD_KAFKA_FEATURE_MSGVER1);
        else if (rkb->rkb_features & RD_KAFKA_FEATURE_THROTTLETIME)
                rd_kafka_buf_ApiVersion_set(rkbuf, ApiVersion,
                                            RD_KAFKA_FEATURE_THROTTLETIME);

        /* GroupId */
        rd_kafka_buf_write_kstr(rkbuf, group_id);

        /* MemberId */
        rd_kafka_buf_write_kstr(rkbuf, member_id);

        // printf(" ---------------------------------------
        // rd_kafka_ShareFetchRequest: member_id=%.*s\n",
        //        RD_KAFKAP_STR_PR(member_id));

        /* ShareSessionEpoch */
        rd_kafka_buf_write_i32(rkbuf, share_session_epoch);

        /* WaitMaxMs */
        rd_kafka_buf_write_i32(rkbuf, wait_max_ms);

        /* MinBytes */
        rd_kafka_buf_write_i32(rkbuf, min_bytes);

        /* MaxBytes */
        rd_kafka_buf_write_i32(rkbuf, max_bytes);

        /* MaxRecords */
        rd_kafka_buf_write_i32(rkbuf, max_records);

        /* BatchSize */
        rd_kafka_buf_write_i32(rkbuf, batch_size);

        /* Write zero TopicArrayCnt but store pointer for later update */
        of_TopicArrayCnt = rd_kafka_buf_write_arraycnt_pos(rkbuf);

        /* TODO KIP-932: Ensure toppars_to_add and ack_details don't have
         * common rktps. A toppar should only appear in one list.
         * Also merge toppars_to_add and ack_details as both can have
         * the same topic but different partitions. */

        /* Write toppars_to_add: new toppars being added to session
         * (no acknowledgements for newly added toppars) */
        if (toppars_to_add) {
                /* TODO KIP-932: This condition will cause partitions of same
                   topics to be inside single instance of the topic as
                   toppars_to_add is not sorted. Eg: T1 0, T1 1, T2 0, T1 3, T1
                   5, T2 1  will translate to T1 (0,1), T2 (0), T1 (3, 5), T2
                   (1) instead it should be T1 (0,1,3,5) T2(0,1) Fix this. */
                RD_LIST_FOREACH(rktp, toppars_to_add, i) {
                        if (rkt_last != rktp->rktp_rkt) {
                                if (rkt_last != NULL) {
                                        /* Update PartitionArrayCnt */
                                        rd_kafka_buf_finalize_arraycnt(
                                            rkbuf, of_PartitionArrayCnt,
                                            PartitionArrayCnt);
                                        /* Topic tags */
                                        rd_kafka_buf_write_tags_empty(rkbuf);
                                }

                                rd_kafka_topic_rdlock(rktp->rktp_rkt);
                                /* Topic ID */
                                rd_kafka_buf_write_uuid(
                                    rkbuf, &rktp->rktp_rkt->rkt_topic_id);
                                rd_kafka_topic_rdunlock(rktp->rktp_rkt);

                                TopicArrayCnt++;
                                rkt_last = rktp->rktp_rkt;
                                /* Partition count */
                                of_PartitionArrayCnt =
                                    rd_kafka_buf_write_arraycnt_pos(rkbuf);
                                PartitionArrayCnt = 0;
                        }

                        PartitionArrayCnt++;

                        /* Partition */
                        rd_kafka_buf_write_i32(rkbuf, rktp->rktp_partition);

                        /* No acknowledgements for newly added toppars */
                        rd_kafka_buf_write_arraycnt(rkbuf, 0);

                        /* Partition tags */
                        rd_kafka_buf_write_tags_empty(rkbuf);

                        rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                                   "Share Fetch adding topic %.*s [%" PRId32
                                   "]",
                                   RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                                   rktp->rktp_partition);

                        cnt++;
                }

                /* Finalize last topic from toppars_to_add */
                if (rkt_last != NULL) {
                        rd_kafka_buf_finalize_arraycnt(
                            rkbuf, of_PartitionArrayCnt, PartitionArrayCnt);
                        rd_kafka_buf_write_tags_empty(rkbuf);
                }
        }

        /* Write ack_details: toppars with acknowledgement batches.
         * Uses rktpar directly (no rktp/lock needed). */
        if (ack_details) {
                rd_kafka_Uuid_t *topic_id_last = NULL;
                rd_kafka_share_ack_batches_t *batches;
                rd_kafka_topic_partition_private_t *parpriv;
                rd_kafka_share_ack_batch_entry_t *entry;
                int k, m, entries_cnt;

                /* TODO KIP-932: This condition will cause partitions of same
                   topics to be inside single instance of the topic as
                   ack_details is not sorted. Eg: T1 0, T1 1, T2 0, T1 3, T1
                   5, T2 1  will translate to T1 (0,1), T2 (0), T1 (3, 5), T2
                   (1) instead it should be T1 (0,1,3,5) T2(0,1) Fix this. */
                PartitionArrayCnt = 0;

                RD_LIST_FOREACH(batches, ack_details, k) {
                        /* TODO KIP-932: Ensure rktpar and rktp are in sync,
                         * leader has not changed in between, and rktp is
                         * present before reaching this point.
                         * Also ensure batches->entries are not empty. */
                        /* _private should always be present here as it was
                         * set when building the ack batches from the
                         * inflight map. */
                        parpriv = (rd_kafka_topic_partition_private_t *)
                                      batches->rktpar->_private;
                        rd_dassert(parpriv != NULL);

                        if (topic_id_last == NULL ||
                            rd_kafka_Uuid_cmp(*topic_id_last,
                                              parpriv->topic_id) != 0) {
                                if (topic_id_last != NULL) {
                                        /* Update PartitionArrayCnt */
                                        rd_kafka_buf_finalize_arraycnt(
                                            rkbuf, of_PartitionArrayCnt,
                                            PartitionArrayCnt);
                                        /* Topic tags */
                                        rd_kafka_buf_write_tags_empty(rkbuf);
                                }

                                /* Topic ID */
                                rd_kafka_buf_write_uuid(rkbuf,
                                                        &parpriv->topic_id);

                                TopicArrayCnt++;
                                topic_id_last = &parpriv->topic_id;
                                /* Partition count */
                                of_PartitionArrayCnt =
                                    rd_kafka_buf_write_arraycnt_pos(rkbuf);
                                PartitionArrayCnt = 0;
                        }

                        PartitionArrayCnt++;

                        /* Partition */
                        rd_kafka_buf_write_i32(rkbuf,
                                               batches->rktpar->partition);

                        /* Write acknowledgement batches */
                        entries_cnt = rd_list_cnt(&batches->entries);
                        rd_kafka_buf_write_arraycnt(rkbuf, entries_cnt);

                        RD_LIST_FOREACH(entry, &batches->entries, m) {
                                /* FirstOffset */
                                rd_kafka_buf_write_i64(rkbuf,
                                                       entry->start_offset);
                                /* LastOffset */
                                rd_kafka_buf_write_i64(rkbuf,
                                                       entry->end_offset);
                                /* AcknowledgeTypes */
                                rd_kafka_buf_write_arraycnt(rkbuf, 1);
                                rd_kafka_buf_write_i8(rkbuf,
                                                      (int8_t)entry->types[0]);
                                /* Acknowledgement tags */
                                rd_kafka_buf_write_tags_empty(rkbuf);
                        }

                        /* Partition tags */
                        rd_kafka_buf_write_tags_empty(rkbuf);

                        rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                                   "Share Fetch ack for topic %s [%" PRId32
                                   "] with %d entries",
                                   batches->rktpar->topic,
                                   batches->rktpar->partition, entries_cnt);

                        cnt++;
                }

                /* Finalize last topic from ack_details */
                if (topic_id_last != NULL) {
                        rd_kafka_buf_finalize_arraycnt(
                            rkbuf, of_PartitionArrayCnt, PartitionArrayCnt);
                        rd_kafka_buf_write_tags_empty(rkbuf);
                }
        }

        rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                   "Share Fetch Request (epoch %" PRId32
                   ") with %d toppars on %d topics",
                   rkb->rkb_share_fetch_session.epoch, cnt, TopicArrayCnt);

        /* Update TopicArrayCnt */
        rd_kafka_buf_finalize_arraycnt(rkbuf, of_TopicArrayCnt, TopicArrayCnt);

        if (toppars_to_forget) {
                TopicArrayCnt     = 0;
                PartitionArrayCnt = 0;
                rkt_last          = NULL;
                /* Write zero TopicArrayCnt but store pointer for later update
                 */
                of_TopicArrayCnt = rd_kafka_buf_write_arraycnt_pos(rkbuf);
                rd_rkb_dbg(rkb, FETCH, "SHAREFETCH", "Forgetting %d toppars",
                           toppars_to_forget_cnt);
                RD_LIST_FOREACH(rktp, toppars_to_forget, i) {
                        /* TODO KIP-932: This condition will cause partitions of
                        same topics to be inside single instance of the topic as
                        toppars_to_forget is not sorted. Eg: T1 0, T1 1, T2 0,
                        T1 3, T1 5, T2 1  will translate to T1 (0,1), T2 (0),
                        T1 (3, 5), T2 (1) instead it should be T1 (0,1,3,5)
                        T2(0,1) Fix this. */
                        if (rkt_last != rktp->rktp_rkt) {
                                if (rkt_last != NULL) {
                                        /* Update PartitionArrayCnt */
                                        rd_kafka_buf_finalize_arraycnt(
                                            rkbuf, of_PartitionArrayCnt,
                                            PartitionArrayCnt);
                                        /* Topic tags */
                                        rd_kafka_buf_write_tags_empty(rkbuf);
                                }

                                rd_kafka_topic_rdlock(rktp->rktp_rkt);
                                /* Topic ID */
                                rd_kafka_buf_write_uuid(
                                    rkbuf, &rktp->rktp_rkt->rkt_topic_id);
                                rd_kafka_topic_rdunlock(rktp->rktp_rkt);

                                TopicArrayCnt++;
                                rkt_last = rktp->rktp_rkt;
                                /* Partition count */
                                of_PartitionArrayCnt =
                                    rd_kafka_buf_write_arraycnt_pos(rkbuf);
                                PartitionArrayCnt = 0;
                        }

                        PartitionArrayCnt++;

                        /* Partition */
                        rd_kafka_buf_write_i32(rkbuf, rktp->rktp_partition);

                        rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                                   "Forgetting Fetch partition %.*s [%" PRId32
                                   "]",
                                   RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                                   rktp->rktp_partition);
                }
                if (rkt_last != NULL) {
                        /* Update last topic's PartitionArrayCnt */
                        rd_kafka_buf_finalize_arraycnt(
                            rkbuf, of_PartitionArrayCnt, PartitionArrayCnt);
                        /* Topic tags */
                        rd_kafka_buf_write_tags_empty(rkbuf);
                }
                /* Update TopicArrayCnt */
                rd_kafka_buf_finalize_arraycnt(rkbuf, of_TopicArrayCnt,
                                               TopicArrayCnt);
        } else {
                /* ForgottenToppars */
                rd_kafka_buf_write_arraycnt(rkbuf, 0);
        }

        /* Consider Fetch requests blocking if fetch.wait.max.ms >= 1s */
        if (rkb->rkb_rk->rk_conf.fetch_wait_max_ms >= 1000)
                rkbuf->rkbuf_flags |= RD_KAFKA_OP_F_BLOCKING;

        /* Use configured timeout */
        rd_kafka_buf_set_timeout(rkbuf,
                                 rkb->rkb_rk->rk_conf.socket_timeout_ms +
                                     rkb->rkb_rk->rk_conf.fetch_wait_max_ms,
                                 now);

        /* Copy toppars_to_add/toppars_to_forget into adding/forgetting lists
         * just before sending. On response, session_update() will move
         * adding_toppars into toppars_in_session and remove from
         * toppars_to_add. */
        if (rkb->rkb_share_fetch_session.toppars_to_add)
                rkb->rkb_share_fetch_session.adding_toppars =
                    rd_list_copy(rkb->rkb_share_fetch_session.toppars_to_add,
                                 rd_kafka_toppar_list_copy, NULL);
        if (rkb->rkb_share_fetch_session.toppars_to_forget)
                rkb->rkb_share_fetch_session.forgetting_toppars =
                    rd_list_copy(rkb->rkb_share_fetch_session.toppars_to_forget,
                                 rd_kafka_toppar_list_copy, NULL);

        rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                   "Issuing ShareFetch request (max wait %dms, min %d bytes, "
                   "max %d bytes, max %d records) with %d toppars",
                   wait_max_ms, min_bytes, max_bytes, max_records, cnt);
        rd_kafka_broker_buf_enq1(rkb, rkbuf, rd_kafka_broker_share_fetch_reply,
                                 rko_orig);

        return;
}

/**
 * @brief Build and send a ShareAcknowledge request.
 *
 * Used for ack-only requests (no fetching) and session close (epoch=-1).
 * ShareAcknowledge carries GroupId, MemberId, ShareSessionEpoch, and
 * acknowledgement batches only — no fetch parameters or forgotten topics.
 *
 * @param rkb Broker to send request to.
 * @param group_id Consumer group id.
 * @param member_id Consumer member id.
 * @param share_session_epoch Session epoch (-1 for close).
 * @param rko_orig The originating SHARE_FETCH op (carries ack_details).
 * @param now Current timestamp.
 *
 * @locality broker thread
 */
void rd_kafka_ShareAcknowledgeRequest(rd_kafka_broker_t *rkb,
                                      const rd_kafkap_str_t *group_id,
                                      const rd_kafkap_str_t *member_id,
                                      int32_t share_session_epoch,
                                      rd_kafka_op_t *rko_orig,
                                      rd_ts_t now) {
        rd_kafka_buf_t *rkbuf;
        int cnt                     = 0;
        size_t of_TopicArrayCnt     = 0;
        int TopicArrayCnt           = 0;
        size_t of_PartitionArrayCnt = 0;
        int PartitionArrayCnt       = 0;
        size_t rkbuf_size           = 0;
        rd_list_t *ack_details =
            rko_orig ? rko_orig->rko_u.share_fetch.ack_details : NULL;
        int ack_details_cnt       = ack_details ? rd_list_cnt(ack_details) : 0;
        int total_ack_entries     = 0;
        int64_t total_ack_records = 0;
        /* FirstOffset + LastOffset + AcknowledgementType per ack entry */
        size_t acknowledgement_size = 8 + 8 + 1;

        rd_rkb_dbg(rkb, FETCH, "SHAREACK",
                   "ack_details_cnt=%d, share_session_epoch=%" PRId32,
                   ack_details_cnt, share_session_epoch);

        /* Calculate buffer size */
        if (group_id)
                rkbuf_size += RD_KAFKAP_STR_SIZE(group_id);
        if (member_id)
                rkbuf_size += RD_KAFKAP_STR_SIZE(member_id);
        /* ShareSessionEpoch + TopicArrayCnt */
        rkbuf_size += 4 + 4;
        /* N x (topic id + partition id) for ack details */
        rkbuf_size += (ack_details_cnt * (32 + 4));
        /* Sum total ack entries and total records across all
         * ack_details batches. */
        rd_kafka_share_ack_details_totals(ack_details, &total_ack_entries,
                                          &total_ack_records);
        /* Accumulate standalone record-level acknowledgements for
         * consumer.share.fetch.manager.acknowledgements.send.{total,rate}. */
        if (total_ack_records > 0)
                rd_atomic64_add(
                    &rkb->rkb_rk->rk_telemetry.acknowledgements_send_total,
                    total_ack_records);

        rkbuf_size += (total_ack_entries * acknowledgement_size);

        rkbuf = rd_kafka_buf_new_flexver_request(
            rkb, RD_KAFKAP_ShareAcknowledge, 1, rkbuf_size, rd_true);

        rd_kafka_buf_ApiVersion_set(
            rkbuf,
            rd_kafka_broker_ApiVersion_supported(
                rkb, RD_KAFKAP_ShareAcknowledge, 1, 1, NULL),
            0);

        /* GroupId */
        rd_kafka_buf_write_kstr(rkbuf, group_id);

        /* MemberId */
        rd_kafka_buf_write_kstr(rkbuf, member_id);

        /* ShareSessionEpoch */
        rd_kafka_buf_write_i32(rkbuf, share_session_epoch);

        /* Topics array with acknowledgement batches */
        of_TopicArrayCnt = rd_kafka_buf_write_arraycnt_pos(rkbuf);

        rd_rkb_dbg(rkb, FETCH, "SHAREACK",
                   "Building ShareAcknowledge request with %d ack toppars "
                   "and %d total ack entries",
                   ack_details_cnt, total_ack_entries);

        if (ack_details) {
                rd_kafka_Uuid_t *topic_id_last = NULL;
                rd_kafka_share_ack_batches_t *batches;
                rd_kafka_topic_partition_private_t *parpriv;
                rd_kafka_share_ack_batch_entry_t *entry;
                int k, m, entries_cnt;

                RD_LIST_FOREACH(batches, ack_details, k) {
                        parpriv = (rd_kafka_topic_partition_private_t *)
                                      batches->rktpar->_private;
                        rd_dassert(parpriv != NULL);

                        if (topic_id_last == NULL ||
                            rd_kafka_Uuid_cmp(*topic_id_last,
                                              parpriv->topic_id) != 0) {
                                if (topic_id_last != NULL) {
                                        rd_kafka_buf_finalize_arraycnt(
                                            rkbuf, of_PartitionArrayCnt,
                                            PartitionArrayCnt);
                                        rd_kafka_buf_write_tags_empty(rkbuf);
                                }

                                /* Topic ID */
                                rd_kafka_buf_write_uuid(rkbuf,
                                                        &parpriv->topic_id);

                                TopicArrayCnt++;
                                topic_id_last = &parpriv->topic_id;
                                of_PartitionArrayCnt =
                                    rd_kafka_buf_write_arraycnt_pos(rkbuf);
                                PartitionArrayCnt = 0;
                        }

                        PartitionArrayCnt++;

                        /* Partition */
                        rd_kafka_buf_write_i32(rkbuf,
                                               batches->rktpar->partition);

                        rd_rkb_dbg(rkb, FETCH, "SHAREACK",
                                   "Adding ack for topic %s [%" PRId32
                                   "] with %d entries",
                                   batches->rktpar->topic,
                                   batches->rktpar->partition,
                                   rd_list_cnt(&batches->entries));

                        /* Write acknowledgement batches */
                        entries_cnt = rd_list_cnt(&batches->entries);
                        rd_kafka_buf_write_arraycnt(rkbuf, entries_cnt);

                        RD_LIST_FOREACH(entry, &batches->entries, m) {
                                rd_rkb_dbg(rkb, FETCH, "SHAREACK",
                                           "Adding ack entry with start offset "
                                           "%" PRId64 ", end offset %" PRId64
                                           ", type %d",
                                           entry->start_offset,
                                           entry->end_offset, entry->types[0]);
                                /* FirstOffset */
                                rd_kafka_buf_write_i64(rkbuf,
                                                       entry->start_offset);
                                /* LastOffset */
                                rd_kafka_buf_write_i64(rkbuf,
                                                       entry->end_offset);
                                /* AcknowledgeTypes */
                                rd_kafka_buf_write_arraycnt(rkbuf, 1);
                                rd_kafka_buf_write_i8(rkbuf,
                                                      (int8_t)entry->types[0]);
                                /* Acknowledgement tags */
                                rd_kafka_buf_write_tags_empty(rkbuf);
                        }

                        /* Partition tags */
                        rd_kafka_buf_write_tags_empty(rkbuf);

                        cnt++;
                }

                /* Finalize last topic from ack_details */
                if (topic_id_last != NULL) {
                        rd_kafka_buf_finalize_arraycnt(
                            rkbuf, of_PartitionArrayCnt, PartitionArrayCnt);
                        rd_kafka_buf_write_tags_empty(rkbuf);
                }
        }

        rd_rkb_dbg(rkb, FETCH, "SHAREACK",
                   "ShareAcknowledge Request with %d toppars on %d topics", cnt,
                   TopicArrayCnt);

        /* Update TopicArrayCnt */
        rd_kafka_buf_finalize_arraycnt(rkbuf, of_TopicArrayCnt, TopicArrayCnt);

        /* Wire RPC timeout is socket.timeout.ms, decoupled from any
         * caller-side commit_sync deadline. Interactions covered by
         * tests/0182-share_consumer_error_handling_mock.c
         * (do_test_socket_timeout_full_ack_then_more). */
        rd_kafka_buf_set_timeout(rkbuf, rkb->rkb_rk->rk_conf.socket_timeout_ms,
                                 now);

        rd_rkb_dbg(rkb, FETCH, "SHAREACK",
                   "Issuing ShareAcknowledge request with %d toppars", cnt);
        rd_kafka_broker_buf_enq1(
            rkb, rkbuf, rd_kafka_broker_share_acknowledge_reply, rko_orig);
}


void rd_kafka_broker_share_fetch_session_clear(rd_kafka_broker_t *rkb) {
        /* Clear toppars in session */
        rd_rkb_dbg(
            rkb, BROKER, "SHARESESSION",
            "Clearing %d toppars from ShareFetch session",
            rd_list_cnt(rkb->rkb_share_fetch_session.toppars_in_session));
        rd_list_clear(rkb->rkb_share_fetch_session.toppars_in_session);

        /* Clear toppars to add */
        if (rkb->rkb_share_fetch_session.toppars_to_add) {
                rd_rkb_dbg(
                    rkb, BROKER, "SHARESESSION",
                    "Clearing %d toppars to add from ShareFetch session on "
                    "clear",
                    rd_list_cnt(rkb->rkb_share_fetch_session.toppars_to_add));
                rd_list_destroy(rkb->rkb_share_fetch_session.toppars_to_add);
                rkb->rkb_share_fetch_session.toppars_to_add = NULL;
        }

        /* Clear toppars to forget */
        if (rkb->rkb_share_fetch_session.toppars_to_forget) {
                rd_rkb_dbg(rkb, BROKER, "SHARESESSION",
                           "Clearing %d toppars to forget from ShareFetch "
                           "session on clear",
                           rd_list_cnt(
                               rkb->rkb_share_fetch_session.toppars_to_forget));
                rd_list_destroy(rkb->rkb_share_fetch_session.toppars_to_forget);
                rkb->rkb_share_fetch_session.toppars_to_forget = NULL;
        }

        /* Clear adding toppars */
        if (rkb->rkb_share_fetch_session.adding_toppars) {
                rd_rkb_dbg(
                    rkb, BROKER, "SHARESESSION",
                    "Clearing %d adding toppars from ShareFetch session on "
                    "clear",
                    rd_list_cnt(rkb->rkb_share_fetch_session.adding_toppars));
                rd_list_destroy(rkb->rkb_share_fetch_session.adding_toppars);
                rkb->rkb_share_fetch_session.adding_toppars = NULL;
        }

        /* Clear forgetting toppars */
        if (rkb->rkb_share_fetch_session.forgetting_toppars) {
                rd_rkb_dbg(
                    rkb, BROKER, "SHARESESSION",
                    "Clearing %d forgetting toppars from ShareFetch session on "
                    "clear",
                    rd_list_cnt(
                        rkb->rkb_share_fetch_session.forgetting_toppars));
                rd_list_destroy(
                    rkb->rkb_share_fetch_session.forgetting_toppars);
                rkb->rkb_share_fetch_session.forgetting_toppars = NULL;
        }

        /*
         * This allows us to avoid future changes to the closed share session
         * Toppar add/remove functions do not allow updates if epoch is -1
         * Avoid future changes to the closed share session */
        rkb->rkb_share_fetch_session.epoch = -1;
}

void rd_kafka_broker_share_fetch_session_leave(rd_kafka_broker_t *rkb,
                                               rd_kafka_op_t *rko_orig,
                                               rd_ts_t now) {
        rd_kafka_cgrp_t *rkcg = rkb->rkb_rk->rk_cgrp;

        if (rkb->rkb_share_fetch_session.epoch > 0) {
                rd_rkb_dbg(rkb, BROKER, "SHARESESSION",
                           "Processing SHARE_FETCH op: "
                           "should_leave = true");

                /* Set epoch to -1 to signal session close before sending
                 * request. This ensures session_update_epoch() skips
                 * incrementing on reply. */
                rkb->rkb_share_fetch_session.epoch = -1;
                rd_kafka_ShareAcknowledgeRequest(
                    rkb, rkcg->rkcg_group_id, rkcg->rkcg_member_id,
                    -1, /* epoch=-1 signals session close */
                    rko_orig, now);
        } else {
                rd_rkb_dbg(rkb, BROKER, "SHARESESSION",
                           "Ignoring SHARE_FETCH op with "
                           "should_leave = true: "
                           "no active session");

                if (rkb->rkb_share_fetch_session.epoch == 0)
                        /* Required as it is possible that we were about
                         * to establish a session */
                        rd_kafka_broker_share_fetch_session_clear(rkb);
                rd_kafka_share_fetch_op_reply_and_update_ack_details_with_err(
                    rko_orig, RD_KAFKA_RESP_ERR_SHARE_SESSION_NOT_FOUND);
        }
}

void rd_kafka_broker_share_rpc(rd_kafka_broker_t *rkb,
                               rd_kafka_op_t *rko_orig,
                               rd_ts_t now) {

        rd_kafka_cgrp_t *rkcg     = rkb->rkb_rk->rk_cgrp;
        int32_t max_records       = 0;
        rd_list_t *ack_details    = rko_orig->rko_u.share_fetch.ack_details;
        rd_bool_t has_ack_details = ack_details && rd_list_cnt(ack_details) > 0;
        rd_list_t *toppars_to_add = NULL;
        rd_list_t *toppars_to_forget = NULL;
        rd_list_t *stripped_acks     = NULL;

        if (!rko_orig->rko_u.share_fetch.should_fetch && !has_ack_details) {
                rd_rkb_dbg(rkb, FETCH, "SHARERPC",
                           "Not sending Share RPC: "
                           "no fetch requested and no acknowledgements");
                rd_kafka_share_fetch_op_reply_and_update_ack_details_with_err(
                    rko_orig, RD_KAFKA_RESP_ERR__NOOP);
                return;
        }

        if (!rkcg->rkcg_member_id) {
                rd_rkb_dbg(rkb, FETCH, "SHARERPC",
                           "Share RPC requested without member_id");
                rd_kafka_share_fetch_op_reply_and_update_ack_details_with_err(
                    rko_orig, RD_KAFKA_RESP_ERR__INVALID_ARG);
                return;
        }

        if (!rko_orig->rko_u.share_fetch.should_fetch) {
                /* Ack-only: use ShareAcknowledge RPC.
                 *
                 * If session epoch is 0 (new consumer or post-reset),
                 * the broker has no session state to acknowledge
                 * against. Fail the acks locally with
                 * INVALID_SHARE_SESSION_EPOCH instead of sending,
                 * since the broker would reject the request. */
                if (rkb->rkb_share_fetch_session.epoch == 0) {
                        rd_rkb_dbg(rkb, FETCH, "SHAREACK",
                                   "Failing %d ack batches locally: "
                                   "session epoch is 0 (no session)",
                                   rd_list_cnt(ack_details));
                        rd_kafka_share_fetch_op_reply_and_update_ack_details_with_err(
                            rko_orig,
                            RD_KAFKA_RESP_ERR_INVALID_SHARE_SESSION_EPOCH);
                        return;
                }

                /* TODO KIP-932: add a defensive per-batch leader-stale
                 * strip here (mirroring the segregation-time check) to
                 * cover the window where the cached leader changes
                 * between segregation on the main thread and this RPC
                 * send on the broker thread. It must run AFTER the
                 * epoch==0 check above so the local-only failure path
                 * stays identical to the broker-roundtrip flow. */

                rd_rkb_dbg(rkb, FETCH, "SHAREACK",
                           "Sending ShareAcknowledge Request with"
                           " acknowledgements");

                rd_kafka_ShareAcknowledgeRequest(
                    rkb, rkcg->rkcg_group_id, rkcg->rkcg_member_id,
                    rkb->rkb_share_fetch_session.epoch, rko_orig, now);
                return;
        }

        max_records       = rkb->rkb_rk->rk_conf.share.max_poll_records;
        toppars_to_add    = rkb->rkb_share_fetch_session.toppars_to_add;
        toppars_to_forget = rkb->rkb_share_fetch_session.toppars_to_forget;

        /* If session epoch is 0 (new/reset session) and we have
         * piggybacked acks, the broker has no session state to ack
         * against. Fail the acks locally with
         * INVALID_SHARE_SESSION_EPOCH and strip them from the wire
         * request. The ShareFetch itself still goes out to establish
         * the session. */
        if (rkb->rkb_share_fetch_session.epoch == 0 && has_ack_details) {
                rd_kafka_share_ack_batches_t *batch;
                int i;

                rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                           "Stripping %d piggybacked ack batches: "
                           "session epoch is 0 (no session)",
                           rd_list_cnt(ack_details));

                /* Pre-set each batch's err. Conditional buf-cb init
                 * preserves this; main reply handler propagates to
                 * commit_sync results / acknowledgement callback. */
                RD_LIST_FOREACH(batch, ack_details, i) {
                        batch->rktpar->err =
                            RD_KAFKA_RESP_ERR_INVALID_SHARE_SESSION_EPOCH;
                }

                /* Detach so ShareFetchRequest builds without the ack
                 * data section. Restored after the request is built
                 * so the buf reply handler / main thread reply
                 * handler can still read the per-batch err. */
                stripped_acks = rko_orig->rko_u.share_fetch.ack_details;
                rko_orig->rko_u.share_fetch.ack_details = NULL;
                has_ack_details                         = rd_false;
        }

        /* TODO KIP-932: add a defensive per-batch leader-stale strip
         * here (mirroring the segregation-time check) to cover the
         * window where the cached leader changes between segregation
         * on the main thread and this RPC send on the broker thread.
         * It must run AFTER the epoch==0 strip above so the local-only
         * failure path stays identical to the broker-roundtrip flow. */

        rd_rkb_dbg(rkb, FETCH, "SHAREFETCH",
                   "Sending ShareFetch Request (epoch %" PRId32
                   ") with%s%s%s fetching messages",
                   rkb->rkb_share_fetch_session.epoch,
                   has_ack_details ? " acknowledgements," : "",
                   toppars_to_add ? " new topics," : "",
                   toppars_to_forget ? " forgotten toppars," : "");

        rd_kafka_ShareFetchRequest(
            rkb, rkcg->rkcg_group_id,           /* group_id */
            rkcg->rkcg_member_id,               /* member_id */
            rkb->rkb_share_fetch_session.epoch, /* share_session_epoch */
            rkb->rkb_rk->rk_conf.fetch_wait_max_ms,
            rkb->rkb_rk->rk_conf.fetch_min_bytes,
            rkb->rkb_rk->rk_conf.fetch_max_bytes, max_records,
            max_records,       /* batch_size: same value as max_records,
                                * both sourced from max.poll.records */
            toppars_to_add,    /* toppars to add to session */
            toppars_to_forget, /* forgetting toppars */
            rko_orig,          /* rko (carries ack_details) */
            now);

        /* Restore ack_details so the buf reply handler / main thread
         * reply handler can read the pre-set per-batch err. */
        if (stripped_acks)
                rko_orig->rko_u.share_fetch.ack_details = stripped_acks;
}

/**
 * @brief Build and send a Fetch request message for all underflowed toppars
 *        for a specific broker.
 *
 * @returns the number of partitions included in the FetchRequest, if any.
 *
 * @locality broker thread
 */
int rd_kafka_broker_fetch_toppars(rd_kafka_broker_t *rkb, rd_ts_t now) {
        rd_kafka_toppar_t *rktp;
        rd_kafka_buf_t *rkbuf;
        int cnt                     = 0;
        size_t of_TopicArrayCnt     = 0;
        int TopicArrayCnt           = 0;
        size_t of_PartitionArrayCnt = 0;
        int PartitionArrayCnt       = 0;
        rd_kafka_topic_t *rkt_last  = NULL;
        int16_t ApiVersion          = 0;

        /* Create buffer and segments:
         *   1 x ReplicaId MaxWaitTime MinBytes TopicArrayCnt
         *   N x topic name
         *   N x PartitionArrayCnt Partition FetchOffset MaxBytes
         * where N = number of toppars.
         * Since we dont keep track of the number of topics served by
         * this broker, only the partition count, we do a worst-case calc
         * when allocating and assume each partition is on its own topic
         */

        if (unlikely(rkb->rkb_active_toppar_cnt == 0))
                return 0;

        ApiVersion = rd_kafka_broker_ApiVersion_supported(rkb, RD_KAFKAP_Fetch,
                                                          0, 16, NULL);

        /* Fallback to version 12 if topic id is null which can happen if
         * inter.broker.protocol.version is < 2.8 */
        if (ApiVersion > 12 && !can_use_topic_ids(rkb))
                ApiVersion = 12;

        rkbuf = rd_kafka_buf_new_flexver_request(
            rkb, RD_KAFKAP_Fetch, 1,
            /* MaxWaitTime+MinBytes+MaxBytes+IsolationLevel+
             *   SessionId+Epoch+TopicCnt */
            4 + 4 + 4 + 1 + 4 + 4 + 4 +
                /* N x PartCnt+Partition+CurrentLeaderEpoch+FetchOffset+
                 * LastFetchedEpoch+LogStartOffset+MaxBytes+?TopicNameLen?*/
                (rkb->rkb_active_toppar_cnt *
                 (4 + 4 + 4 + 8 + 4 + 8 + 4 + 40)) +
                /* ForgottenTopicsCnt */
                4 +
                /* N x ForgottenTopicsData */
                0,
            ApiVersion >= 12);

        if (rkb->rkb_features & RD_KAFKA_FEATURE_MSGVER2)
                rd_kafka_buf_ApiVersion_set(rkbuf, ApiVersion,
                                            RD_KAFKA_FEATURE_MSGVER2);
        else if (rkb->rkb_features & RD_KAFKA_FEATURE_MSGVER1)
                rd_kafka_buf_ApiVersion_set(rkbuf, ApiVersion,
                                            RD_KAFKA_FEATURE_MSGVER1);
        else if (rkb->rkb_features & RD_KAFKA_FEATURE_THROTTLETIME)
                rd_kafka_buf_ApiVersion_set(rkbuf, ApiVersion,
                                            RD_KAFKA_FEATURE_THROTTLETIME);


        /* FetchRequest header */
        if (rd_kafka_buf_ApiVersion(rkbuf) <= 14)
                /* ReplicaId */
                rd_kafka_buf_write_i32(rkbuf, -1);

        /* MaxWaitTime */
        rd_kafka_buf_write_i32(rkbuf, rkb->rkb_rk->rk_conf.fetch_wait_max_ms);
        /* MinBytes */
        rd_kafka_buf_write_i32(rkbuf, rkb->rkb_rk->rk_conf.fetch_min_bytes);

        if (rd_kafka_buf_ApiVersion(rkbuf) >= 3)
                /* MaxBytes */
                rd_kafka_buf_write_i32(rkbuf,
                                       rkb->rkb_rk->rk_conf.fetch_max_bytes);

        if (rd_kafka_buf_ApiVersion(rkbuf) >= 4)
                /* IsolationLevel */
                rd_kafka_buf_write_i8(rkbuf,
                                      rkb->rkb_rk->rk_conf.isolation_level);

        if (rd_kafka_buf_ApiVersion(rkbuf) >= 7) {
                /* SessionId */
                rd_kafka_buf_write_i32(rkbuf, 0);
                /* Epoch */
                rd_kafka_buf_write_i32(rkbuf, -1);
        }

        /* Write zero TopicArrayCnt but store pointer for later update */
        of_TopicArrayCnt = rd_kafka_buf_write_arraycnt_pos(rkbuf);

        /* Prepare map for storing the fetch version for each partition,
         * this will later be checked in Fetch response to purge outdated
         * responses (e.g., after a seek). */
        rkbuf->rkbuf_rktp_vers =
            rd_list_new(0, (void *)rd_kafka_toppar_ver_destroy);
        rd_list_prealloc_elems(rkbuf->rkbuf_rktp_vers,
                               sizeof(struct rd_kafka_toppar_ver),
                               rkb->rkb_active_toppar_cnt, 0);

        /* Round-robin start of the list. */
        rktp = rkb->rkb_active_toppar_next;
        do {
                struct rd_kafka_toppar_ver *tver;

                if (rkt_last != rktp->rktp_rkt) {
                        if (rkt_last != NULL) {
                                /* Update PartitionArrayCnt */
                                rd_kafka_buf_finalize_arraycnt(
                                    rkbuf, of_PartitionArrayCnt,
                                    PartitionArrayCnt);
                                /* Topic tags */
                                rd_kafka_buf_write_tags_empty(rkbuf);
                        }

                        /* TODO: This is not thread safe as topic can
                                 be recreated in which case topic id is
                                 updated from the main thread and we are
                                 sending topic id from broker thread.*/
                        if (rd_kafka_buf_ApiVersion(rkbuf) > 12) {
                                /* Topic id must be non-zero here */
                                rd_dassert(!RD_KAFKA_UUID_IS_ZERO(
                                    rktp->rktp_rkt->rkt_topic_id));
                                /* Topic ID */
                                rd_kafka_buf_write_uuid(
                                    rkbuf, &rktp->rktp_rkt->rkt_topic_id);
                        } else {
                                /* Topic name */
                                rd_kafka_buf_write_kstr(
                                    rkbuf, rktp->rktp_rkt->rkt_topic);
                        }

                        TopicArrayCnt++;
                        rkt_last = rktp->rktp_rkt;
                        /* Partition count */
                        of_PartitionArrayCnt =
                            rd_kafka_buf_write_arraycnt_pos(rkbuf);
                        PartitionArrayCnt = 0;
                }

                PartitionArrayCnt++;

                /* Partition */
                rd_kafka_buf_write_i32(rkbuf, rktp->rktp_partition);

                if (rd_kafka_buf_ApiVersion(rkbuf) >= 9) {
                        /* CurrentLeaderEpoch */
                        if (rktp->rktp_leader_epoch < 0 &&
                            rd_kafka_has_reliable_leader_epochs(rkb)) {
                                /* If current leader epoch is set to -1 and
                                 * the broker has reliable leader epochs,
                                 * send 0 instead, so that epoch is checked
                                 * and optionally metadata is refreshed.
                                 * This can happen if metadata is read initially
                                 * without an existing topic (see
                                 * rd_kafka_topic_metadata_update2).
                                 */
                                rd_kafka_buf_write_i32(rkbuf, 0);
                        } else {
                                rd_kafka_buf_write_i32(rkbuf,
                                                       rktp->rktp_leader_epoch);
                        }
                }
                /* FetchOffset */
                rd_kafka_buf_write_i64(rkbuf,
                                       rktp->rktp_offsets.fetch_pos.offset);
                if (rd_kafka_buf_ApiVersion(rkbuf) >= 12)
                        /* LastFetchedEpoch - only used by follower replica */
                        rd_kafka_buf_write_i32(rkbuf, -1);
                if (rd_kafka_buf_ApiVersion(rkbuf) >= 5)
                        /* LogStartOffset - only used by follower replica */
                        rd_kafka_buf_write_i64(rkbuf, -1);

                /* MaxBytes */
                rd_kafka_buf_write_i32(rkbuf, rktp->rktp_fetch_msg_max_bytes);

                /* Partition tags */
                rd_kafka_buf_write_tags_empty(rkbuf);

                rd_rkb_dbg(rkb, FETCH, "FETCH",
                           "Fetch topic %.*s [%" PRId32 "] at offset %" PRId64
                           " (leader epoch %" PRId32
                           ", current leader epoch %" PRId32 ", v%d)",
                           RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                           rktp->rktp_partition,
                           rktp->rktp_offsets.fetch_pos.offset,
                           rktp->rktp_offsets.fetch_pos.leader_epoch,
                           rktp->rktp_leader_epoch, rktp->rktp_fetch_version);

                /* We must have a valid fetch offset when we get here */
                rd_dassert(rktp->rktp_offsets.fetch_pos.offset >= 0);

                /* Add toppar + op version mapping. */
                tver          = rd_list_add(rkbuf->rkbuf_rktp_vers, NULL);
                tver->rktp    = rd_kafka_toppar_keep(rktp);
                tver->version = rktp->rktp_fetch_version;

                cnt++;
        } while ((rktp = CIRCLEQ_LOOP_NEXT(&rkb->rkb_active_toppars, rktp,
                                           rktp_activelink)) !=
                 rkb->rkb_active_toppar_next);

        /* Update next toppar to fetch in round-robin list. */
        rd_kafka_broker_active_toppar_next(
            rkb, rktp ? CIRCLEQ_LOOP_NEXT(&rkb->rkb_active_toppars, rktp,
                                          rktp_activelink)
                      : NULL);

        rd_rkb_dbg(rkb, FETCH, "FETCH", "Fetch %i/%i/%i toppar(s)", cnt,
                   rkb->rkb_active_toppar_cnt, rkb->rkb_toppar_cnt);
        if (!cnt) {
                rd_kafka_buf_destroy(rkbuf);
                return cnt;
        }

        if (rkt_last != NULL) {
                /* Update last topic's PartitionArrayCnt */
                rd_kafka_buf_finalize_arraycnt(rkbuf, of_PartitionArrayCnt,
                                               PartitionArrayCnt);
                /* Topic tags */
                rd_kafka_buf_write_tags_empty(rkbuf);
        }

        /* Update TopicArrayCnt */
        rd_kafka_buf_finalize_arraycnt(rkbuf, of_TopicArrayCnt, TopicArrayCnt);


        if (rd_kafka_buf_ApiVersion(rkbuf) >= 7)
                /* Length of the ForgottenTopics list (KIP-227). Broker
                 * use only - not used by the consumer. */
                rd_kafka_buf_write_arraycnt(rkbuf, 0);

        if (rd_kafka_buf_ApiVersion(rkbuf) >= 11)
                /* RackId */
                rd_kafka_buf_write_kstr(rkbuf,
                                        rkb->rkb_rk->rk_conf.client_rack);

        /* Consider Fetch requests blocking if fetch.wait.max.ms >= 1s */
        if (rkb->rkb_rk->rk_conf.fetch_wait_max_ms >= 1000)
                rkbuf->rkbuf_flags |= RD_KAFKA_OP_F_BLOCKING;

        /* Use configured timeout */
        rd_kafka_buf_set_timeout(rkbuf,
                                 rkb->rkb_rk->rk_conf.socket_timeout_ms +
                                     rkb->rkb_rk->rk_conf.fetch_wait_max_ms,
                                 now);

        /* Sort toppar versions for quicker lookups in Fetch response. */
        rd_list_sort(rkbuf->rkbuf_rktp_vers, rd_kafka_toppar_ver_cmp);

        rkb->rkb_fetching = 1;
        rd_kafka_broker_buf_enq1(rkb, rkbuf, rd_kafka_broker_fetch_reply, NULL);

        return cnt;
}

/**
 * @brief Decide whether it should start fetching from next fetch start
 *        or continue with current fetch pos.
 *
 * @param rktp the toppar
 *
 * @returns rd_true if it should start fetching from next fetch start,
 *          rd_false otherwise.
 *
 * @locality any
 * @locks toppar_lock() MUST be held
 */
static rd_bool_t rd_kafka_toppar_fetch_decide_start_from_next_fetch_start(
    rd_kafka_toppar_t *rktp) {
        return rktp->rktp_op_version > rktp->rktp_fetch_version ||
               rd_kafka_fetch_pos_cmp(&rktp->rktp_next_fetch_start,
                                      &rktp->rktp_last_next_fetch_start) ||
               rktp->rktp_offsets.fetch_pos.offset == RD_KAFKA_OFFSET_INVALID;
}

/**
 * @brief Return next fetch start position:
 *        if it should start fetching from next fetch start
 *        or continue with current fetch pos.
 *
 * @param rktp The toppar
 *
 * @returns Next fetch start position
 *
 * @locality any
 * @locks toppar_lock() MUST be held
 */
rd_kafka_fetch_pos_t
rd_kafka_toppar_fetch_decide_next_fetch_start_pos(rd_kafka_toppar_t *rktp) {
        if (rd_kafka_toppar_fetch_decide_start_from_next_fetch_start(rktp))
                return rktp->rktp_next_fetch_start;
        else
                return rktp->rktp_offsets.fetch_pos;
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
rd_ts_t rd_kafka_toppar_fetch_decide(rd_kafka_toppar_t *rktp,
                                     rd_kafka_broker_t *rkb,
                                     int force_remove) {
        int should_fetch   = 1;
        const char *reason = "";
        int32_t version;
        rd_ts_t ts_backoff      = 0;
        rd_bool_t lease_expired = rd_false;

        rd_kafka_toppar_lock(rktp);

        /* Check for preferred replica lease expiry */
        lease_expired = rktp->rktp_leader_id != rktp->rktp_broker_id &&
                        rd_interval(&rktp->rktp_lease_intvl,
                                    5 * 60 * 1000 * 1000 /*5 minutes*/, 0) > 0;
        if (lease_expired) {
                /* delegate_to_leader() requires no locks to be held */
                rd_kafka_toppar_unlock(rktp);
                rd_kafka_toppar_delegate_to_leader(rktp);
                rd_kafka_toppar_lock(rktp);

                reason       = "preferred replica lease expired";
                should_fetch = 0;
                goto done;
        }

        /* Forced removal from fetch list */
        if (unlikely(force_remove)) {
                reason       = "forced removal";
                should_fetch = 0;
                goto done;
        }

        if (unlikely((rktp->rktp_flags & RD_KAFKA_TOPPAR_F_REMOVE) != 0)) {
                reason       = "partition removed";
                should_fetch = 0;
                goto done;
        }

        /* Skip toppars not in active fetch state */
        if (rktp->rktp_fetch_state != RD_KAFKA_TOPPAR_FETCH_ACTIVE) {
                reason       = "not in active fetch state";
                should_fetch = 0;
                goto done;
        }

        /* Update broker thread's fetch op version */
        version = rktp->rktp_op_version;
        if (rd_kafka_toppar_fetch_decide_start_from_next_fetch_start(rktp)) {
                /* New version barrier, something was modified from the
                 * control plane. Reset and start over.
                 * Alternatively only the next_offset changed but not the
                 * barrier, which is the case when automatically triggering
                 * offset.reset (such as on PARTITION_EOF or
                 * OFFSET_OUT_OF_RANGE). */

                rd_kafka_dbg(
                    rktp->rktp_rkt->rkt_rk, TOPIC, "FETCHDEC",
                    "Topic %s [%" PRId32
                    "]: fetch decide: "
                    "updating to version %d (was %d) at %s "
                    "(was %s)",
                    rktp->rktp_rkt->rkt_topic->str, rktp->rktp_partition,
                    version, rktp->rktp_fetch_version,
                    rd_kafka_fetch_pos2str(rktp->rktp_next_fetch_start),
                    rd_kafka_fetch_pos2str(rktp->rktp_offsets.fetch_pos));

                rd_kafka_offset_stats_reset(&rktp->rktp_offsets);

                /* New start offset */
                rktp->rktp_offsets.fetch_pos     = rktp->rktp_next_fetch_start;
                rktp->rktp_last_next_fetch_start = rktp->rktp_next_fetch_start;

                rktp->rktp_fetch_version = version;

                /* Clear last error to propagate new fetch
                 * errors if encountered. */
                rktp->rktp_last_error = RD_KAFKA_RESP_ERR_NO_ERROR;

                rd_kafka_q_purge_toppar_version(rktp->rktp_fetchq, rktp,
                                                version);
        }


        if (RD_KAFKA_TOPPAR_IS_PAUSED(rktp)) {
                should_fetch = 0;
                reason       = "paused";

        } else if (RD_KAFKA_OFFSET_IS_LOGICAL(
                       rktp->rktp_next_fetch_start.offset)) {
                should_fetch = 0;
                reason       = "no concrete offset";
        } else if (rktp->rktp_ts_fetch_backoff > rd_clock()) {
                reason       = "fetch backed off";
                ts_backoff   = rktp->rktp_ts_fetch_backoff;
                should_fetch = 0;
        } else if (rd_kafka_q_len(rktp->rktp_fetchq) >=
                   rkb->rkb_rk->rk_conf.queued_min_msgs) {
                /* Skip toppars who's local message queue is already above
                 * the lower threshold. */
                reason     = "queued.min.messages exceeded";
                ts_backoff = rd_kafka_toppar_fetch_backoff(
                    rkb, rktp, RD_KAFKA_RESP_ERR__QUEUE_FULL);
                should_fetch = 0;

        } else if ((int64_t)rd_kafka_q_size(rktp->rktp_fetchq) >=
                   rkb->rkb_rk->rk_conf.queued_max_msg_bytes) {
                reason     = "queued.max.messages.kbytes exceeded";
                ts_backoff = rd_kafka_toppar_fetch_backoff(
                    rkb, rktp, RD_KAFKA_RESP_ERR__QUEUE_FULL);
                should_fetch = 0;
        }

done:
        /* Copy offset stats to finalized place holder. */
        rktp->rktp_offsets_fin = rktp->rktp_offsets;

        if (rktp->rktp_fetch != should_fetch) {
                rd_rkb_dbg(
                    rkb, FETCH, "FETCH",
                    "Topic %s [%" PRId32
                    "] in state %s at %s "
                    "(%d/%d msgs, %" PRId64
                    "/%d kb queued, "
                    "opv %" PRId32 ") is %s%s",
                    rktp->rktp_rkt->rkt_topic->str, rktp->rktp_partition,
                    rd_kafka_fetch_states[rktp->rktp_fetch_state],
                    rd_kafka_fetch_pos2str(rktp->rktp_next_fetch_start),
                    rd_kafka_q_len(rktp->rktp_fetchq),
                    rkb->rkb_rk->rk_conf.queued_min_msgs,
                    rd_kafka_q_size(rktp->rktp_fetchq) / 1024,
                    rkb->rkb_rk->rk_conf.queued_max_msg_kbytes,
                    rktp->rktp_fetch_version,
                    should_fetch ? "fetchable" : "not fetchable: ", reason);

                if (should_fetch) {
                        rd_dassert(rktp->rktp_fetch_version > 0);
                        rd_kafka_broker_active_toppar_add(
                            rkb, rktp, *reason ? reason : "fetchable");
                } else {
                        rd_kafka_broker_active_toppar_del(rkb, rktp, reason);
                }
        }

        rd_kafka_toppar_unlock(rktp);

        /* Non-fetching partitions will have an
         * indefinate backoff, unless explicitly specified. */
        if (!should_fetch && !ts_backoff)
                ts_backoff = RD_TS_MAX;

        return ts_backoff;
}
