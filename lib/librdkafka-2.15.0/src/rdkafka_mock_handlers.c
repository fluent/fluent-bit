/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019-2022, Magnus Edenhill,
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
 * Mocks - protocol request handlers
 *
 */

#include "rdkafka_int.h"
#include "rdbuf.h"
#include "rdrand.h"
#include "rdkafka_interceptor.h"
#include "rdkafka_mock_int.h"
#include "rdkafka_transport_int.h"
#include "rdkafka_offset.h"
#include "rdkafka_telemetry_decode.h"



void rd_kafka_mock_Produce_reply_tags_partition_write(
    rd_kafka_buf_t *rkbuf,
    int tagtype,
    rd_kafka_mock_partition_t *mpart) {
        switch (tagtype) {
        case 0: /* CurrentLeader */
                /* Leader id */
                rd_kafka_buf_write_i32(rkbuf, mpart->leader->id);
                /* Leader epoch */
                rd_kafka_buf_write_i32(rkbuf, mpart->leader_epoch);
                /* Field tags */
                rd_kafka_buf_write_tags_empty(rkbuf);
                break;
        default:
                break;
        }
}

void rd_kafka_mock_Produce_reply_tags_write(
    rd_kafka_buf_t *rkbuf,
    int tagtype,
    rd_kafka_mock_broker_t **changed_leaders,
    int changed_leader_cnt) {
        int i;
        switch (tagtype) {
        case 0: /* NodeEndpoints */
                /* #NodeEndpoints */
                rd_kafka_buf_write_arraycnt(rkbuf, changed_leader_cnt);
                for (i = 0; i < changed_leader_cnt; i++) {
                        rd_kafka_mock_broker_t *changed_leader =
                            changed_leaders[i];
                        /* Leader id */
                        rd_kafka_buf_write_i32(rkbuf, changed_leader->id);
                        /* Leader Hostname */
                        rd_kafka_buf_write_str(
                            rkbuf, changed_leader->advertised_listener, -1);

                        /* Leader Port number */
                        rd_kafka_buf_write_i32(rkbuf,
                                               (int32_t)changed_leader->port);

                        /* Leader Rack */
                        rd_kafka_buf_write_str(rkbuf, changed_leader->rack, -1);

                        /* Field tags */
                        rd_kafka_buf_write_tags_empty(rkbuf);
                }
        default:
                break;
        }
}

/**
 * @brief Handle ProduceRequest
 */
static int rd_kafka_mock_handle_Produce(rd_kafka_mock_connection_t *mconn,
                                        rd_kafka_buf_t *rkbuf) {
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        int32_t TopicsCnt;
        rd_kafkap_str_t TransactionalId = RD_KAFKAP_STR_INITIALIZER;
        int16_t Acks;
        int32_t TimeoutMs;
        rd_kafka_resp_err_t all_err;
        int32_t tags_to_write[1] = {0};
        size_t tags_to_write_cnt = 0;
        int changed_leaders_cnt  = 0;
        rd_kafka_mock_broker_t **changed_leaders =
            rd_calloc(mcluster->broker_cnt, sizeof(*changed_leaders));


        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 3)
                rd_kafka_buf_read_str(rkbuf, &TransactionalId);

        rd_kafka_buf_read_i16(rkbuf, &Acks);
        rd_kafka_buf_read_i32(rkbuf, &TimeoutMs);
        /* #Topics */
        rd_kafka_buf_read_arraycnt(rkbuf, &TopicsCnt, RD_KAFKAP_TOPICS_MAX);

        /* Response: #Topics */
        rd_kafka_buf_write_arraycnt(resp, TopicsCnt);

        /* Inject error, if any */
        all_err = rd_kafka_mock_next_request_error(mconn, resp);

        while (TopicsCnt-- > 0) {
                rd_kafkap_str_t Topic;
                int32_t PartitionCnt;
                rd_kafka_mock_topic_t *mtopic;

                rd_kafka_buf_read_str(rkbuf, &Topic);
                rd_kafka_buf_read_arraycnt(rkbuf, &PartitionCnt,
                                           RD_KAFKAP_PARTITIONS_MAX);
                mtopic = rd_kafka_mock_topic_find_by_kstr(mcluster, &Topic);

                /* Response: Topic */
                rd_kafka_buf_write_kstr(resp, &Topic);
                /* Response: #Partitions */
                rd_kafka_buf_write_arraycnt(resp, PartitionCnt);

                while (PartitionCnt-- > 0) {
                        int32_t Partition;
                        rd_kafka_mock_partition_t *mpart = NULL;
                        rd_kafkap_bytes_t records;
                        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;
                        int64_t BaseOffset      = -1;
                        int32_t partition_tags_to_write[1] = {0};
                        size_t partition_tags_to_write_cnt = 0;

                        rd_kafka_buf_read_i32(rkbuf, &Partition);

                        if (mtopic)
                                mpart = rd_kafka_mock_partition_find(mtopic,
                                                                     Partition);

                        rd_kafka_buf_read_kbytes(rkbuf, &records);
                        /* Partition Tags */
                        rd_kafka_buf_skip_tags(rkbuf);
                        /* Response: Partition */
                        rd_kafka_buf_write_i32(resp, Partition);

                        if (all_err)
                                err = all_err;
                        else if (!mpart)
                                err = RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;
                        else if (mpart->leader != mconn->broker)
                                err =
                                    RD_KAFKA_RESP_ERR_NOT_LEADER_FOR_PARTITION;
                        else
                                err =
                                    rd_kafka_mock_partition_next_request_error(
                                        mpart, rkbuf->rkbuf_reqhdr.ApiKey);

                        /* Append to partition log */
                        if (!err)
                                err = rd_kafka_mock_partition_log_append(
                                    mpart, &records, &TransactionalId,
                                    &BaseOffset);

                        /* Response: ErrorCode */
                        rd_kafka_buf_write_i16(resp, err);

                        if (err) {
                                /* Response: BaseOffset */
                                rd_kafka_buf_write_i64(resp, BaseOffset);

                                if (rkbuf->rkbuf_reqhdr.ApiVersion >= 2) {
                                        /* Response: LogAppendTimeMs */
                                        rd_kafka_buf_write_i64(resp, -1);
                                }
                                if (rkbuf->rkbuf_reqhdr.ApiVersion >= 6) {
                                        /* Response: LogStartOffset */
                                        rd_kafka_buf_write_i64(resp, -1);
                                }

                        } else {
                                /* Response: BaseOffset */
                                rd_kafka_buf_write_i64(resp, BaseOffset);

                                if (rkbuf->rkbuf_reqhdr.ApiVersion >= 2) {
                                        /* Response: LogAppendTimeMs */
                                        rd_kafka_buf_write_i64(resp, 1234);
                                }
                                if (rkbuf->rkbuf_reqhdr.ApiVersion >= 6) {
                                        /* Response: LogStartOffset */
                                        rd_kafka_buf_write_i64(
                                            resp, mpart->start_offset);
                                }
                        }

                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 8) {
                                /* Response: #RecordErrors
                                 * TODO: Add support for injecting RecordErrors
                                 * 0 record errors for now */
                                rd_kafka_buf_write_arraycnt(resp, 0);

                                /* Response: ErrorMessage */
                                rd_kafka_buf_write_str(resp, NULL, 0);
                        }

                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 10 &&
                            err == RD_KAFKA_RESP_ERR_NOT_LEADER_FOR_PARTITION) {
                                int changed_leader_idx;
                                /* See if this leader is already included */
                                for (changed_leader_idx = 0;
                                     changed_leader_idx < changed_leaders_cnt;
                                     changed_leader_idx++) {
                                        if (changed_leaders[changed_leader_idx]
                                                ->id == mpart->leader->id)
                                                break;
                                }
                                if (changed_leader_idx == changed_leaders_cnt) {
                                        /* Add the new leader that wasn't
                                         * present */
                                        changed_leaders[changed_leaders_cnt] =
                                            mpart->leader;
                                        changed_leaders_cnt++;
                                }

                                partition_tags_to_write
                                    [partition_tags_to_write_cnt] =
                                        0 /* CurrentLeader */;
                                partition_tags_to_write_cnt++;
                        }

                        /* Response: Partition tags */
                        rd_kafka_buf_write_tags(
                            resp,
                            rd_kafka_mock_Produce_reply_tags_partition_write,
                            partition_tags_to_write,
                            partition_tags_to_write_cnt, mpart);
                }

                /* Topic tags */
                rd_kafka_buf_skip_tags(rkbuf);
                /* Response: Topic tags */
                rd_kafka_buf_write_tags_empty(resp);
        }

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1) {
                /* Response: ThrottleTime */
                rd_kafka_buf_write_i32(resp, 0);
        }

        /* Response: Top level tags */
        if (changed_leaders_cnt) {
                tags_to_write[tags_to_write_cnt] = 0 /* NodeEndpoints */;
                tags_to_write_cnt++;
        }

        rd_kafka_buf_write_tags(resp, rd_kafka_mock_Produce_reply_tags_write,
                                tags_to_write, tags_to_write_cnt,
                                changed_leaders, changed_leaders_cnt);

        rd_kafka_mock_connection_send_response0(mconn, resp, rd_true);
        rd_free(changed_leaders);
        return 0;

err_parse:
        rd_free(changed_leaders);
        rd_kafka_buf_destroy(resp);
        return -1;
}

void rd_kafka_mock_Fetch_reply_tags_partition_write(
    rd_kafka_buf_t *rkbuf,
    int tagtype,
    rd_kafka_mock_partition_t *mpart) {
        switch (tagtype) {
        case 1: /* CurrentLeader */
        {
                int32_t leader_id    = mpart->leader->id,
                        leader_epoch = mpart->leader_epoch;
                rd_kafka_mock_partition_leader_t *mpart_leader =
                    rd_kafka_mock_partition_next_leader_response(mpart);
                if (mpart_leader) {
                        leader_id    = mpart_leader->leader_id;
                        leader_epoch = mpart_leader->leader_epoch;
                        rd_kafka_mock_partition_leader_destroy(mpart,
                                                               mpart_leader);
                }

                /* Leader id */
                rd_kafka_buf_write_i32(rkbuf, leader_id);
                /* Leader epoch */
                rd_kafka_buf_write_i32(rkbuf, leader_epoch);
                /* Field tags */
                rd_kafka_buf_write_tags_empty(rkbuf);
                break;
        }
        default:
                break;
        }
}

void rd_kafka_mock_Fetch_reply_tags_write(
    rd_kafka_buf_t *rkbuf,
    int tagtype,
    rd_kafka_mock_broker_t **changed_leaders,
    int changed_leader_cnt) {
        int i;
        switch (tagtype) {
        case 0: /* NodeEndpoints */
                /* #NodeEndpoints */
                rd_kafka_buf_write_arraycnt(rkbuf, changed_leader_cnt);
                for (i = 0; i < changed_leader_cnt; i++) {
                        rd_kafka_mock_broker_t *changed_leader =
                            changed_leaders[i];
                        /* Leader id */
                        rd_kafka_buf_write_i32(rkbuf, changed_leader->id);
                        /* Leader Hostname */
                        rd_kafka_buf_write_str(
                            rkbuf, changed_leader->advertised_listener, -1);

                        /* Leader Port number */
                        rd_kafka_buf_write_i32(rkbuf,
                                               (int32_t)changed_leader->port);

                        /* Leader Rack */
                        rd_kafka_buf_write_str(rkbuf, changed_leader->rack, -1);

                        /* Field tags */
                        rd_kafka_buf_write_tags_empty(rkbuf);
                }
        default:
                break;
        }
}


/**
 * @brief Handle FetchRequest
 */
static int rd_kafka_mock_handle_Fetch(rd_kafka_mock_connection_t *mconn,
                                      rd_kafka_buf_t *rkbuf) {
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafka_resp_err_t all_err;
        int32_t ReplicaId = -1, MaxWait, MinBytes, MaxBytes = -1,
                SessionId = -1, Epoch, TopicsCnt;
        int8_t IsolationLevel;
        size_t totsize = 0;

        int32_t tags_to_write[1]   = {0};
        uint64_t tags_to_write_cnt = 0;

        int changed_leaders_cnt = 0;
        rd_kafka_mock_broker_t **changed_leaders =
            rd_calloc(mcluster->broker_cnt, sizeof(*changed_leaders));

        if (rkbuf->rkbuf_reqhdr.ApiVersion <= 14) {
                rd_kafka_buf_read_i32(rkbuf, &ReplicaId);
        }
        rd_kafka_buf_read_i32(rkbuf, &MaxWait);
        rd_kafka_buf_read_i32(rkbuf, &MinBytes);
        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 3)
                rd_kafka_buf_read_i32(rkbuf, &MaxBytes);
        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 4)
                rd_kafka_buf_read_i8(rkbuf, &IsolationLevel);
        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 7) {
                rd_kafka_buf_read_i32(rkbuf, &SessionId);
                rd_kafka_buf_read_i32(rkbuf, &Epoch);
        }

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1) {
                /* Response: ThrottleTime */
                rd_kafka_buf_write_i32(resp, 0);
        }


        /* Inject error, if any */
        all_err = rd_kafka_mock_next_request_error(mconn, resp);

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 7) {
                /* Response: ErrorCode */
                rd_kafka_buf_write_i16(resp, all_err);

                /* Response: SessionId */
                rd_kafka_buf_write_i32(resp, SessionId);
        }

        rd_kafka_buf_read_arraycnt(rkbuf, &TopicsCnt, RD_KAFKAP_TOPICS_MAX);

        /* Response: #Topics */
        rd_kafka_buf_write_arraycnt(resp, TopicsCnt);

        while (TopicsCnt-- > 0) {
                rd_kafkap_str_t Topic   = RD_KAFKAP_STR_INITIALIZER;
                rd_kafka_Uuid_t TopicId = RD_KAFKA_UUID_ZERO;
                int32_t PartitionCnt;
                rd_kafka_mock_topic_t *mtopic;
                rd_bool_t find_topic_by_id = rd_true;

                if (rkbuf->rkbuf_reqhdr.ApiVersion <= 12) {
                        rd_kafka_buf_read_str(rkbuf, &Topic);
                        find_topic_by_id = rd_false;
                }

                if (rkbuf->rkbuf_reqhdr.ApiVersion >= 13) {
                        rd_kafka_buf_read_uuid(rkbuf, &TopicId);
                }

                rd_kafka_buf_read_arraycnt(rkbuf, &PartitionCnt,
                                           RD_KAFKAP_PARTITIONS_MAX);

                if (find_topic_by_id) {
                        mtopic =
                            rd_kafka_mock_topic_find_by_id(mcluster, TopicId);
                        /* Response: TopicId */
                        rd_kafka_buf_write_uuid(resp, &TopicId);
                } else {
                        mtopic =
                            rd_kafka_mock_topic_find_by_kstr(mcluster, &Topic);
                        /* Response: Topic */
                        rd_kafka_buf_write_kstr(resp, &Topic);
                }

                /* Response: #Partitions */
                rd_kafka_buf_write_arraycnt(resp, PartitionCnt);

                while (PartitionCnt-- > 0) {
                        int32_t Partition, CurrentLeaderEpoch = -1,
                                           LastFetchedEpoch = -1, PartMaxBytes;
                        int64_t FetchOffset, LogStartOffset;
                        rd_kafka_mock_partition_t *mpart = NULL;
                        rd_kafka_resp_err_t err          = all_err;
                        rd_bool_t on_follower;
                        size_t partsize                      = 0;
                        const rd_kafka_mock_msgset_t *mset   = NULL;
                        int32_t partition_tags_to_write[1]   = {0};
                        uint64_t partition_tags_to_write_cnt = 0;

                        rd_kafka_buf_read_i32(rkbuf, &Partition);

                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 9)
                                rd_kafka_buf_read_i32(rkbuf,
                                                      &CurrentLeaderEpoch);

                        rd_kafka_buf_read_i64(rkbuf, &FetchOffset);

                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 12)
                                rd_kafka_buf_read_i32(rkbuf, &LastFetchedEpoch);

                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 5)
                                rd_kafka_buf_read_i64(rkbuf, &LogStartOffset);

                        rd_kafka_buf_read_i32(rkbuf, &PartMaxBytes);

                        /* Partition tags */
                        rd_kafka_buf_skip_tags(rkbuf);

                        if (mtopic)
                                mpart = rd_kafka_mock_partition_find(mtopic,
                                                                     Partition);
                        else if (find_topic_by_id)
                                err = RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_ID;

                        /* Response: Partition */
                        rd_kafka_buf_write_i32(resp, Partition);

                        /* Fetch is directed at follower and this is
                         * the follower broker. */
                        on_follower =
                            mpart && mpart->follower_id == mconn->broker->id;

                        if (!err) {
                                if (!all_err && !mpart)
                                        err =
                                            RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;
                                else if (!all_err &&
                                         mpart->leader != mconn->broker &&
                                         !on_follower)
                                        err =
                                            RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER;
                        }

                        if (!err && mpart)
                                err =
                                    rd_kafka_mock_partition_leader_epoch_check(
                                        mpart, CurrentLeaderEpoch);

                        if (!err && mpart)
                                err =
                                    rd_kafka_mock_partition_next_request_error(
                                        mpart, rkbuf->rkbuf_reqhdr.ApiKey);

                        /* Find MessageSet for FetchOffset */
                        if (!err && FetchOffset != mpart->end_offset) {
                                /* Kafka currently only returns
                                 * OFFSET_NOT_AVAILABLE
                                 * in ListOffsets calls */
                                if (!(mset = rd_kafka_mock_msgset_find(
                                          mpart, FetchOffset, on_follower)))
                                        err =
                                            RD_KAFKA_RESP_ERR_OFFSET_OUT_OF_RANGE;
                                rd_kafka_dbg(
                                    mcluster->rk, MOCK, "MOCK",
                                    "Topic %.*s [%" PRId32
                                    "] fetch err %s for offset %" PRId64
                                    " mset %p, on_follower %d, "
                                    "start %" PRId64 ", end_offset %" PRId64
                                    ", current epoch %" PRId32,
                                    RD_KAFKAP_STR_PR(&Topic), Partition,
                                    rd_kafka_err2name(err), FetchOffset, mset,
                                    on_follower, mpart->start_offset,
                                    mpart->end_offset, mpart->leader_epoch);
                        }


                        /* Response: ErrorCode */
                        rd_kafka_buf_write_i16(resp, err);

                        /* Response: Highwatermark */
                        rd_kafka_buf_write_i64(
                            resp,
                            mpart ? (on_follower ? mpart->follower_end_offset
                                                 : mpart->end_offset)
                                  : -1);

                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 4) {
                                /* Response: LastStableOffset */
                                rd_kafka_buf_write_i64(
                                    resp, mpart ? mpart->end_offset : -1);
                        }

                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 5) {
                                /* Response: LogStartOffset */
                                rd_kafka_buf_write_i64(
                                    resp,
                                    !mpart ? -1
                                           : (on_follower
                                                  ? mpart->follower_start_offset
                                                  : mpart->start_offset));
                        }

                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 4) {
                                /* Response: #Aborted */
                                rd_kafka_buf_write_arraycnt(resp, 0);
                        }


                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 11) {
                                int32_t PreferredReadReplica =
                                    mpart && mpart->leader == mconn->broker &&
                                            mpart->follower_id != -1
                                        ? mpart->follower_id
                                        : -1;

                                /* Response: PreferredReplica */
                                rd_kafka_buf_write_i32(resp,
                                                       PreferredReadReplica);

                                if (PreferredReadReplica != -1) {
                                        /* Don't return any data when
                                         * PreferredReadReplica is set */
                                        mset    = NULL;
                                        MaxWait = 0;
                                }
                        }


                        if (mset && partsize < (size_t)PartMaxBytes &&
                            totsize < (size_t)MaxBytes) {
                                /* Response: Records */
                                size_t written = rd_kafka_buf_write_kbytes(
                                    resp, &mset->bytes);
                                partsize += written;
                                totsize += written;

                                /* FIXME: Multiple messageSets ? */
                        } else {
                                /* Empty Response: Records: Null */
                                rd_kafka_buf_write_arraycnt(resp, 0);
                        }

                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 12 &&
                            err == RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER) {
                                int changed_leader_idx;
                                for (changed_leader_idx = 0;
                                     changed_leader_idx < changed_leaders_cnt;
                                     changed_leader_idx++) {
                                        if (changed_leaders[changed_leader_idx]
                                                ->id == mpart->leader->id)
                                                break;
                                }
                                if (changed_leader_idx == changed_leaders_cnt) {
                                        changed_leaders[changed_leaders_cnt] =
                                            mpart->leader;
                                        changed_leaders_cnt++;
                                }
                                /* CurrentLeader */
                                partition_tags_to_write
                                    [partition_tags_to_write_cnt] = 1;
                                partition_tags_to_write_cnt++;
                        }

                        /* Response: Partition tags */
                        rd_kafka_buf_write_tags(
                            resp,
                            rd_kafka_mock_Fetch_reply_tags_partition_write,
                            partition_tags_to_write,
                            partition_tags_to_write_cnt, mpart);
                }

                /* Topic tags */
                rd_kafka_buf_skip_tags(rkbuf);
                /* Response: Topic tags */
                rd_kafka_buf_write_tags_empty(resp);
        }

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 7) {
                int32_t ForgottenTopicCnt;
                rd_kafka_buf_read_arraycnt(rkbuf, &ForgottenTopicCnt,
                                           RD_KAFKAP_TOPICS_MAX);
                while (ForgottenTopicCnt-- > 0) {
                        rd_kafkap_str_t Topic   = RD_KAFKAP_STR_INITIALIZER;
                        rd_kafka_Uuid_t TopicId = RD_KAFKA_UUID_ZERO;
                        int32_t ForgPartCnt;
                        if (rkbuf->rkbuf_reqhdr.ApiVersion <= 12) {
                                rd_kafka_buf_read_str(rkbuf, &Topic);
                        }
                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 13) {
                                rd_kafka_buf_read_uuid(rkbuf, &TopicId);
                        }
                        rd_kafka_buf_read_arraycnt(rkbuf, &ForgPartCnt,
                                                   RD_KAFKAP_PARTITIONS_MAX);
                        while (ForgPartCnt-- > 0) {
                                int32_t Partition;
                                rd_kafka_buf_read_i32(rkbuf, &Partition);
                        }

                        /* ForgottenTopic tags */
                        rd_kafka_buf_skip_tags(rkbuf);
                }
        }

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 11) {
                rd_kafkap_str_t RackId;
                char *rack;
                rd_kafka_buf_read_str(rkbuf, &RackId);
                RD_KAFKAP_STR_DUPA(&rack, &RackId);
                /* Matt might do something sensible with this */
        }

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 16 && changed_leaders_cnt) {
                tags_to_write[tags_to_write_cnt] = 0 /* NodeEndpoints */;
                tags_to_write_cnt++;
        }

        /* Response: Top level tags */
        rd_kafka_buf_write_tags(resp, rd_kafka_mock_Fetch_reply_tags_write,
                                tags_to_write, tags_to_write_cnt,
                                changed_leaders, changed_leaders_cnt);

        /* If there was no data, delay up to MaxWait.
         * This isn't strictly correct since we should cut the wait short
         * and feed newly produced data if a producer writes to the
         * partitions, but that is too much of a hassle here since we
         * can't block the thread. */
        if (!totsize && MaxWait > 0)
                resp->rkbuf_ts_retry = rd_clock() + (MaxWait * 1000);

        rd_kafka_mock_connection_send_response0(mconn, resp, rd_true);
        rd_free(changed_leaders);
        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        rd_free(changed_leaders);
        return -1;
}



/**
 * @brief Handle ListOffsets
 */
static int rd_kafka_mock_handle_ListOffsets(rd_kafka_mock_connection_t *mconn,
                                            rd_kafka_buf_t *rkbuf) {
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafka_resp_err_t all_err;
        int32_t ReplicaId, TopicsCnt;
        int8_t IsolationLevel;

        rd_kafka_buf_read_i32(rkbuf, &ReplicaId);
        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 2)
                rd_kafka_buf_read_i8(rkbuf, &IsolationLevel);

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 2) {
                /* Response: ThrottleTime */
                rd_kafka_buf_write_i32(resp, 0);
        }


        /* Inject error, if any */
        all_err = rd_kafka_mock_next_request_error(mconn, resp);

        rd_kafka_buf_read_arraycnt(rkbuf, &TopicsCnt, RD_KAFKAP_TOPICS_MAX);

        /* Response: #Topics */
        rd_kafka_buf_write_arraycnt(resp, TopicsCnt);

        while (TopicsCnt-- > 0) {
                rd_kafkap_str_t Topic;
                int32_t PartitionCnt;
                rd_kafka_mock_topic_t *mtopic;

                rd_kafka_buf_read_str(rkbuf, &Topic);
                rd_kafka_buf_read_arraycnt(rkbuf, &PartitionCnt,
                                           RD_KAFKAP_PARTITIONS_MAX);

                mtopic = rd_kafka_mock_topic_find_by_kstr(mcluster, &Topic);

                /* Response: Topic */
                rd_kafka_buf_write_kstr(resp, &Topic);
                /* Response: #Partitions */
                rd_kafka_buf_write_arraycnt(resp, PartitionCnt);

                while (PartitionCnt-- > 0) {
                        int32_t Partition, CurrentLeaderEpoch = -1;
                        int64_t Timestamp, Offset             = -1;
                        int32_t MaxNumOffsets;
                        rd_kafka_mock_partition_t *mpart = NULL;
                        rd_kafka_resp_err_t err          = all_err;

                        rd_kafka_buf_read_i32(rkbuf, &Partition);

                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 4)
                                rd_kafka_buf_read_i32(rkbuf,
                                                      &CurrentLeaderEpoch);

                        rd_kafka_buf_read_i64(rkbuf, &Timestamp);

                        if (rkbuf->rkbuf_reqhdr.ApiVersion == 0)
                                rd_kafka_buf_read_i32(rkbuf, &MaxNumOffsets);

                        /* Partition tags */
                        rd_kafka_buf_skip_tags(rkbuf);

                        if (mtopic)
                                mpart = rd_kafka_mock_partition_find(mtopic,
                                                                     Partition);

                        /* Response: Partition */
                        rd_kafka_buf_write_i32(resp, Partition);

                        if (!all_err && !mpart)
                                err = RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;
                        else if (!all_err && mpart->leader != mconn->broker)
                                err =
                                    RD_KAFKA_RESP_ERR_NOT_LEADER_FOR_PARTITION;

                        if (!err && mpart)
                                err =
                                    rd_kafka_mock_partition_leader_epoch_check(
                                        mpart, CurrentLeaderEpoch);

                        /* Response: ErrorCode */
                        rd_kafka_buf_write_i16(resp, err);

                        if (!err && mpart) {
                                if (Timestamp == RD_KAFKA_OFFSET_BEGINNING)
                                        Offset = mpart->start_offset;
                                else if (Timestamp == RD_KAFKA_OFFSET_END)
                                        Offset = mpart->end_offset;
                                else if (Timestamp < 0)
                                        Offset = -1;
                                else /* FIXME: by timestamp */
                                        Offset = -1;
                        }

                        if (rkbuf->rkbuf_reqhdr.ApiVersion == 0) {
                                /* Response: #OldStyleOffsets */
                                rd_kafka_buf_write_i32(resp,
                                                       Offset != -1 ? 1 : 0);
                                /* Response: OldStyleOffsets[0] */
                                if (Offset != -1)
                                        rd_kafka_buf_write_i64(resp, Offset);
                        } else {
                                /* Response: Timestamp (FIXME) */
                                rd_kafka_buf_write_i64(resp, -1);

                                /* Response: Offset */
                                rd_kafka_buf_write_i64(resp, Offset);
                        }

                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 4) {
                                /* Response: LeaderEpoch */
                                const rd_kafka_mock_msgset_t *mset = NULL;
                                int32_t leader_epoch               = -1;
                                rd_bool_t on_follower              = rd_false;

                                if (mpart) {
                                        on_follower =
                                            mpart && mpart->follower_id ==
                                                         mconn->broker->id;

                                        if (Offset >= 0 &&
                                            (mset = rd_kafka_mock_msgset_find(
                                                 mpart, Offset, on_follower))) {
                                                leader_epoch =
                                                    mset->leader_epoch;
                                        }
                                }

                                rd_kafka_buf_write_i32(resp, leader_epoch);
                        }

                        /* Response: Partition tags */
                        rd_kafka_buf_write_tags_empty(resp);

                        rd_kafka_dbg(mcluster->rk, MOCK, "MOCK",
                                     "Topic %.*s [%" PRId32
                                     "] returning "
                                     "offset %" PRId64 " (leader epoch %" PRId32
                                     ") for %s: %s",
                                     RD_KAFKAP_STR_PR(&Topic), Partition,
                                     Offset, mpart ? mpart->leader_epoch : -1,
                                     rd_kafka_offset2str(Timestamp),
                                     rd_kafka_err2str(err));
                }

                /* Topic tags */
                rd_kafka_buf_skip_tags(rkbuf);
                /* Response: Topic tags */
                rd_kafka_buf_write_tags_empty(resp);
        }


        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}


/**
 * @brief Handle OffsetFetch (fetch committed offsets)
 */
static int rd_kafka_mock_handle_OffsetFetch(rd_kafka_mock_connection_t *mconn,
                                            rd_kafka_buf_t *rkbuf) {
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafka_mock_broker_t *mrkb;
        rd_kafka_resp_err_t all_err;
        int32_t TopicsCnt;
        rd_kafkap_str_t GroupId;

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 3) {
                /* Response: ThrottleTime */
                rd_kafka_buf_write_i32(resp, 0);
        }

        rd_kafka_buf_read_str(rkbuf, &GroupId);

        /* Inject error, if any */
        all_err = rd_kafka_mock_next_request_error(mconn, resp);

        mrkb = rd_kafka_mock_cluster_get_coord(mcluster, RD_KAFKA_COORD_GROUP,
                                               &GroupId);
        if (!mrkb && !all_err)
                all_err = RD_KAFKA_RESP_ERR_NOT_COORDINATOR;  // FIXME? check if
                                                              // its this mrkb?


        rd_kafka_buf_read_arraycnt(rkbuf, &TopicsCnt, 100000);

        /* Response: #Topics */
        rd_kafka_buf_write_arraycnt(resp, TopicsCnt);

        while (TopicsCnt-- > 0) {
                rd_kafkap_str_t Topic;
                int32_t PartitionCnt;
                rd_kafka_mock_topic_t *mtopic;

                rd_kafka_buf_read_str(rkbuf, &Topic);
                rd_kafka_buf_read_arraycnt(rkbuf, &PartitionCnt, 100000);

                mtopic = rd_kafka_mock_topic_find_by_kstr(mcluster, &Topic);

                /* Response: Topic */
                rd_kafka_buf_write_kstr(resp, &Topic);
                /* Response: #Partitions */
                rd_kafka_buf_write_arraycnt(resp, PartitionCnt);

                while (PartitionCnt-- > 0) {
                        int32_t Partition;
                        rd_kafka_mock_partition_t *mpart             = NULL;
                        const rd_kafka_mock_committed_offset_t *coff = NULL;
                        rd_kafka_resp_err_t err                      = all_err;

                        rd_kafka_buf_read_i32(rkbuf, &Partition);

                        if (mtopic)
                                mpart = rd_kafka_mock_partition_find(mtopic,
                                                                     Partition);

                        /* Response: Partition */
                        rd_kafka_buf_write_i32(resp, Partition);

                        if (!all_err && !mpart)
                                err = RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;

                        if (!err)
                                coff = rd_kafka_mock_committed_offset_find(
                                    mpart, &GroupId);

                        /* Response: CommittedOffset */
                        rd_kafka_buf_write_i64(resp, coff ? coff->offset : -1);

                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 5) {
                                /* Response: CommittedLeaderEpoch */
                                rd_kafka_buf_write_i32(
                                    resp, mpart ? mpart->leader_epoch : -1);
                        }

                        /* Response: Metadata */
                        rd_kafka_buf_write_kstr(resp,
                                                coff ? coff->metadata : NULL);

                        /* Response: ErrorCode */
                        rd_kafka_buf_write_i16(resp, err);

                        /* Response: Struct tags */
                        rd_kafka_buf_write_tags_empty(resp);

                        if (coff)
                                rd_kafka_dbg(mcluster->rk, MOCK, "MOCK",
                                             "Topic %s [%" PRId32
                                             "] returning "
                                             "committed offset %" PRId64
                                             " for group %s",
                                             mtopic->name, mpart->id,
                                             coff->offset, coff->group);
                        else
                                rd_kafka_dbg(mcluster->rk, MOCK, "MOCK",
                                             "Topic %.*s [%" PRId32
                                             "] has no "
                                             "committed offset for group %.*s: "
                                             "%s",
                                             RD_KAFKAP_STR_PR(&Topic),
                                             Partition,
                                             RD_KAFKAP_STR_PR(&GroupId),
                                             rd_kafka_err2str(err));
                }

                /* Request: Skip struct tags */
                rd_kafka_buf_skip_tags(rkbuf);

                /* Response: Struct tags */
                rd_kafka_buf_write_tags_empty(resp);
        }

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 2) {
                /* Response: Outer ErrorCode */
                rd_kafka_buf_write_i16(resp, all_err);
        }


        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}



/**
 * @brief Handle OffsetCommit
 */
static int rd_kafka_mock_handle_OffsetCommit(rd_kafka_mock_connection_t *mconn,
                                             rd_kafka_buf_t *rkbuf) {
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafka_mock_broker_t *mrkb;
        rd_kafka_resp_err_t all_err;
        int32_t GenerationIdOrMemberEpoch = -1, TopicsCnt;
        rd_kafkap_str_t GroupId, MemberId, GroupInstanceId;

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 3) {
                /* Response: ThrottleTime */
                rd_kafka_buf_write_i32(resp, 0);
        }

        rd_kafka_buf_read_str(rkbuf, &GroupId);

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1) {
                rd_kafka_buf_read_i32(rkbuf, &GenerationIdOrMemberEpoch);
                rd_kafka_buf_read_str(rkbuf, &MemberId);
        }

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 7)
                rd_kafka_buf_read_str(rkbuf, &GroupInstanceId);

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 2 &&
            rkbuf->rkbuf_reqhdr.ApiVersion <= 4) {
                int64_t RetentionTimeMs;
                rd_kafka_buf_read_i64(rkbuf, &RetentionTimeMs);
        }


        /* Inject error, if any */
        all_err = rd_kafka_mock_next_request_error(mconn, resp);

        mrkb = rd_kafka_mock_cluster_get_coord(mcluster, RD_KAFKA_COORD_GROUP,
                                               &GroupId);
        if (!mrkb && !all_err)
                all_err = RD_KAFKA_RESP_ERR_NOT_COORDINATOR;


        if (!all_err) {
                rd_kafka_mock_cgrp_classic_t *mcgrp_classic;

                mcgrp_classic =
                    rd_kafka_mock_cgrp_classic_find(mcluster, &GroupId);
                if (mcgrp_classic) {
                        rd_kafka_mock_cgrp_classic_member_t *member = NULL;

                        if (!RD_KAFKAP_STR_IS_NULL(&MemberId))
                                member = rd_kafka_mock_cgrp_classic_member_find(
                                    mcgrp_classic, &MemberId);

                        if (!member)
                                all_err = RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID;
                        else
                                all_err =
                                    rd_kafka_mock_cgrp_classic_check_state(
                                        mcgrp_classic, member, rkbuf,
                                        GenerationIdOrMemberEpoch);
                } else {
                        rd_kafka_mock_cgrp_consumer_t *mcgrp_consumer;
                        rd_kafka_mock_cgrp_consumer_member_t *member = NULL;

                        mcgrp_consumer = rd_kafka_mock_cgrp_consumer_find(
                            mcluster, &GroupId);
                        if (mcgrp_consumer) {
                                if (!RD_KAFKAP_STR_IS_NULL(&MemberId))
                                        member =
                                            rd_kafka_mock_cgrp_consumer_member_find(
                                                mcgrp_consumer, &MemberId);

                                if (!member)
                                        all_err =
                                            RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID;
                                else
                                        all_err =
                                            GenerationIdOrMemberEpoch !=
                                                    member->current_member_epoch
                                                ? RD_KAFKA_RESP_ERR_STALE_MEMBER_EPOCH
                                                : RD_KAFKA_RESP_ERR_NO_ERROR;
                        }
                }

                /* As happens here, a real broker doesn't check that partitions
                 * are assigned to the member, but only the GenerationId. */
        }

        rd_kafka_buf_read_arraycnt(rkbuf, &TopicsCnt, RD_KAFKAP_TOPICS_MAX);

        /* Response: #Topics */
        rd_kafka_buf_write_arraycnt(resp, TopicsCnt);

        while (TopicsCnt-- > 0) {
                rd_kafkap_str_t Topic;
                int32_t PartitionCnt;
                rd_kafka_mock_topic_t *mtopic;

                rd_kafka_buf_read_str(rkbuf, &Topic);
                rd_kafka_buf_read_arraycnt(rkbuf, &PartitionCnt,
                                           RD_KAFKAP_PARTITIONS_MAX);

                mtopic = rd_kafka_mock_topic_find_by_kstr(mcluster, &Topic);

                /* Response: Topic */
                rd_kafka_buf_write_kstr(resp, &Topic);
                /* Response: #Partitions */
                rd_kafka_buf_write_arraycnt(resp, PartitionCnt);

                while (PartitionCnt-- > 0) {
                        int32_t Partition;
                        rd_kafka_mock_partition_t *mpart = NULL;
                        rd_kafka_resp_err_t err          = all_err;
                        int64_t CommittedOffset;
                        rd_kafkap_str_t Metadata;

                        rd_kafka_buf_read_i32(rkbuf, &Partition);

                        if (mtopic)
                                mpart = rd_kafka_mock_partition_find(mtopic,
                                                                     Partition);

                        /* Response: Partition */
                        rd_kafka_buf_write_i32(resp, Partition);

                        if (!all_err && !mpart)
                                err = RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;

                        rd_kafka_buf_read_i64(rkbuf, &CommittedOffset);

                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 6) {
                                int32_t CommittedLeaderEpoch;
                                rd_kafka_buf_read_i32(rkbuf,
                                                      &CommittedLeaderEpoch);

                                if (!err && mpart)
                                        err =
                                            rd_kafka_mock_partition_leader_epoch_check(
                                                mpart, CommittedLeaderEpoch);
                        }

                        if (rkbuf->rkbuf_reqhdr.ApiVersion == 1) {
                                int64_t CommitTimestamp;
                                rd_kafka_buf_read_i64(rkbuf, &CommitTimestamp);
                        }

                        rd_kafka_buf_read_str(rkbuf, &Metadata);
                        rd_kafka_buf_skip_tags(rkbuf);

                        if (!err)
                                rd_kafka_mock_commit_offset(mpart, &GroupId,
                                                            CommittedOffset,
                                                            &Metadata);

                        /* Response: ErrorCode */
                        rd_kafka_buf_write_i16(resp, err);
                        rd_kafka_buf_write_tags_empty(resp);
                }
                rd_kafka_buf_skip_tags(rkbuf);
                rd_kafka_buf_write_tags_empty(resp);
        }

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}



/**
 * @brief Handle ApiVersionRequest
 */
static int rd_kafka_mock_handle_ApiVersion(rd_kafka_mock_connection_t *mconn,
                                           rd_kafka_buf_t *rkbuf);


/**
 * @brief Write a MetadataResponse.Topics. entry to \p resp.
 *
 * @param mtopic may be NULL
 */
static void
rd_kafka_mock_buf_write_Metadata_Topic(rd_kafka_mock_cluster_t *mcluster,
                                       rd_kafka_buf_t *resp,
                                       int16_t ApiVersion,
                                       rd_kafka_Uuid_t topic_id,
                                       const char *topic,
                                       const rd_kafka_mock_topic_t *mtopic,
                                       rd_kafka_resp_err_t err) {
        int i;
        int partition_cnt =
            (!mtopic || err == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART ||
             err == RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_ID)
                ? 0
                : mtopic->partition_cnt;

        /* Response: Topics.ErrorCode */
        rd_kafka_buf_write_i16(resp, err);
        /* Response: Topics.Name */
        rd_kafka_buf_write_str(resp, topic, -1);

        if (ApiVersion >= 10) {
                /* Response: Topics.TopicId */
                rd_kafka_buf_write_uuid(resp, &topic_id);
        }

        if (ApiVersion >= 1) {
                /* Response: Topics.IsInternal */
                rd_kafka_buf_write_bool(resp, rd_false);
        }
        /* Response: Topics.#Partitions */
        rd_kafka_buf_write_arraycnt(resp, partition_cnt);

        for (i = 0; mtopic && i < partition_cnt; i++) {
                rd_kafka_mock_partition_leader_t *mpart_leader;
                rd_kafka_mock_partition_t *mpart = &mtopic->partitions[i];
                int r;

                /* Response: ..Partitions.ErrorCode */
                rd_kafka_buf_write_i16(resp, 0);
                /* Response: ..Partitions.PartitionIndex */
                rd_kafka_buf_write_i32(resp, mpart->id);

                mpart_leader =
                    rd_kafka_mock_partition_next_leader_response(mpart);
                if (mpart_leader) {
                        rd_kafka_dbg(
                            mcluster->rk, MOCK, "MOCK",
                            "MetadataRequest: using next leader response "
                            "(%" PRId32 ", %" PRId32 ")",
                            mpart_leader->leader_id,
                            mpart_leader->leader_epoch);

                        /* Response: ..Partitions.Leader */
                        rd_kafka_buf_write_i32(resp, mpart_leader->leader_id);

                        if (ApiVersion >= 7) {
                                /* Response: ..Partitions.LeaderEpoch */
                                rd_kafka_buf_write_i32(
                                    resp, mpart_leader->leader_epoch);
                        }
                        rd_kafka_mock_partition_leader_destroy(mpart,
                                                               mpart_leader);
                        mpart_leader = NULL;
                } else {
                        /* Response: ..Partitions.Leader */
                        rd_kafka_buf_write_i32(
                            resp, mpart->leader ? mpart->leader->id : -1);

                        if (ApiVersion >= 7) {
                                /* Response: ..Partitions.LeaderEpoch */
                                rd_kafka_buf_write_i32(resp,
                                                       mpart->leader_epoch);
                        }
                }

                /* Response: ..Partitions.#ReplicaNodes */
                rd_kafka_buf_write_arraycnt(resp, mpart->replica_cnt);
                for (r = 0; r < mpart->replica_cnt; r++)
                        rd_kafka_buf_write_i32(resp, mpart->replicas[r]->id);

                /* Response: ..Partitions.#IsrNodes */
                /* Let Replicas == ISRs for now */
                rd_kafka_buf_write_arraycnt(resp, mpart->replica_cnt);
                for (r = 0; r < mpart->replica_cnt; r++)
                        rd_kafka_buf_write_i32(resp, mpart->replicas[r]->id);

                if (ApiVersion >= 5) {
                        /* Response: ...OfflineReplicas */
                        rd_kafka_buf_write_arraycnt(resp, 0);
                }

                rd_kafka_buf_write_tags_empty(resp);
        }

        if (ApiVersion >= 8) {
                /* Response: Topics.TopicAuthorizedOperations */
                rd_kafka_buf_write_i32(resp, INT32_MIN);
        }

        rd_kafka_buf_write_tags_empty(resp);
}


/**
 * @brief Handle MetadataRequest
 */
static int rd_kafka_mock_handle_Metadata(rd_kafka_mock_connection_t *mconn,
                                         rd_kafka_buf_t *rkbuf) {
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_bool_t AllowAutoTopicCreation  = rd_true;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        const rd_kafka_mock_broker_t *mrkb;
        rd_kafka_topic_partition_list_t *requested_topics = NULL;
        rd_bool_t list_all_topics                         = rd_false;
        int32_t TopicsCnt;
        int i;
        size_t of_Brokers_cnt;
        int32_t response_Brokers_cnt = 0;

        /* Consume the next pushed err+rtt for ApiKey=Metadata so an
         * injected RTT (or __TRANSPORT close) on this connection takes
         * effect. The returned err code is not propagated into the
         * response body (Metadata's error reporting is per-topic and
         * per-partition; tests that need to inject a topic-level
         * MetadataResponse error should use the dedicated mock
         * topic/partition error APIs). */
        rd_kafka_mock_next_request_error(mconn, resp);

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 3) {
                /* Response: ThrottleTime */
                rd_kafka_buf_write_i32(resp, 0);
        }

        /* Response: #Brokers */
        of_Brokers_cnt = rd_kafka_buf_write_arraycnt_pos(resp);

        TAILQ_FOREACH(mrkb, &mcluster->brokers, link) {
                if (!mrkb->up || !mrkb->in_metadata)
                        continue;
                /* Response: Brokers.Nodeid */
                rd_kafka_buf_write_i32(resp, mrkb->id);
                /* Response: Brokers.Host */
                rd_kafka_buf_write_str(resp, mrkb->advertised_listener, -1);
                /* Response: Brokers.Port */
                rd_kafka_buf_write_i32(resp, (int32_t)mrkb->port);
                if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1) {
                        /* Response: Brokers.Rack (Matt's going to love this) */
                        rd_kafka_buf_write_str(resp, mrkb->rack, -1);
                }
                rd_kafka_buf_write_tags_empty(resp);
                response_Brokers_cnt++;
        }
        rd_kafka_buf_finalize_arraycnt(resp, of_Brokers_cnt,
                                       response_Brokers_cnt);

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 2) {
                /* Response: ClusterId */
                rd_kafka_buf_write_str(resp, mcluster->id, -1);
        }

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1) {
                /* Response: ControllerId */
                rd_kafka_buf_write_i32(resp, mcluster->controller_id);
        }

        /* #Topics */
        rd_kafka_buf_read_arraycnt(rkbuf, &TopicsCnt, RD_KAFKAP_TOPICS_MAX);

        if (TopicsCnt > 0)
                requested_topics = rd_kafka_topic_partition_list_new(TopicsCnt);
        else if (rkbuf->rkbuf_reqhdr.ApiVersion == 0 || TopicsCnt == -1)
                list_all_topics = rd_true;

        for (i = 0; i < TopicsCnt; i++) {
                rd_kafkap_str_t Topic;
                rd_kafka_Uuid_t TopicId = RD_KAFKA_UUID_ZERO;
                rd_kafka_topic_partition_t *rktpar;
                char *topic = NULL;

                if (rkbuf->rkbuf_reqhdr.ApiVersion >= 10) {
                        /* TopicId */
                        rd_kafka_buf_read_uuid(rkbuf, &TopicId);
                }
                rd_kafka_buf_read_str(rkbuf, &Topic);
                RD_KAFKAP_STR_DUPA(&topic, &Topic);

                rktpar = rd_kafka_topic_partition_list_add(
                    requested_topics, topic, RD_KAFKA_PARTITION_UA);
                if (rkbuf->rkbuf_reqhdr.ApiVersion >= 10)
                        rd_kafka_topic_partition_set_topic_id(rktpar, TopicId);
                rd_kafka_buf_skip_tags(rkbuf);
        }

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 4)
                rd_kafka_buf_read_bool(rkbuf, &AllowAutoTopicCreation);

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 8) {
                rd_bool_t IncludeClusterAuthorizedOperations;
                rd_bool_t IncludeTopicAuthorizedOperations;
                if (rkbuf->rkbuf_reqhdr.ApiVersion <= 10)
                        rd_kafka_buf_read_bool(
                            rkbuf, &IncludeClusterAuthorizedOperations);
                rd_kafka_buf_read_bool(rkbuf,
                                       &IncludeTopicAuthorizedOperations);
        }

        if (list_all_topics) {
                rd_kafka_mock_topic_t *mtopic;
                /* Response: #Topics */
                rd_kafka_buf_write_arraycnt(resp, mcluster->topic_cnt);

                TAILQ_FOREACH(mtopic, &mcluster->topics, link) {
                        rd_kafka_mock_buf_write_Metadata_Topic(
                            mcluster, resp, rkbuf->rkbuf_reqhdr.ApiVersion,
                            mtopic->id, mtopic->name, mtopic, mtopic->err);
                }

        } else if (requested_topics) {
                /* Response: #Topics */
                rd_kafka_buf_write_arraycnt(resp, requested_topics->cnt);

                for (i = 0; i < requested_topics->cnt; i++) {
                        const rd_kafka_topic_partition_t *rktpar =
                            &requested_topics->elems[i];
                        rd_kafka_mock_topic_t *mtopic = NULL;
                        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;
                        char *topic_name        = rktpar->topic;
                        rd_kafka_Uuid_t topic_id =
                            rd_kafka_topic_partition_get_topic_id(rktpar);
                        rd_bool_t invalid_before_12 =
                            rkbuf->rkbuf_reqhdr.ApiVersion < 12 &&
                            (!RD_KAFKA_UUID_IS_ZERO(topic_id) || !topic_name);
                        rd_bool_t invalid_after_12 =
                            rkbuf->rkbuf_reqhdr.ApiVersion >= 12 &&
                            RD_KAFKA_UUID_IS_ZERO(topic_id) && !topic_name;
                        if (invalid_before_12 || invalid_after_12) {
                                err = RD_KAFKA_RESP_ERR_INVALID_REQUEST;
                        }

                        if (!err) {
                                rd_bool_t use_topic_id =
                                    !RD_KAFKA_UUID_IS_ZERO(topic_id);
                                if (use_topic_id) {
                                        mtopic = rd_kafka_mock_topic_find_by_id(
                                            mcluster, topic_id);
                                } else
                                        mtopic = rd_kafka_mock_topic_find(
                                            mcluster, topic_name);

                                if (mtopic) {
                                        topic_name = mtopic->name;
                                        topic_id   = mtopic->id;
                                } else if (!use_topic_id) {
                                        topic_name = rktpar->topic;
                                } else {
                                        topic_name = NULL;
                                }

                                if (!mtopic && topic_name &&
                                    AllowAutoTopicCreation) {
                                        mtopic =
                                            rd_kafka_mock_topic_auto_create(
                                                mcluster, topic_name, -1, &err);
                                        topic_id = mtopic->id;
                                } else if (!mtopic) {
                                        err =
                                            use_topic_id
                                                ? RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_ID
                                                : RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;
                                }
                        }

                        rd_kafka_mock_buf_write_Metadata_Topic(
                            mcluster, resp, rkbuf->rkbuf_reqhdr.ApiVersion,
                            topic_id, topic_name, mtopic,
                            err ? err : mtopic->err);
                }

        } else {
                /* Response: #Topics: brokers only */
                rd_kafka_buf_write_arraycnt(resp, 0);
        }

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 8 &&
            rkbuf->rkbuf_reqhdr.ApiVersion <= 10) {
                /* ClusterAuthorizedOperations */
                rd_kafka_buf_write_i32(resp, INT32_MIN);
        }

        rd_kafka_buf_skip_tags(rkbuf);
        rd_kafka_buf_write_tags_empty(resp);

        if (requested_topics)
                rd_kafka_topic_partition_list_destroy(requested_topics);

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        if (requested_topics)
                rd_kafka_topic_partition_list_destroy(requested_topics);

        rd_kafka_buf_destroy(resp);
        return -1;
}


/**
 * @brief Handle FindCoordinatorRequest
 */
static int
rd_kafka_mock_handle_FindCoordinator(rd_kafka_mock_connection_t *mconn,
                                     rd_kafka_buf_t *rkbuf) {
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafkap_str_t Key;
        int8_t KeyType                     = RD_KAFKA_COORD_GROUP;
        const rd_kafka_mock_broker_t *mrkb = NULL;
        rd_kafka_resp_err_t err;

        /* Key */
        rd_kafka_buf_read_str(rkbuf, &Key);

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1) {
                /* KeyType */
                rd_kafka_buf_read_i8(rkbuf, &KeyType);
        }


        /*
         * Construct response
         */
        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1) {
                /* Response: Throttle */
                rd_kafka_buf_write_i32(resp, 0);
        }

        /* Inject error, if any */
        err = rd_kafka_mock_next_request_error(mconn, resp);

        if (!err && RD_KAFKAP_STR_LEN(&Key) > 0) {
                mrkb = rd_kafka_mock_cluster_get_coord(mcluster, KeyType, &Key);
                rd_assert(mrkb);
        }

        if (!mrkb && !err)
                err = RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE;

        if (err) {
                /* Response: ErrorCode and ErrorMessage */
                rd_kafka_buf_write_i16(resp, err);
                if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1)
                        rd_kafka_buf_write_str(resp, rd_kafka_err2str(err), -1);

                /* Response: NodeId, Host, Port */
                rd_kafka_buf_write_i32(resp, -1);
                rd_kafka_buf_write_str(resp, NULL, -1);
                rd_kafka_buf_write_i32(resp, -1);
        } else {
                /* Response: ErrorCode and ErrorMessage */
                rd_kafka_buf_write_i16(resp, 0);
                if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1)
                        rd_kafka_buf_write_str(resp, NULL, -1);

                /* Response: NodeId, Host, Port */
                rd_kafka_buf_write_i32(resp, mrkb->id);
                rd_kafka_buf_write_str(resp, mrkb->advertised_listener, -1);
                rd_kafka_buf_write_i32(resp, (int32_t)mrkb->port);
        }

        rd_kafka_mock_connection_send_response(mconn, resp);
        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}



/**
 * @brief Handle JoinGroupRequest
 */
static int rd_kafka_mock_handle_JoinGroup(rd_kafka_mock_connection_t *mconn,
                                          rd_kafka_buf_t *rkbuf) {
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_mock_broker_t *mrkb;
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafkap_str_t GroupId, MemberId, ProtocolType;
        rd_kafkap_str_t GroupInstanceId = RD_KAFKAP_STR_INITIALIZER;
        int32_t SessionTimeoutMs;
        int32_t MaxPollIntervalMs = -1;
        int32_t ProtocolCnt       = 0;
        int32_t i;
        rd_kafka_resp_err_t err;
        rd_kafka_mock_cgrp_classic_t *mcgrp;
        rd_kafka_mock_cgrp_classic_proto_t *protos = NULL;

        rd_kafka_buf_read_str(rkbuf, &GroupId);
        rd_kafka_buf_read_i32(rkbuf, &SessionTimeoutMs);
        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1)
                rd_kafka_buf_read_i32(rkbuf, &MaxPollIntervalMs);
        rd_kafka_buf_read_str(rkbuf, &MemberId);
        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 5)
                rd_kafka_buf_read_str(rkbuf, &GroupInstanceId);
        rd_kafka_buf_read_str(rkbuf, &ProtocolType);
        rd_kafka_buf_read_i32(rkbuf, &ProtocolCnt);

        if (ProtocolCnt > 1000) {
                rd_kafka_dbg(mcluster->rk, MOCK, "MOCK",
                             "JoinGroupRequest: ProtocolCnt %" PRId32
                             " > max allowed 1000",
                             ProtocolCnt);
                rd_kafka_buf_destroy(resp);
                return -1;
        }

        protos = rd_malloc(sizeof(*protos) * ProtocolCnt);
        for (i = 0; i < ProtocolCnt; i++) {
                rd_kafkap_str_t ProtocolName;
                rd_kafkap_bytes_t Metadata;
                rd_kafka_buf_read_str(rkbuf, &ProtocolName);
                rd_kafka_buf_read_kbytes(rkbuf, &Metadata);
                protos[i].name     = rd_kafkap_str_copy(&ProtocolName);
                protos[i].metadata = rd_kafkap_bytes_copy(&Metadata);
        }

        /*
         * Construct response
         */
        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 2) {
                /* Response: Throttle */
                rd_kafka_buf_write_i32(resp, 0);
        }

        /* Inject error, if any */
        err = rd_kafka_mock_next_request_error(mconn, resp);

        if (!err) {
                mrkb = rd_kafka_mock_cluster_get_coord(
                    mcluster, RD_KAFKA_COORD_GROUP, &GroupId);

                if (!mrkb)
                        err = RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE;
                else if (mrkb != mconn->broker)
                        err = RD_KAFKA_RESP_ERR_NOT_COORDINATOR;
        }

        if (!err) {
                mcgrp = rd_kafka_mock_cgrp_classic_get(mcluster, &GroupId,
                                                       &ProtocolType);
                rd_assert(mcgrp);

                /* This triggers an async rebalance, the response will be
                 * sent later. */
                err = rd_kafka_mock_cgrp_classic_member_add(
                    mcgrp, mconn, resp, &MemberId, &ProtocolType,
                    &GroupInstanceId, protos, ProtocolCnt, SessionTimeoutMs);
                if (!err) {
                        /* .._add() assumes ownership of resp and protos */
                        protos = NULL;
                        rd_kafka_mock_connection_set_blocking(mconn, rd_true);
                        return 0;
                }
        }

        rd_kafka_mock_cgrp_classic_protos_destroy(protos, ProtocolCnt);

        /* Error case */
        rd_kafka_buf_write_i16(resp, err);      /* ErrorCode */
        rd_kafka_buf_write_i32(resp, -1);       /* GenerationId */
        rd_kafka_buf_write_str(resp, NULL, -1); /* ProtocolName */
        rd_kafka_buf_write_str(resp, NULL, -1); /* LeaderId */
        rd_kafka_buf_write_kstr(resp, NULL);    /* MemberId */
        rd_kafka_buf_write_i32(resp, 0);        /* MemberCnt */

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        if (protos)
                rd_kafka_mock_cgrp_classic_protos_destroy(protos, ProtocolCnt);
        return -1;
}


/**
 * @brief Handle HeartbeatRequest
 */
static int rd_kafka_mock_handle_Heartbeat(rd_kafka_mock_connection_t *mconn,
                                          rd_kafka_buf_t *rkbuf) {
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_mock_broker_t *mrkb;
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafkap_str_t GroupId, MemberId;
        rd_kafkap_str_t GroupInstanceId = RD_KAFKAP_STR_INITIALIZER;
        int32_t GenerationId;
        rd_kafka_resp_err_t err;
        rd_kafka_mock_cgrp_classic_t *mcgrp;
        rd_kafka_mock_cgrp_classic_member_t *member = NULL;

        rd_kafka_buf_read_str(rkbuf, &GroupId);
        rd_kafka_buf_read_i32(rkbuf, &GenerationId);
        rd_kafka_buf_read_str(rkbuf, &MemberId);
        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 3)
                rd_kafka_buf_read_str(rkbuf, &GroupInstanceId);

        /*
         * Construct response
         */
        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1) {
                /* Response: Throttle */
                rd_kafka_buf_write_i32(resp, 0);
        }

        /* Inject error, if any */
        err = rd_kafka_mock_next_request_error(mconn, resp);
        if (!err) {
                mrkb = rd_kafka_mock_cluster_get_coord(
                    mcluster, RD_KAFKA_COORD_GROUP, &GroupId);

                if (!mrkb)
                        err = RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE;
                else if (mrkb != mconn->broker)
                        err = RD_KAFKA_RESP_ERR_NOT_COORDINATOR;
        }

        if (!err) {
                mcgrp = rd_kafka_mock_cgrp_classic_find(mcluster, &GroupId);
                if (!mcgrp)
                        err = RD_KAFKA_RESP_ERR_GROUP_ID_NOT_FOUND;
        }

        if (!err) {
                member =
                    rd_kafka_mock_cgrp_classic_member_find(mcgrp, &MemberId);
                if (!member)
                        err = RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID;
        }

        if (!err)
                err = rd_kafka_mock_cgrp_classic_check_state(
                    mcgrp, member, rkbuf, GenerationId);

        if (!err)
                rd_kafka_mock_cgrp_classic_member_active(mcgrp, member);

        rd_kafka_buf_write_i16(resp, err); /* ErrorCode */

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}


/**
 * @brief Handle LeaveGroupRequest
 */
static int rd_kafka_mock_handle_LeaveGroup(rd_kafka_mock_connection_t *mconn,
                                           rd_kafka_buf_t *rkbuf) {
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_mock_broker_t *mrkb;
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafkap_str_t GroupId, MemberId;
        rd_kafka_resp_err_t err;
        rd_kafka_mock_cgrp_classic_t *mcgrp;
        rd_kafka_mock_cgrp_classic_member_t *member = NULL;

        rd_kafka_buf_read_str(rkbuf, &GroupId);
        rd_kafka_buf_read_str(rkbuf, &MemberId);

        /*
         * Construct response
         */

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1) {
                /* Response: Throttle */
                rd_kafka_buf_write_i32(resp, 0);
        }

        /* Inject error, if any */
        err = rd_kafka_mock_next_request_error(mconn, resp);
        if (!err) {
                mrkb = rd_kafka_mock_cluster_get_coord(
                    mcluster, RD_KAFKA_COORD_GROUP, &GroupId);

                if (!mrkb)
                        err = RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE;
                else if (mrkb != mconn->broker)
                        err = RD_KAFKA_RESP_ERR_NOT_COORDINATOR;
        }

        if (!err) {
                mcgrp = rd_kafka_mock_cgrp_classic_find(mcluster, &GroupId);
                if (!mcgrp)
                        err = RD_KAFKA_RESP_ERR_GROUP_ID_NOT_FOUND;
        }

        if (!err) {
                member =
                    rd_kafka_mock_cgrp_classic_member_find(mcgrp, &MemberId);
                if (!member)
                        err = RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID;
        }

        if (!err)
                err = rd_kafka_mock_cgrp_classic_check_state(mcgrp, member,
                                                             rkbuf, -1);

        if (!err)
                rd_kafka_mock_cgrp_classic_member_leave(mcgrp, member);

        rd_kafka_buf_write_i16(resp, err); /* ErrorCode */

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}



/**
 * @brief Handle SyncGroupRequest
 */
static int rd_kafka_mock_handle_SyncGroup(rd_kafka_mock_connection_t *mconn,
                                          rd_kafka_buf_t *rkbuf) {
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_mock_broker_t *mrkb;
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafkap_str_t GroupId, MemberId;
        rd_kafkap_str_t GroupInstanceId = RD_KAFKAP_STR_INITIALIZER;
        int32_t GenerationId, AssignmentCnt;
        int32_t i;
        rd_kafka_resp_err_t err;
        rd_kafka_mock_cgrp_classic_t *mcgrp         = NULL;
        rd_kafka_mock_cgrp_classic_member_t *member = NULL;

        rd_kafka_buf_read_str(rkbuf, &GroupId);
        rd_kafka_buf_read_i32(rkbuf, &GenerationId);
        rd_kafka_buf_read_str(rkbuf, &MemberId);
        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 3)
                rd_kafka_buf_read_str(rkbuf, &GroupInstanceId);
        rd_kafka_buf_read_i32(rkbuf, &AssignmentCnt);

        /*
         * Construct response
         */
        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1) {
                /* Response: Throttle */
                rd_kafka_buf_write_i32(resp, 0);
        }

        /* Inject error, if any */
        err = rd_kafka_mock_next_request_error(mconn, resp);
        if (!err) {
                mrkb = rd_kafka_mock_cluster_get_coord(
                    mcluster, RD_KAFKA_COORD_GROUP, &GroupId);

                if (!mrkb)
                        err = RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE;
                else if (mrkb != mconn->broker)
                        err = RD_KAFKA_RESP_ERR_NOT_COORDINATOR;
        }

        if (!err) {
                mcgrp = rd_kafka_mock_cgrp_classic_find(mcluster, &GroupId);
                if (!mcgrp)
                        err = RD_KAFKA_RESP_ERR_GROUP_ID_NOT_FOUND;
        }

        if (!err) {
                member =
                    rd_kafka_mock_cgrp_classic_member_find(mcgrp, &MemberId);
                if (!member)
                        err = RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID;
        }

        if (!err)
                err = rd_kafka_mock_cgrp_classic_check_state(
                    mcgrp, member, rkbuf, GenerationId);

        if (!err)
                rd_kafka_mock_cgrp_classic_member_active(mcgrp, member);

        if (!err) {
                rd_bool_t is_leader = mcgrp->leader && mcgrp->leader == member;

                if (AssignmentCnt > 0 && !is_leader)
                        err =
                            RD_KAFKA_RESP_ERR_NOT_LEADER_FOR_PARTITION; /* FIXME
                                                                         */
                else if (AssignmentCnt == 0 && is_leader)
                        err = RD_KAFKA_RESP_ERR_INVALID_PARTITIONS; /* FIXME */
        }

        for (i = 0; i < AssignmentCnt; i++) {
                rd_kafkap_str_t MemberId2;
                rd_kafkap_bytes_t Metadata;
                rd_kafka_mock_cgrp_classic_member_t *member2;

                rd_kafka_buf_read_str(rkbuf, &MemberId2);
                rd_kafka_buf_read_kbytes(rkbuf, &Metadata);

                if (err)
                        continue;

                /* Find member */
                member2 =
                    rd_kafka_mock_cgrp_classic_member_find(mcgrp, &MemberId2);
                if (!member2)
                        continue;

                rd_kafka_mock_cgrp_classic_member_assignment_set(mcgrp, member2,
                                                                 &Metadata);
        }

        if (!err) {
                err = rd_kafka_mock_cgrp_classic_member_sync_set(mcgrp, member,
                                                                 mconn, resp);
                /* .._sync_set() assumes ownership of resp */
                if (!err)
                        return 0; /* Response will be sent when all members
                                   * are synchronized */
        }

        /* Error case */
        rd_kafka_buf_write_i16(resp, err);        /* ErrorCode */
        rd_kafka_buf_write_bytes(resp, NULL, -1); /* MemberState */

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}



/**
 * @brief Generate a unique ProducerID
 */
static const rd_kafka_pid_t
rd_kafka_mock_pid_new(rd_kafka_mock_cluster_t *mcluster,
                      const rd_kafkap_str_t *TransactionalId) {
        size_t tidlen =
            TransactionalId ? RD_KAFKAP_STR_LEN(TransactionalId) : 0;
        rd_kafka_mock_pid_t *mpid = rd_malloc(sizeof(*mpid) + tidlen);
        rd_kafka_pid_t ret;

        mpid->pid.id    = rd_jitter(1, 900000) * 1000;
        mpid->pid.epoch = 0;

        if (tidlen > 0)
                memcpy(mpid->TransactionalId, TransactionalId->str, tidlen);
        mpid->TransactionalId[tidlen] = '\0';

        mtx_lock(&mcluster->lock);
        rd_list_add(&mcluster->pids, mpid);
        ret = mpid->pid;
        mtx_unlock(&mcluster->lock);

        return ret;
}


/**
 * @brief Finds a matching mcluster mock PID for the given \p pid.
 *
 * @locks_required mcluster->lock
 */
rd_kafka_resp_err_t
rd_kafka_mock_pid_find(rd_kafka_mock_cluster_t *mcluster,
                       const rd_kafkap_str_t *TransactionalId,
                       const rd_kafka_pid_t pid,
                       rd_kafka_mock_pid_t **mpidp) {
        rd_kafka_mock_pid_t *mpid;
        rd_kafka_mock_pid_t skel = {pid};

        *mpidp = NULL;
        mpid = rd_list_find(&mcluster->pids, &skel, rd_kafka_mock_pid_cmp_pid);

        if (!mpid)
                return RD_KAFKA_RESP_ERR_UNKNOWN_PRODUCER_ID;
        else if (((TransactionalId != NULL) !=
                  (*mpid->TransactionalId != '\0')) ||
                 (TransactionalId &&
                  rd_kafkap_str_cmp_str(TransactionalId,
                                        mpid->TransactionalId)))
                return RD_KAFKA_RESP_ERR_INVALID_PRODUCER_ID_MAPPING;

        *mpidp = mpid;
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * @brief Checks if the given pid is known, else returns an error.
 */
static rd_kafka_resp_err_t
rd_kafka_mock_pid_check(rd_kafka_mock_cluster_t *mcluster,
                        const rd_kafkap_str_t *TransactionalId,
                        const rd_kafka_pid_t check_pid) {
        rd_kafka_mock_pid_t *mpid;
        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;

        mtx_lock(&mcluster->lock);
        err =
            rd_kafka_mock_pid_find(mcluster, TransactionalId, check_pid, &mpid);
        if (!err && check_pid.epoch != mpid->pid.epoch)
                err = RD_KAFKA_RESP_ERR_INVALID_PRODUCER_EPOCH;
        mtx_unlock(&mcluster->lock);

        if (unlikely(err))
                rd_kafka_dbg(mcluster->rk, MOCK, "MOCK",
                             "PID check failed for TransactionalId=%.*s: "
                             "expected %s, not %s: %s",
                             RD_KAFKAP_STR_PR(TransactionalId),
                             mpid ? rd_kafka_pid2str(mpid->pid) : "none",
                             rd_kafka_pid2str(check_pid),
                             rd_kafka_err2name(err));
        return err;
}


/**
 * @brief Bump the epoch for an existing pid, or return an error
 *        if the current_pid does not match an existing pid.
 */
static rd_kafka_resp_err_t
rd_kafka_mock_pid_bump(rd_kafka_mock_cluster_t *mcluster,
                       const rd_kafkap_str_t *TransactionalId,
                       rd_kafka_pid_t *current_pid) {
        rd_kafka_mock_pid_t *mpid;
        rd_kafka_resp_err_t err;

        mtx_lock(&mcluster->lock);
        err = rd_kafka_mock_pid_find(mcluster, TransactionalId, *current_pid,
                                     &mpid);
        if (err) {
                mtx_unlock(&mcluster->lock);
                return err;
        }

        if (current_pid->epoch != mpid->pid.epoch) {
                mtx_unlock(&mcluster->lock);
                return RD_KAFKA_RESP_ERR_INVALID_PRODUCER_EPOCH;
        }

        mpid->pid.epoch++;
        *current_pid = mpid->pid;
        mtx_unlock(&mcluster->lock);

        rd_kafka_dbg(mcluster->rk, MOCK, "MOCK", "Bumped PID %s",
                     rd_kafka_pid2str(*current_pid));

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * @brief Handle InitProducerId
 */
static int
rd_kafka_mock_handle_InitProducerId(rd_kafka_mock_connection_t *mconn,
                                    rd_kafka_buf_t *rkbuf) {
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafkap_str_t TransactionalId;
        rd_kafka_pid_t pid         = RD_KAFKA_PID_INITIALIZER;
        rd_kafka_pid_t current_pid = RD_KAFKA_PID_INITIALIZER;
        int32_t TxnTimeoutMs;
        rd_kafka_resp_err_t err;

        /* TransactionalId */
        rd_kafka_buf_read_str(rkbuf, &TransactionalId);
        /* TransactionTimeoutMs */
        rd_kafka_buf_read_i32(rkbuf, &TxnTimeoutMs);

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 3) {
                /* ProducerId */
                rd_kafka_buf_read_i64(rkbuf, &current_pid.id);
                /* ProducerEpoch */
                rd_kafka_buf_read_i16(rkbuf, &current_pid.epoch);
        }

        /*
         * Construct response
         */

        /* ThrottleTimeMs */
        rd_kafka_buf_write_i32(resp, 0);

        /* Inject error */
        err = rd_kafka_mock_next_request_error(mconn, resp);

        if (!err && !RD_KAFKAP_STR_IS_NULL(&TransactionalId)) {
                if (RD_KAFKAP_STR_LEN(&TransactionalId) == 0)
                        err = RD_KAFKA_RESP_ERR_INVALID_REQUEST;
                else if (rd_kafka_mock_cluster_get_coord(
                             mcluster, RD_KAFKA_COORD_TXN, &TransactionalId) !=
                         mconn->broker)
                        err = RD_KAFKA_RESP_ERR_NOT_COORDINATOR;
        }

        if (!err) {
                if (rd_kafka_pid_valid(current_pid)) {
                        /* Producer is asking for the transactional coordinator
                         * to bump the epoch (KIP-360).
                         * Verify that current_pid matches and then
                         * bump the epoch. */
                        err = rd_kafka_mock_pid_bump(mcluster, &TransactionalId,
                                                     &current_pid);
                        if (!err)
                                pid = current_pid;

                } else {
                        /* Generate a new pid */
                        pid = rd_kafka_mock_pid_new(mcluster, &TransactionalId);
                }
        }

        /* ErrorCode */
        rd_kafka_buf_write_i16(resp, err);

        /* ProducerId */
        rd_kafka_buf_write_i64(resp, pid.id);
        /* ProducerEpoch */
        rd_kafka_buf_write_i16(resp, pid.epoch);

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}



/**
 * @brief Handle AddPartitionsToTxn
 */
static int
rd_kafka_mock_handle_AddPartitionsToTxn(rd_kafka_mock_connection_t *mconn,
                                        rd_kafka_buf_t *rkbuf) {
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafka_resp_err_t all_err;
        rd_kafkap_str_t TransactionalId;
        rd_kafka_pid_t pid;
        rd_kafka_mock_txn_t *mtxn = NULL;
        int32_t TopicsCnt;

        /* Response: ThrottleTimeMs */
        rd_kafka_buf_write_i32(resp, 0);

        /* TransactionalId */
        rd_kafka_buf_read_str(rkbuf, &TransactionalId);
        /* ProducerId */
        rd_kafka_buf_read_i64(rkbuf, &pid.id);
        /* Epoch */
        rd_kafka_buf_read_i16(rkbuf, &pid.epoch);
        /* #Topics */
        rd_kafka_buf_read_i32(rkbuf, &TopicsCnt);

        /* Response: #Results */
        rd_kafka_buf_write_i32(resp, TopicsCnt);

        /* Inject error */
        all_err = rd_kafka_mock_next_request_error(mconn, resp);

        if (!all_err &&
            rd_kafka_mock_cluster_get_coord(mcluster, RD_KAFKA_COORD_TXN,
                                            &TransactionalId) != mconn->broker)
                all_err = RD_KAFKA_RESP_ERR_NOT_COORDINATOR;

        if (!all_err)
                all_err =
                    rd_kafka_mock_pid_check(mcluster, &TransactionalId, pid);

        /* Track transaction state. */
        if (!all_err) {
                mtx_lock(&mcluster->lock);
                mtxn        = rd_kafka_mock_txn_get(mcluster, &TransactionalId);
                mtxn->pid   = pid;
                mtxn->state = RD_KAFKA_MOCK_TXN_ONGOING;
                mtx_unlock(&mcluster->lock);
        }

        while (TopicsCnt-- > 0) {
                rd_kafkap_str_t Topic;
                int32_t PartsCnt;
                const rd_kafka_mock_topic_t *mtopic;

                /* Topic */
                rd_kafka_buf_read_str(rkbuf, &Topic);
                /* Response: Topic */
                rd_kafka_buf_write_kstr(resp, &Topic);

                /* #Partitions */
                rd_kafka_buf_read_i32(rkbuf, &PartsCnt);
                /* Response: #Partitions */
                rd_kafka_buf_write_i32(resp, PartsCnt);

                mtopic = rd_kafka_mock_topic_find_by_kstr(mcluster, &Topic);

                while (PartsCnt--) {
                        int32_t Partition;
                        rd_kafka_resp_err_t err = all_err;

                        /* Partition */
                        rd_kafka_buf_read_i32(rkbuf, &Partition);
                        /* Response: Partition */
                        rd_kafka_buf_write_i32(resp, Partition);

                        if (!mtopic || Partition < 0 ||
                            Partition >= mtopic->partition_cnt)
                                err = RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;
                        else if (mtopic && mtopic->err)
                                err = mtopic->err;

                        /* Track partition in transaction */
                        if (!err && mtxn) {
                                char *topic_name;
                                RD_KAFKAP_STR_DUPA(&topic_name, &Topic);
                                mtx_lock(&mcluster->lock);
                                rd_kafka_mock_txn_partition_add(
                                    mtxn, topic_name, Partition);
                                mtx_unlock(&mcluster->lock);
                        }

                        /* Response: ErrorCode */
                        rd_kafka_buf_write_i16(resp, err);
                }
        }

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}


/**
 * @brief Handle AddOffsetsToTxn
 */
static int
rd_kafka_mock_handle_AddOffsetsToTxn(rd_kafka_mock_connection_t *mconn,
                                     rd_kafka_buf_t *rkbuf) {
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafka_resp_err_t err;
        rd_kafkap_str_t TransactionalId, GroupId;
        rd_kafka_pid_t pid;

        /* TransactionalId */
        rd_kafka_buf_read_str(rkbuf, &TransactionalId);
        /* ProducerId */
        rd_kafka_buf_read_i64(rkbuf, &pid.id);
        /* Epoch */
        rd_kafka_buf_read_i16(rkbuf, &pid.epoch);
        /* GroupIdId */
        rd_kafka_buf_read_str(rkbuf, &GroupId);

        /* Response: ThrottleTimeMs */
        rd_kafka_buf_write_i32(resp, 0);

        /* Inject error */
        err = rd_kafka_mock_next_request_error(mconn, resp);

        if (!err &&
            rd_kafka_mock_cluster_get_coord(mcluster, RD_KAFKA_COORD_TXN,
                                            &TransactionalId) != mconn->broker)
                err = RD_KAFKA_RESP_ERR_NOT_COORDINATOR;

        if (!err)
                err = rd_kafka_mock_pid_check(mcluster, &TransactionalId, pid);

        /* Response: ErrorCode */
        rd_kafka_buf_write_i16(resp, err);

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}


/**
 * @brief Handle TxnOffsetCommit
 */
static int
rd_kafka_mock_handle_TxnOffsetCommit(rd_kafka_mock_connection_t *mconn,
                                     rd_kafka_buf_t *rkbuf) {
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafka_resp_err_t err;
        rd_kafkap_str_t TransactionalId, GroupId;
        rd_kafka_pid_t pid;
        int32_t TopicsCnt;

        /* Response: ThrottleTimeMs */
        rd_kafka_buf_write_i32(resp, 0);

        /* TransactionalId */
        rd_kafka_buf_read_str(rkbuf, &TransactionalId);
        /* GroupId */
        rd_kafka_buf_read_str(rkbuf, &GroupId);
        /* ProducerId */
        rd_kafka_buf_read_i64(rkbuf, &pid.id);
        /* Epoch */
        rd_kafka_buf_read_i16(rkbuf, &pid.epoch);

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 3) {
                int32_t GenerationId;
                rd_kafkap_str_t kMemberId, kGroupInstanceId;

                /* GenerationId */
                rd_kafka_buf_read_i32(rkbuf, &GenerationId);
                /* MemberId */
                rd_kafka_buf_read_str(rkbuf, &kMemberId);
                /* GroupInstanceId */
                rd_kafka_buf_read_str(rkbuf, &kGroupInstanceId);
        }

        /* #Topics */
        rd_kafka_buf_read_arraycnt(rkbuf, &TopicsCnt, 100000);

        /* Response: #Results */
        rd_kafka_buf_write_arraycnt(resp, TopicsCnt);

        /* Inject error */
        err = rd_kafka_mock_next_request_error(mconn, resp);

        if (!err &&
            rd_kafka_mock_cluster_get_coord(mcluster, RD_KAFKA_COORD_GROUP,
                                            &GroupId) != mconn->broker)
                err = RD_KAFKA_RESP_ERR_NOT_COORDINATOR;

        if (!err)
                err = rd_kafka_mock_pid_check(mcluster, &TransactionalId, pid);

        while (TopicsCnt-- > 0) {
                rd_kafkap_str_t Topic;
                int32_t PartsCnt;
                rd_kafka_mock_topic_t *mtopic;

                /* Topic */
                rd_kafka_buf_read_str(rkbuf, &Topic);
                /* Response: Topic */
                rd_kafka_buf_write_kstr(resp, &Topic);

                mtopic = rd_kafka_mock_topic_find_by_kstr(mcluster, &Topic);

                /* #Partitions */
                rd_kafka_buf_read_arraycnt(rkbuf, &PartsCnt, 100000);

                /* Response: #Partitions */
                rd_kafka_buf_write_arraycnt(resp, PartsCnt);

                while (PartsCnt-- > 0) {
                        int32_t Partition;
                        int64_t Offset;
                        rd_kafkap_str_t Metadata;
                        rd_kafka_mock_partition_t *mpart;

                        /* Partition */
                        rd_kafka_buf_read_i32(rkbuf, &Partition);
                        /* Response: Partition */
                        rd_kafka_buf_write_i32(resp, Partition);

                        mpart = rd_kafka_mock_partition_find(mtopic, Partition);
                        if (!err && !mpart)
                                err = RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;

                        /* CommittedOffset */
                        rd_kafka_buf_read_i64(rkbuf, &Offset);

                        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 2) {
                                /* CommittedLeaderEpoch */
                                int32_t CommittedLeaderEpoch;
                                rd_kafka_buf_read_i32(rkbuf,
                                                      &CommittedLeaderEpoch);
                                if (!err && mpart)
                                        err =
                                            rd_kafka_mock_partition_leader_epoch_check(
                                                mpart, CommittedLeaderEpoch);
                        }

                        /* CommittedMetadata */
                        rd_kafka_buf_read_str(rkbuf, &Metadata);

                        /* Response: ErrorCode */
                        rd_kafka_buf_write_i16(resp, err);

                        /* Request: Struct tags */
                        rd_kafka_buf_skip_tags(rkbuf);

                        /* Response: Struct tags */
                        rd_kafka_buf_write_tags_empty(resp);
                }

                /* Request: Struct tags */
                rd_kafka_buf_skip_tags(rkbuf);

                /* Response: Struct tags */
                rd_kafka_buf_write_tags_empty(resp);
        }

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}


/**
 * @brief Handle EndTxn
 */
static int rd_kafka_mock_handle_EndTxn(rd_kafka_mock_connection_t *mconn,
                                       rd_kafka_buf_t *rkbuf) {
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafka_resp_err_t err;
        rd_kafkap_str_t TransactionalId;
        rd_kafka_pid_t pid;
        rd_bool_t committed;

        /* TransactionalId */
        rd_kafka_buf_read_str(rkbuf, &TransactionalId);
        /* ProducerId */
        rd_kafka_buf_read_i64(rkbuf, &pid.id);
        /* ProducerEpoch */
        rd_kafka_buf_read_i16(rkbuf, &pid.epoch);
        /* Committed */
        rd_kafka_buf_read_bool(rkbuf, &committed);

        /*
         * Construct response
         */

        /* ThrottleTimeMs */
        rd_kafka_buf_write_i32(resp, 0);

        /* Inject error */
        err = rd_kafka_mock_next_request_error(mconn, resp);

        if (!err &&
            rd_kafka_mock_cluster_get_coord(mcluster, RD_KAFKA_COORD_TXN,
                                            &TransactionalId) != mconn->broker)
                err = RD_KAFKA_RESP_ERR_NOT_COORDINATOR;

        if (!err)
                err = rd_kafka_mock_pid_check(mcluster, &TransactionalId, pid);

        /* Commit/abort the transaction. */
        if (!err) {
                rd_kafka_mock_txn_t *mtxn;
                rd_kafka_mock_txn_partition_t *mtxnp;

                mtx_lock(&mcluster->lock);
                mtxn = rd_kafka_mock_txn_get(mcluster, &TransactionalId);

                if (mtxn->state != RD_KAFKA_MOCK_TXN_ONGOING) {
                        /* No active transaction — could be an idempotent
                         * retry after the txn was already completed. */
                        mtx_unlock(&mcluster->lock);
                        goto write_response;
                }

                /* For each partition in the transaction, write a control
                 * batch and (for abort) record the aborted range. */
                TAILQ_FOREACH(mtxnp, &mtxn->partitions, link) {
                        rd_kafka_mock_topic_t *mtopic =
                            rd_kafka_mock_topic_find(mcluster,
                                                     mtxnp->topic_name);
                        rd_kafka_mock_partition_t *mpart;
                        int64_t last_data_offset;

                        if (!mtopic)
                                continue;
                        mpart = rd_kafka_mock_partition_find(mtopic,
                                                             mtxnp->partition);
                        if (!mpart)
                                continue;

                        /* Skip partitions where no data was produced */
                        if (mtxnp->first_offset < 0)
                                continue;

                        /* Offset just before the control batch */
                        last_data_offset = mpart->end_offset - 1;

                        /* Write COMMIT or ABORT control record */
                        rd_kafka_mock_partition_write_control_batch(mpart, pid,
                                                                    committed);

                        /* For abort: record the aborted range */
                        if (!committed) {
                                rd_kafka_mock_aborted_txn_t *mabort =
                                    rd_calloc(1, sizeof(*mabort));
                                mabort->pid_id       = pid.id;
                                mabort->first_offset = mtxnp->first_offset;
                                mabort->last_offset  = last_data_offset;
                                TAILQ_INSERT_TAIL(&mpart->aborted_txns, mabort,
                                                  link);
                        }
                }

                /* Clear transaction state BEFORE recalculating LSO,
                 * so update_lso no longer sees this txn as open. */
                mtxn->state = RD_KAFKA_MOCK_TXN_NONE;

                /* Recalculate LSO for all affected partitions now that
                 * the txn is no longer ONGOING. */
                TAILQ_FOREACH(mtxnp, &mtxn->partitions, link) {
                        rd_kafka_mock_topic_t *mtopic =
                            rd_kafka_mock_topic_find(mcluster,
                                                     mtxnp->topic_name);
                        rd_kafka_mock_partition_t *mpart;
                        if (!mtopic)
                                continue;
                        mpart = rd_kafka_mock_partition_find(mtopic,
                                                             mtxnp->partition);
                        if (!mpart)
                                continue;
                        rd_kafka_mock_partition_update_lso(mpart, mcluster);
                }

                rd_kafka_mock_txn_partitions_clear(mtxn);

                mtx_unlock(&mcluster->lock);
        }

write_response:
        /* ErrorCode */
        rd_kafka_buf_write_i16(resp, err);

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}

static int
rd_kafka_mock_handle_OffsetForLeaderEpoch(rd_kafka_mock_connection_t *mconn,
                                          rd_kafka_buf_t *rkbuf) {
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafka_resp_err_t err;
        int32_t TopicsCnt, i;

        /* Response: ThrottleTimeMs */
        rd_kafka_buf_write_i32(resp, 0);

        /* #Topics */
        rd_kafka_buf_read_arraycnt(rkbuf, &TopicsCnt, RD_KAFKAP_TOPICS_MAX);

        /* Response: #Topics */
        rd_kafka_buf_write_arraycnt(resp, TopicsCnt);

        /* Inject error */
        err = rd_kafka_mock_next_request_error(mconn, resp);

        for (i = 0; i < TopicsCnt; i++) {
                rd_kafkap_str_t Topic;
                int32_t PartitionsCnt, j;
                rd_kafka_mock_topic_t *mtopic;

                /* Topic */
                rd_kafka_buf_read_str(rkbuf, &Topic);

                mtopic = rd_kafka_mock_topic_find_by_kstr(mcluster, &Topic);

                /* Response: Topic */
                rd_kafka_buf_write_kstr(resp, &Topic);

                /* #Partitions */
                rd_kafka_buf_read_arraycnt(rkbuf, &PartitionsCnt,
                                           RD_KAFKAP_PARTITIONS_MAX);

                /* Response: #Partitions */
                rd_kafka_buf_write_arraycnt(resp, PartitionsCnt);

                for (j = 0; j < PartitionsCnt; j++) {
                        rd_kafka_mock_partition_t *mpart;
                        int32_t Partition, CurrentLeaderEpoch, LeaderEpoch;
                        int64_t EndOffset = -1;

                        /* Partition */
                        rd_kafka_buf_read_i32(rkbuf, &Partition);
                        /* CurrentLeaderEpoch */
                        rd_kafka_buf_read_i32(rkbuf, &CurrentLeaderEpoch);
                        /* LeaderEpoch */
                        rd_kafka_buf_read_i32(rkbuf, &LeaderEpoch);

                        mpart = rd_kafka_mock_partition_find(mtopic, Partition);
                        if (!err && !mpart)
                                err = RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;

                        if (!err && mpart)
                                err =
                                    rd_kafka_mock_partition_leader_epoch_check(
                                        mpart, CurrentLeaderEpoch);

                        if (!err && mpart) {
                                EndOffset =
                                    rd_kafka_mock_partition_offset_for_leader_epoch(
                                        mpart, LeaderEpoch);
                        }

                        /* Response: ErrorCode */
                        rd_kafka_buf_write_i16(resp, err);
                        /* Response: Partition */
                        rd_kafka_buf_write_i32(resp, Partition);
                        /* Response: LeaderEpoch */
                        rd_kafka_buf_write_i32(resp, LeaderEpoch);
                        /* Response: Partition */
                        rd_kafka_buf_write_i64(resp, EndOffset);
                }
        }

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}

/**
 * @brief Handle GetTelemetrySubscriptions
 */
static int rd_kafka_mock_handle_GetTelemetrySubscriptions(
    rd_kafka_mock_connection_t *mconn,
    rd_kafka_buf_t *rkbuf) {
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafka_resp_err_t err;
        size_t i;
        rd_kafka_Uuid_t ClientInstanceId;
        rd_kafka_Uuid_t zero_uuid = RD_KAFKA_UUID_ZERO;

        /* Request: ClientInstanceId */
        rd_kafka_buf_read_uuid(rkbuf, &ClientInstanceId);
        if (ClientInstanceId.least_significant_bits ==
                zero_uuid.least_significant_bits &&
            ClientInstanceId.most_significant_bits ==
                zero_uuid.most_significant_bits) {
                /* Some random numbers */
                ClientInstanceId.least_significant_bits = 129;
                ClientInstanceId.most_significant_bits  = 298;
        }

        /* Response: ThrottleTimeMs */
        rd_kafka_buf_write_i32(resp, 0);

        /* Inject error */
        err = rd_kafka_mock_next_request_error(mconn, resp);

        /* Response: ErrorCode */
        rd_kafka_buf_write_i16(resp, err);

        /* Response: ClientInstanceId*/
        rd_kafka_buf_write_uuid(resp, &ClientInstanceId);

        /* Response: SubscriptionId */
        // TODO: Calculate subscription ID.
        rd_kafka_buf_write_i32(resp, 0);

        /* Response: #AcceptedCompressionTypes */
        rd_kafka_buf_write_arraycnt(resp, 4);

        /* Response: AcceptedCompressionTypes */
        rd_kafka_buf_write_i8(resp, RD_KAFKA_COMPRESSION_ZSTD);
        rd_kafka_buf_write_i8(resp, RD_KAFKA_COMPRESSION_LZ4);
        rd_kafka_buf_write_i8(resp, RD_KAFKA_COMPRESSION_GZIP);
        rd_kafka_buf_write_i8(resp, RD_KAFKA_COMPRESSION_SNAPPY);

        /* Response: PushIntervalMs */
        /* We use the value in telemetry_push_interval_ms, and if not set, the
         * default of 5 minutes. */
        rd_kafka_buf_write_i32(resp, mcluster->telemetry_push_interval_ms > 0
                                         ? mcluster->telemetry_push_interval_ms
                                         : (5 * 60 * 1000));

        /* Response: TelemetryMaxBytes */
        rd_kafka_buf_write_i32(resp, 10000);

        /* Response: DeltaTemporality */
        rd_kafka_buf_write_bool(resp, rd_true);

        /* Response: #RequestedMetrics */
        rd_kafka_buf_write_arraycnt(resp, mcluster->metrics_cnt);

        for (i = 0; i < mcluster->metrics_cnt; i++)
                rd_kafka_buf_write_str(resp, mcluster->metrics[i], -1);

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}

/**
 * @brief Handle PushTelemetry
 */

static void rd_kafka_mock_handle_PushTelemetry_decoded_NumberDataPoint(
    void *opaque,
    const opentelemetry_proto_metrics_v1_NumberDataPoint *decoded) {
        rd_kafka_broker_t *rkb = opaque;
        if (decoded->which_value ==
            opentelemetry_proto_metrics_v1_NumberDataPoint_as_int_tag)
                rd_rkb_log(rkb, LOG_INFO, "MOCKTELEMETRY",
                           "NumberDataPoint int value: %" PRId64
                           " time: %" PRIu64,
                           decoded->value.as_int, decoded->time_unix_nano);
        else if (decoded->which_value ==
                 opentelemetry_proto_metrics_v1_NumberDataPoint_as_double_tag)
                rd_rkb_log(rkb, LOG_INFO, "MOCKTELEMETRY",
                           "NumberDataPoint double value: %f time: %" PRIu64,
                           decoded->value.as_double, decoded->time_unix_nano);
}

static void
rd_kafka_mock_handle_PushTelemetry_decoded_int64(void *opaque,
                                                 int64_t int64_value) {
        rd_kafka_broker_t *rkb = opaque;
        rd_rkb_log(rkb, LOG_INFO, "MOCKTELEMETRY", "int64 value: %" PRId64,
                   int64_value);
}

static void
rd_kafka_mock_handle_PushTelemetry_decoded_string(void *opaque,
                                                  const uint8_t *decoded) {
        rd_kafka_broker_t *rkb = opaque;
        rd_rkb_log(rkb, LOG_INFO, "MOCKTELEMETRY", "string value: %s", decoded);
}

static void rd_kafka_mock_handle_PushTelemetry_decoded_type(
    void *opaque,
    rd_kafka_telemetry_metric_type_t type) {
        rd_kafka_broker_t *rkb = opaque;
        rd_rkb_log(rkb, LOG_INFO, "MOCKTELEMETRY", "Metric type: %d", type);
}

static void rd_kafka_mock_handle_PushTelemetry_decode_error(void *opaque,
                                                            const char *error,
                                                            ...) {
        rd_kafka_broker_t *rkb = opaque;
        va_list ap;
        va_start(ap, error);
        rd_rkb_log(rkb, LOG_ERR, "MOCKTELEMETRY", error, ap);
        va_end(ap);
        rd_assert(!*"Failure while decoding telemetry data");
}

void rd_kafka_mock_handle_PushTelemetry_payload(rd_kafka_broker_t *rkb,
                                                void *payload,
                                                size_t size) {
        rd_kafka_telemetry_decode_interface_t decode_interface = {
            .decoded_string = rd_kafka_mock_handle_PushTelemetry_decoded_string,
            .decoded_NumberDataPoint =
                rd_kafka_mock_handle_PushTelemetry_decoded_NumberDataPoint,
            .decoded_int64 = rd_kafka_mock_handle_PushTelemetry_decoded_int64,
            .decoded_type  = rd_kafka_mock_handle_PushTelemetry_decoded_type,
            .decode_error  = rd_kafka_mock_handle_PushTelemetry_decode_error,
            .opaque        = rkb,
        };
        rd_kafka_telemetry_decode_metrics(&decode_interface, payload, size);
}

static int rd_kafka_mock_handle_PushTelemetry(rd_kafka_mock_connection_t *mconn,
                                              rd_kafka_buf_t *rkbuf) {
        rd_kafka_broker_t *rkb            = mconn->broker->cluster->dummy_rkb;
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafka_Uuid_t ClientInstanceId;
        int32_t SubscriptionId;
        rd_bool_t terminating;
        int8_t CompressionType;
        rd_kafka_compression_t compression_type = RD_KAFKA_COMPRESSION_NONE;
        rd_kafkap_bytes_t metrics;
        rd_kafka_resp_err_t err;

        rd_kafka_buf_read_uuid(rkbuf, &ClientInstanceId);
        rd_kafka_buf_read_i32(rkbuf, &SubscriptionId);
        rd_kafka_buf_read_bool(rkbuf, &terminating);
        rd_kafka_buf_read_i8(rkbuf, &CompressionType);
        compression_type = CompressionType;
        rd_kafka_buf_read_kbytes(rkbuf, &metrics);

        void *uncompressed_payload      = NULL;
        size_t uncompressed_payload_len = 0;
        rd_assert(metrics.data != NULL);

        if (compression_type != RD_KAFKA_COMPRESSION_NONE) {
                rd_rkb_log(rkb, LOG_DEBUG, "MOCKTELEMETRY",
                           "Compression type %s",
                           rd_kafka_compression2str(compression_type));
                int err_uncompress =
                    rd_kafka_telemetry_uncompress_metrics_payload(
                        rkb, compression_type, (void *)metrics.data,
                        metrics.len, &uncompressed_payload,
                        &uncompressed_payload_len);
                if (err_uncompress) {
                        rd_kafka_dbg(mcluster->rk, MOCK, "MOCKTELEMETRY",
                                     "Failed to uncompress "
                                     "telemetry payload.");
                        goto err_parse;
                }
        } else {
                uncompressed_payload     = (void *)metrics.data;
                uncompressed_payload_len = metrics.len;
        }

        rd_assert(uncompressed_payload != NULL);
        rd_kafka_mock_handle_PushTelemetry_payload(rkb, uncompressed_payload,
                                                   uncompressed_payload_len);
        if (compression_type != RD_KAFKA_COMPRESSION_NONE)
                rd_free(uncompressed_payload);

        /* ThrottleTime */
        rd_kafka_buf_write_i32(resp, 0);

        /* ErrorCode */
        err = rd_kafka_mock_next_request_error(mconn, resp);
        rd_kafka_buf_write_i16(resp, err);

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;

err_parse:
        rd_kafka_buf_destroy(resp);
        return -1;
}
static void rd_kafka_mock_handle_ConsumerGroupHeartbeat_write_TopicPartitions(
    rd_kafka_buf_t *rkbuf,
    rd_kafka_topic_partition_list_t *rktparlist) {
        const rd_kafka_topic_partition_field_t fields[] = {
            RD_KAFKA_TOPIC_PARTITION_FIELD_PARTITION,
            RD_KAFKA_TOPIC_PARTITION_FIELD_END};
        rd_kafka_topic_partition_list_sort_by_topic_id(rktparlist);
        rd_kafka_buf_write_topic_partitions(
            rkbuf, rktparlist, rd_false /*don't skip invalid offsets*/,
            rd_false /*any offset*/, rd_true /* use_topic id */,
            rd_false /* don't use topic name */, fields);
}

static int
rd_kafka_mock_handle_ConsumerGroupHeartbeat(rd_kafka_mock_connection_t *mconn,
                                            rd_kafka_buf_t *rkbuf) {
        const rd_bool_t log_decode_errors   = rd_true;
        rd_bool_t sent_assignment_parse_err = rd_false;
        rd_kafka_mock_cluster_t *mcluster   = mconn->broker->cluster;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafka_topic_partition_list_t *sent_assignment     = NULL,
                                        *existing_assignment = NULL,
                                        *next_assignment     = NULL;
        rd_kafka_topic_partition_t *rktpar;
        rd_kafkap_str_t GroupId, MemberId, InstanceId, RackId, ServerAssignor,
            SubscribedTopicRegex;
        rd_kafkap_str_t *SubscribedTopicNames = NULL;
        int32_t MemberEpoch, RebalanceTimeoutMs, SubscribedTopicNamesCnt;
        int32_t i;
        rd_kafka_resp_err_t err;
        rd_kafka_mock_cgrp_consumer_t *mcgrp         = NULL;
        rd_kafka_mock_broker_t *mrkb                 = NULL;
        rd_kafka_mock_cgrp_consumer_member_t *member = NULL;

        /* GroupId */
        rd_kafka_buf_read_str(rkbuf, &GroupId);
        rd_assert(!RD_KAFKAP_STR_IS_NULL(&GroupId));

        /* MemberId */
        rd_kafka_buf_read_str(rkbuf, &MemberId);
        rd_assert(!RD_KAFKAP_STR_IS_NULL(&MemberId));

        /* MemberEpoch */
        rd_kafka_buf_read_i32(rkbuf, &MemberEpoch);
        rd_assert(MemberEpoch >= -2);

        /* InstanceId */
        rd_kafka_buf_read_str(rkbuf, &InstanceId);

        /* RackId */
        rd_kafka_buf_read_str(rkbuf, &RackId);

        /* RebalanceTimeoutMs */
        rd_kafka_buf_read_i32(rkbuf, &RebalanceTimeoutMs);
        rd_assert(RebalanceTimeoutMs >= -1);

        /* #SubscribedTopicNames */
        rd_kafka_buf_read_arraycnt(rkbuf, &SubscribedTopicNamesCnt,
                                   RD_KAFKAP_TOPICS_MAX);
        if (SubscribedTopicNamesCnt >= 0) {
                SubscribedTopicNames = rd_calloc(
                    SubscribedTopicNamesCnt > 0 ? SubscribedTopicNamesCnt : 1,
                    sizeof(rd_kafkap_str_t));
                for (i = 0; i < SubscribedTopicNamesCnt; i++) {
                        /* SubscribedTopicNames[i] */
                        rd_kafka_buf_read_str(rkbuf, &SubscribedTopicNames[i]);
                }
        }

        rd_kafka_buf_read_str(rkbuf, &SubscribedTopicRegex);

        /* ServerAssignor */
        rd_kafka_buf_read_str(rkbuf, &ServerAssignor);

        /* #TopicPartitions */
        const rd_kafka_topic_partition_field_t sent_assignment_fields[] = {
            RD_KAFKA_TOPIC_PARTITION_FIELD_PARTITION,
            RD_KAFKA_TOPIC_PARTITION_FIELD_END};
        sent_assignment = rd_kafka_buf_read_topic_partitions_nullable(
            rkbuf, rd_true, rd_false, 0, sent_assignment_fields,
            &sent_assignment_parse_err);
        if (sent_assignment_parse_err)
                goto err_parse;

        if (sent_assignment) {
                rd_kafka_Uuid_t last_topic_id = RD_KAFKA_UUID_ZERO;
                rd_kafka_mock_topic_t *mtopic = NULL;
                existing_assignment =
                    rd_kafka_topic_partition_list_new(sent_assignment->cnt);
                RD_KAFKA_TPLIST_FOREACH(rktpar, sent_assignment) {
                        rd_kafka_Uuid_t current_topic_id =
                            rd_kafka_topic_partition_get_topic_id(rktpar);

                        if (rd_kafka_Uuid_cmp(current_topic_id,
                                              last_topic_id) != 0) {
                                last_topic_id = current_topic_id;
                                mtopic        = rd_kafka_mock_topic_find_by_id(
                                    mcluster, current_topic_id);
                        }

                        if (mtopic) {
                                rd_kafka_topic_partition_t *added =
                                    rd_kafka_topic_partition_list_add(
                                        existing_assignment, "",
                                        rktpar->partition);
                                rd_kafka_topic_partition_set_topic_id(
                                    added, last_topic_id);
                        }
                }
        }

        /* Inject error, if any */
        err = rd_kafka_mock_next_request_error(mconn, resp);

        if (!err) {
                mrkb = rd_kafka_mock_cluster_get_coord(
                    mcluster, RD_KAFKA_COORD_GROUP, &GroupId);

                if (!mrkb)
                        err = RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE;
                else if (mrkb != mconn->broker)
                        err = RD_KAFKA_RESP_ERR_NOT_COORDINATOR;
        }

        /* A member (re-)joining (MemberEpoch 0) must provide a
         * RebalanceTimeoutMs and a subscription (topic names or regex),
         * otherwise the coordinator rejects the request. This mirrors the
         * broker-side validation and catches malformed (re-)join heartbeats. */
        if (!err && MemberEpoch == 0 &&
            (RebalanceTimeoutMs == -1 ||
             (!SubscribedTopicNames &&
              RD_KAFKAP_STR_IS_NULL(&SubscribedTopicRegex))))
                err = RD_KAFKA_RESP_ERR_INVALID_REQUEST;

        if (!err) {
                mtx_lock(&mcluster->lock);
                mcgrp = rd_kafka_mock_cgrp_consumer_get(mcluster, &GroupId);
                rd_assert(mcgrp);

                member = rd_kafka_mock_cgrp_consumer_member_add(
                    mcgrp, mconn, &MemberId, &InstanceId, SubscribedTopicNames,
                    SubscribedTopicNamesCnt, &SubscribedTopicRegex);

                if (member) {
                        if (MemberEpoch >= 0) {
                                next_assignment =
                                    rd_kafka_mock_cgrp_consumer_member_next_assignment(
                                        member, existing_assignment,
                                        &MemberEpoch);
                                if (MemberEpoch < 0) {
                                        err =
                                            RD_KAFKA_RESP_ERR_FENCED_MEMBER_EPOCH;
                                }
                        } else {
                                rd_kafka_mock_cgrp_consumer_member_leave(
                                    mcgrp, member, MemberEpoch == -2);
                                member = NULL;
                        }
                } else {
                        err = RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID;
                }
                mtx_unlock(&mcluster->lock);
        } else {
                switch (err) {
                case RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID:
                case RD_KAFKA_RESP_ERR_FENCED_MEMBER_EPOCH:
                        /* In case the error was set
                         * by `rd_kafka_mock_next_request_error`. */
                        MemberEpoch = -1;
                        mtx_lock(&mcluster->lock);
                        mcgrp = rd_kafka_mock_cgrp_consumer_find(mcluster,
                                                                 &GroupId);
                        if (!mcgrp) {
                                mtx_unlock(&mcluster->lock);
                                break;
                        }

                        rd_kafka_mock_cgrp_consumer_member_t *member =
                            rd_kafka_mock_cgrp_consumer_member_find(mcgrp,
                                                                    &MemberId);
                        if (member) {
                                rd_kafka_mock_cgrp_consumer_member_fenced(
                                    mcgrp, member);
                                member = NULL;
                        }
                        mtx_unlock(&mcluster->lock);
                default:
                        break;
                }
        }

        /*
         * Construct response
         */
        /* Response: Throttle */
        rd_kafka_buf_write_i32(resp, 0);

        /* Response: ErrorCode */
        rd_kafka_buf_write_i16(resp, err);

        /* Response: ErrorMessage */
        rd_kafka_buf_write_str(resp, rd_kafka_err2str(err), -1);

        /* Response: MemberId */
        if (!err && member)
                rd_kafka_buf_write_str(resp, member->id, -1);
        else
                rd_kafka_buf_write_str(resp, NULL, -1);

        /* Response: MemberEpoch */
        rd_kafka_buf_write_i32(resp, MemberEpoch);

        /* Response: HeartbeatIntervalMs */
        if (mcgrp) {
                rd_kafka_buf_write_i32(resp, mcgrp->heartbeat_interval_ms);
        } else {
                rd_kafka_buf_write_i32(resp, 0);
        }

        if (next_assignment) {
                /* Response: Assignment */
                rd_kafka_buf_write_i8(resp, 1);

                /* Response: TopicPartitions */
                rd_kafka_mock_handle_ConsumerGroupHeartbeat_write_TopicPartitions(
                    resp, next_assignment);

                rd_kafka_buf_write_tags_empty(resp);
        } else {
                /* Response: Assignment */
                rd_kafka_buf_write_i8(resp, -1);
        }

        rd_kafka_mock_connection_send_response(mconn, resp);

        rd_free(SubscribedTopicNames);
        RD_IF_FREE(sent_assignment, rd_kafka_topic_partition_list_destroy);
        RD_IF_FREE(existing_assignment, rd_kafka_topic_partition_list_destroy);
        RD_IF_FREE(next_assignment, rd_kafka_topic_partition_list_destroy);
        return 0;

err_parse:
        RD_IF_FREE(SubscribedTopicNames, rd_free);
        RD_IF_FREE(sent_assignment, rd_kafka_topic_partition_list_destroy);
        RD_IF_FREE(existing_assignment, rd_kafka_topic_partition_list_destroy);
        RD_IF_FREE(next_assignment, rd_kafka_topic_partition_list_destroy);
        rd_kafka_buf_destroy(resp);
        return -1;
}

/**
 * @brief Helper to write assignment TopicPartitions to ShareGroupHeartbeat
 * response.
 */
static void rd_kafka_mock_handle_ShareGroupHeartbeat_write_TopicPartitions(
    rd_kafka_buf_t *resp,
    rd_kafka_topic_partition_list_t *assignment) {
        const rd_kafka_topic_partition_field_t fields[] = {
            RD_KAFKA_TOPIC_PARTITION_FIELD_PARTITION,
            RD_KAFKA_TOPIC_PARTITION_FIELD_END};

        rd_kafka_topic_partition_list_sort_by_topic_id(assignment);
        rd_kafka_buf_write_topic_partitions(
            resp, assignment, rd_false /* don't skip invalid offsets */,
            rd_false /* any offset */, rd_true /* use topic id */,
            rd_false /* don't use topic name */, fields);
}

/**
 * @brief Handle ShareGroupHeartbeat request (API Key 76).
 */
static int
rd_kafka_mock_handle_ShareGroupHeartbeat(rd_kafka_mock_connection_t *mconn,
                                         rd_kafka_buf_t *rkbuf) {
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_buf_t *resp;
        rd_kafkap_str_t GroupId, MemberId, RackId;
        rd_kafkap_str_t *SubscribedTopicNames = NULL;
        int32_t MemberEpoch                   = 0, SubscribedTopicNamesCnt;
        int32_t i;
        rd_kafka_resp_err_t err                   = RD_KAFKA_RESP_ERR_NO_ERROR;
        rd_kafka_mock_sharegroup_t *mshgrp        = NULL;
        rd_kafka_mock_sharegroup_member_t *member = NULL;
        rd_bool_t assignment_changed              = rd_false;

        resp = rd_kafka_mock_buf_new_response(rkbuf);

        /* Inject Error */
        err = rd_kafka_mock_next_request_error(mconn, resp);
        if (err)
                goto build_response;

        /* GroupId */
        rd_kafka_buf_read_str(rkbuf, &GroupId);

        /* Coordinator check */
        {
                rd_kafka_mock_broker_t *mrkb;

                mrkb = rd_kafka_mock_cluster_get_coord(
                    mcluster, RD_KAFKA_COORD_GROUP, &GroupId);

                if (!mrkb)
                        err = RD_KAFKA_RESP_ERR_COORDINATOR_NOT_AVAILABLE;
                else if (mrkb != mconn->broker)
                        err = RD_KAFKA_RESP_ERR_NOT_COORDINATOR;
        }

        if (err)
                goto build_response;

        /* MemberId */
        rd_kafka_buf_read_str(rkbuf, &MemberId);

        /* MemberEpoch */
        rd_kafka_buf_read_i32(rkbuf, &MemberEpoch);

        /* RackId (nullable) */
        rd_kafka_buf_read_str(rkbuf, &RackId);

        /* SubscribedTopicNames array (nullable) */
        rd_kafka_buf_read_arraycnt(rkbuf, &SubscribedTopicNamesCnt,
                                   RD_KAFKAP_TOPICS_MAX);
        if (SubscribedTopicNamesCnt >= 0) {
                SubscribedTopicNames = rd_calloc(
                    SubscribedTopicNamesCnt > 0 ? SubscribedTopicNamesCnt : 1,
                    sizeof(rd_kafkap_str_t));
                for (i = 0; i < SubscribedTopicNamesCnt; i++) {
                        rd_kafka_buf_read_str(rkbuf, &SubscribedTopicNames[i]);
                }
        }

        {
                mtx_lock(&mcluster->lock);

                mshgrp = rd_kafka_mock_sharegroup_get(mcluster, &GroupId);

                if (MemberEpoch == -1) {
                        /* LEAVE: Member wants to leave */
                        member = rd_kafka_mock_sharegroup_member_find(
                            mshgrp, &MemberId);
                        if (member) {
                                rd_kafka_mock_sharegroup_member_destroy(mshgrp,
                                                                        member);
                                member             = NULL;
                                assignment_changed = rd_true;
                        }

                } else if (MemberEpoch == 0) {
                        /* JOIN: New member wants to join */

                        /* Check max group size before allowing join */
                        if (mshgrp->max_size > 0 &&
                            !rd_kafka_mock_sharegroup_member_find(mshgrp,
                                                                  &MemberId) &&
                            mshgrp->member_cnt >= mshgrp->max_size) {
                                err = RD_KAFKA_RESP_ERR_GROUP_MAX_SIZE_REACHED;
                                mtx_unlock(&mcluster->lock);
                                goto build_response;
                        }

                        member = rd_kafka_mock_sharegroup_member_get(
                            mshgrp, &MemberId, MemberEpoch, mconn);

                        if (member) {
                                if (rd_kafka_mock_sharegroup_member_subscribed_topic_names_set(
                                        member, SubscribedTopicNames,
                                        SubscribedTopicNamesCnt)) {
                                        assignment_changed = rd_true;
                                } else {
                                        /* New member always triggers
                                         * recalculation */
                                        assignment_changed = rd_true;
                                }
                                MemberEpoch = member->member_epoch;
                        } else {
                                err = RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID;
                        }

                } else {
                        /* HEARTBEAT: Existing member heartbeat */
                        member = rd_kafka_mock_sharegroup_member_find(
                            mshgrp, &MemberId);
                        if (!member) {
                                err = RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID;
                        } else if (MemberEpoch > member->member_epoch) {
                                /* Client epoch is ahead of server - indicates
                                 * a bug or stale coordinator. */
                                err = RD_KAFKA_RESP_ERR_FENCED_MEMBER_EPOCH;
                        } else if (MemberEpoch < member->member_epoch) {
                                /* Client epoch is behind. Allow if it matches
                                 * the previous epoch (response with bumped
                                 * epoch may have been lost). Otherwise fence.
                                 */
                                if (MemberEpoch !=
                                    member->previous_member_epoch) {
                                        err =
                                            RD_KAFKA_RESP_ERR_FENCED_MEMBER_EPOCH;
                                } else {
                                        /* Accept previous epoch - client is
                                         * catching up */
                                        member->conn = mconn;
                                        MemberEpoch  = member->member_epoch;
                                        rd_kafka_mock_sharegroup_member_active(
                                            mshgrp, member);
                                }
                        } else {
                                /* Epoch matches - normal heartbeat */
                                /* Check for subscription changes */
                                if (SubscribedTopicNamesCnt >= 0 &&
                                    rd_kafka_mock_sharegroup_member_subscribed_topic_names_set(
                                        member, SubscribedTopicNames,
                                        SubscribedTopicNamesCnt)) {
                                        assignment_changed = rd_true;
                                }
                                member->conn = mconn;
                                MemberEpoch  = member->member_epoch;
                                rd_kafka_mock_sharegroup_member_active(mshgrp,
                                                                       member);
                        }
                }

                /* Recalculate assignments if needed */
                if (assignment_changed && mshgrp->member_cnt > 0) {
                        rd_kafka_mock_sharegroup_assignment_recalculate(mshgrp);
                        if (member)
                                MemberEpoch = member->member_epoch;
                }

                mtx_unlock(&mcluster->lock);
        }

build_response:

        /* ThrottleTimeMs */
        rd_kafka_buf_write_i32(resp, 0);

        /* ErrorCode */
        rd_kafka_buf_write_i16(resp, err);

        /* ErrorMessage */
        if (err)
                rd_kafka_buf_write_str(resp, rd_kafka_err2str(err), -1);
        else
                rd_kafka_buf_write_str(resp, NULL, -1);

        /* MemberId */
        if (!err && member)
                rd_kafka_buf_write_str(resp, member->id, -1);
        else
                rd_kafka_buf_write_str(resp, NULL, -1);

        /* MemberEpoch */
        rd_kafka_buf_write_i32(resp, MemberEpoch);

        /* HeartbeatIntervalMs */
        if (mshgrp)
                rd_kafka_buf_write_i32(resp, mshgrp->heartbeat_interval_ms);
        else
                rd_kafka_buf_write_i32(resp, 5000);

        /* Assignment */
        if (!err && member && member->assignment) {
                /* Send assignment even if empty (cnt == 0).
                 * Null (-1) means "no change", while an empty assignment
                 * means "you have 0 partitions". */
                rd_kafka_buf_write_i8(resp, 1);
                rd_kafka_mock_handle_ShareGroupHeartbeat_write_TopicPartitions(
                    resp, member->assignment);
                rd_kafka_buf_write_tags_empty(resp);
        } else {
                rd_kafka_buf_write_i8(resp, -1);
        }

        rd_kafka_buf_write_tags_empty(resp);

        rd_kafka_mock_connection_send_response(mconn, resp);

        RD_IF_FREE(SubscribedTopicNames, rd_free);
        return 0;

err_parse:
        RD_IF_FREE(SubscribedTopicNames, rd_free);
        rd_kafka_buf_destroy(resp);
        return -1;
}

static rd_kafka_mock_sgrp_partmeta_t *
rd_kafka_mock_sgrp_partmeta_find(rd_kafka_mock_sharegroup_t *sgrp,
                                 rd_kafka_Uuid_t topic_id,
                                 int32_t partition) {
        rd_kafka_mock_sgrp_partmeta_t *pmeta;

        TAILQ_FOREACH(pmeta, &sgrp->partitions, link) {
                if (pmeta->partition != partition)
                        continue;
                if (!rd_kafka_Uuid_cmp(pmeta->topic_id, topic_id))
                        return pmeta;
        }

        return NULL;
}

static rd_kafka_mock_sgrp_partmeta_t *
rd_kafka_mock_sgrp_partmeta_get(rd_kafka_mock_sharegroup_t *sgrp,
                                rd_kafka_Uuid_t topic_id,
                                int32_t partition,
                                const rd_kafka_mock_partition_t *mpart) {
        rd_kafka_mock_sgrp_partmeta_t *pmeta;
        int64_t log_start;
        int64_t log_end;

        pmeta = rd_kafka_mock_sgrp_partmeta_find(sgrp, topic_id, partition);
        if (pmeta) {
                log_start = mpart->start_offset;
                log_end   = mpart->end_offset;
                if (log_start > pmeta->spso) {
                        /* Log retention moved start_offset past SPSO.
                         * Archive all in-flight records below the new
                         * SPSO — they are no longer in the log. */
                        rd_kafka_mock_sgrp_record_state_t *state, *tmp;
                        TAILQ_FOREACH_SAFE(state, &pmeta->inflight, link, tmp) {
                                if (state->offset >= log_start)
                                        continue;
                                if (state->state ==
                                    RD_KAFKA_MOCK_SGRP_RECORD_ACQUIRED)
                                        pmeta->acquired_cnt--;
                                state->state =
                                    RD_KAFKA_MOCK_SGRP_RECORD_ARCHIVED;
                                RD_IF_FREE(state->owner_member_id, rd_free);
                                state->owner_member_id = NULL;
                                state->lock_expiry_ts  = 0;
                        }
                        pmeta->spso = log_start;
                }
                if (log_end > log_start) {
                        int64_t new_speo = log_end - 1;
                        if (new_speo > pmeta->speo)
                                pmeta->speo = new_speo;
                }
                return pmeta;
        }

        pmeta            = rd_calloc(1, sizeof(*pmeta));
        pmeta->topic_id  = topic_id;
        pmeta->partition = partition;
        /* Initialize SPSO based on auto.offset.reset:
         * 0 = latest (end of log), 1 = earliest (start of log). */
        if (sgrp->auto_offset_reset == 1)
                pmeta->spso = mpart->start_offset;
        else
                pmeta->spso = mpart->end_offset;
        if (mpart->end_offset > mpart->start_offset)
                pmeta->speo = mpart->end_offset - 1;
        else
                pmeta->speo = mpart->start_offset - 1;
        TAILQ_INIT(&pmeta->inflight);

        TAILQ_INSERT_TAIL(&sgrp->partitions, pmeta, link);
        sgrp->partition_cnt++;

        return pmeta;
}

static rd_kafka_mock_sgrp_record_state_t *
rd_kafka_mock_sgrp_record_state_find(rd_kafka_mock_sgrp_partmeta_t *pmeta,
                                     int64_t offset) {
        rd_kafka_mock_sgrp_record_state_t *state;

        TAILQ_FOREACH(state, &pmeta->inflight, link) {
                if (state->offset == offset)
                        return state;
        }

        return NULL;
}

static rd_kafka_mock_sgrp_record_state_t *
rd_kafka_mock_sgrp_record_state_get(rd_kafka_mock_sgrp_partmeta_t *pmeta,
                                    int64_t offset) {
        rd_kafka_mock_sgrp_record_state_t *state;

        state = rd_kafka_mock_sgrp_record_state_find(pmeta, offset);
        if (state)
                return state;

        state         = rd_calloc(1, sizeof(*state));
        state->offset = offset;
        state->state  = RD_KAFKA_MOCK_SGRP_RECORD_AVAILABLE;
        TAILQ_INSERT_TAIL(&pmeta->inflight, state, link);
        pmeta->inflight_cnt++;

        return state;
}

static int32_t
rd_kafka_mock_msgset_est_record_size(const rd_kafka_mock_msgset_t *mset) {
        int64_t record_cnt = mset->last_offset - mset->first_offset + 1;
        int32_t size;

        if (record_cnt <= 0)
                return 1;

        size = (int32_t)(RD_KAFKAP_BYTES_LEN(&mset->bytes) / record_cnt);
        if (size <= 0)
                size = 1;

        return size;
}

/**
 * @brief Check if an offset belongs to an aborted transaction on this
 * partition.
 *
 * @locks mcluster->lock MUST be held (or single-threaded context).
 */
static rd_bool_t
rd_kafka_mock_offset_is_aborted(const rd_kafka_mock_partition_t *mpart,
                                int64_t offset,
                                int64_t pid_id) {
        rd_kafka_mock_aborted_txn_t *mabort;
        TAILQ_FOREACH(mabort, &mpart->aborted_txns, link) {
                if (mabort->pid_id == pid_id &&
                    offset >= mabort->first_offset &&
                    offset <= mabort->last_offset)
                        return rd_true;
        }
        return rd_false;
}

static void rd_kafka_mock_sgrp_acquire_available_offsets(
    rd_kafka_mock_sgrp_partmeta_t *pmeta,
    const rd_kafka_mock_partition_t *mpart,
    const rd_kafkap_str_t *member_id,
    rd_ts_t lock_expiry_ts,
    int max_delivery_attempts,
    int max_record_locks,
    int64_t *remaining_records,
    int64_t *remaining_bytes,
    int *acquired_cnt,
    int64_t *acquired_bytes,
    int isolation_level) {
        int64_t offset;
        int64_t upper_bound = pmeta->speo;

        /* For read_committed, cap acquisition at LSO - 1.
         * When lso == 0 (open txn starts at offset 0), upper_bound
         * becomes -1, which makes the loop body unreachable —
         * correct behavior: block all reads until the txn resolves. */
        if (isolation_level == 1 && mpart->lso - 1 < upper_bound)
                upper_bound = mpart->lso - 1;

        for (offset = pmeta->spso; offset <= upper_bound; offset++) {
                const rd_kafka_mock_msgset_t *mset;
                rd_kafka_mock_sgrp_record_state_t *state;
                int32_t est_size;

                if (remaining_records && *remaining_records == 0)
                        break;
                if (remaining_bytes && *remaining_bytes == 0)
                        break;

                /* Check max acquired record locks per partition */
                if (max_record_locks > 0 &&
                    pmeta->acquired_cnt >= max_record_locks)
                        break;

                state = rd_kafka_mock_sgrp_record_state_find(pmeta, offset);
                if (state &&
                    state->state != RD_KAFKA_MOCK_SGRP_RECORD_AVAILABLE)
                        continue;

                /* Check max delivery attempts: if the record has already
                 * been acquired (and released/expired) too many times,
                 * archive it instead of re-acquiring. */
                if (max_delivery_attempts > 0 && state &&
                    state->delivery_count >= max_delivery_attempts) {
                        state->state = RD_KAFKA_MOCK_SGRP_RECORD_ARCHIVED;
                        RD_IF_FREE(state->owner_member_id, rd_free);
                        state->owner_member_id = NULL;
                        state->lock_expiry_ts  = 0;
                        continue;
                }

                mset = rd_kafka_mock_msgset_find(mpart, offset, rd_false);
                if (!mset)
                        continue;

                /* For read_committed: skip aborted transactional data batches
                 * by archiving them immediately. */
                if (isolation_level == 1) {
                        int16_t attrs     = 0;
                        int64_t batch_pid = 0;
                        memcpy(&attrs,
                               (const char *)mset->bytes.data +
                                   RD_KAFKAP_MSGSET_V2_OF_Attributes,
                               sizeof(attrs));
                        attrs = be16toh(attrs);
                        if (attrs & RD_KAFKA_MSGSET_V2_ATTR_TRANSACTIONAL) {
                                memcpy(&batch_pid,
                                       (const char *)mset->bytes.data +
                                           RD_KAFKAP_MSGSET_V2_OF_ProducerId,
                                       sizeof(batch_pid));
                                batch_pid = be64toh(batch_pid);
                                if (!(attrs &
                                      RD_KAFKA_MSGSET_V2_ATTR_CONTROL) &&
                                    rd_kafka_mock_offset_is_aborted(
                                        mpart, offset, batch_pid)) {
                                        /* Archive aborted data batch */
                                        state =
                                            rd_kafka_mock_sgrp_record_state_get(
                                                pmeta, offset);
                                        state->state =
                                            RD_KAFKA_MOCK_SGRP_RECORD_ARCHIVED;
                                        RD_IF_FREE(state->owner_member_id,
                                                   rd_free);
                                        state->owner_member_id = NULL;
                                        state->lock_expiry_ts  = 0;
                                        continue;
                                }
                        }
                }

                est_size = rd_kafka_mock_msgset_est_record_size(mset);
                if (remaining_bytes && *remaining_bytes > 0 &&
                    est_size > *remaining_bytes)
                        break;

                state = rd_kafka_mock_sgrp_record_state_get(pmeta, offset);
                state->state          = RD_KAFKA_MOCK_SGRP_RECORD_ACQUIRED;
                state->lock_expiry_ts = lock_expiry_ts;
                state->delivery_count++;
                RD_IF_FREE(state->owner_member_id, rd_free);
                state->owner_member_id = RD_KAFKAP_STR_DUP(member_id);
                pmeta->acquired_cnt++;

                (*acquired_cnt)++;
                *acquired_bytes += est_size;
                if (remaining_records && *remaining_records > 0)
                        (*remaining_records)--;
                if (remaining_bytes && *remaining_bytes > 0)
                        (*remaining_bytes) -= est_size;
        }
}

static void rd_kafka_mock_sgrp_partmeta_prune_archived(
    rd_kafka_mock_sgrp_partmeta_t *pmeta) {
        rd_kafka_mock_sgrp_record_state_t *state, *tmp;

        TAILQ_FOREACH_SAFE(state, &pmeta->inflight, link, tmp) {
                if (state->state != RD_KAFKA_MOCK_SGRP_RECORD_ARCHIVED &&
                    state->state != RD_KAFKA_MOCK_SGRP_RECORD_ACKNOWLEDGED)
                        continue;
                if (state->offset >= pmeta->spso)
                        continue;

                TAILQ_REMOVE(&pmeta->inflight, state, link);
                pmeta->inflight_cnt--;
                rd_free(state->owner_member_id);
                rd_free(state);
        }
}

/**
 * @brief Write all acquired record batches for the given partition and member
 *        into the response buffer as a single Records field (compact bytes
 *        containing concatenated RecordBatches).
 *
 * @returns the total number of record data bytes written (0 if none).
 */
static size_t rd_kafka_mock_sgrp_write_acquired_records(
    rd_kafka_buf_t *resp,
    rd_kafka_mock_sgrp_partmeta_t *pmeta,
    const rd_kafka_mock_partition_t *mpart,
    const rd_kafkap_str_t *member_id,
    rd_ts_t now) {
        rd_list_t msgsets;
        int64_t offset;
        size_t total_len = 0;
        int i;

        rd_list_init(&msgsets, 16, NULL); /* no free_cb: borrowed ptrs */

        /* Collect unique msgsets containing acquired records for this member */
        for (offset = pmeta->spso; offset <= pmeta->speo; offset++) {
                rd_kafka_mock_sgrp_record_state_t *state =
                    rd_kafka_mock_sgrp_record_state_find(pmeta, offset);
                const rd_kafka_mock_msgset_t *mset;

                if (!state ||
                    state->state != RD_KAFKA_MOCK_SGRP_RECORD_ACQUIRED)
                        continue;

                if (state->lock_expiry_ts && state->lock_expiry_ts <= now)
                        continue;

                if (rd_kafkap_str_cmp_str(member_id, state->owner_member_id))
                        continue;

                mset = rd_kafka_mock_msgset_find(mpart, offset, rd_false);
                if (!mset)
                        continue;

                /* Deduplicate: multiple offsets may fall in the same batch */
                if (rd_list_find(&msgsets, mset, rd_list_cmp_ptr))
                        continue;

                rd_list_add(&msgsets, (void *)mset);
                total_len += RD_KAFKAP_BYTES_LEN(&mset->bytes);
        }

        if (rd_list_cnt(&msgsets) == 0) {
                /* No acquired records: write empty compact bytes
                 * (uvarint(1) = 0 data bytes).  Do NOT write NULL
                 * (uvarint(0)) because the client reads this field
                 * with rd_kafka_buf_read_arraycnt() which decodes
                 * NULL as -1 and triggers a parse failure. */
                rd_list_destroy(&msgsets);
                rd_kafka_buf_write_uvarint(resp, 1);
                return 0;
        }

        /* Write compact bytes length prefix (N+1 encoding) */
        rd_kafka_buf_write_uvarint(resp, (uint64_t)(total_len + 1));

        /* Write each msgset's raw bytes back-to-back */
        for (i = 0; i < rd_list_cnt(&msgsets); i++) {
                const rd_kafka_mock_msgset_t *mset = rd_list_elem(&msgsets, i);
                rd_kafka_buf_write(resp, mset->bytes.data,
                                   RD_KAFKAP_BYTES_LEN(&mset->bytes));
        }

        rd_list_destroy(&msgsets);
        return total_len;
}

/**
 * @brief Temporary structure for accumulating acknowledgement batches
 *        during ShareFetch request parsing.
 */
struct rd_kafka_mock_sgrp_ack_entry {
        rd_kafka_Uuid_t topic_id;
        int32_t partition;
        int64_t first_offset;
        int64_t last_offset;
        int8_t ack_type;         /**< 0=GAP, 1=ACCEPT, 2=RELEASE, 3=REJECT */
        rd_kafka_resp_err_t err; /**< Per-batch ack result, set after apply */
};

/**
 * @brief Allocate and initialize a new ack entry.
 */
static struct rd_kafka_mock_sgrp_ack_entry *
rd_kafka_mock_sgrp_ack_entry_new(rd_kafka_Uuid_t topic_id,
                                 int32_t partition,
                                 int64_t first_offset,
                                 int64_t last_offset,
                                 int8_t ack_type) {
        struct rd_kafka_mock_sgrp_ack_entry *entry =
            rd_calloc(1, sizeof(*entry));
        entry->topic_id     = topic_id;
        entry->partition    = partition;
        entry->first_offset = first_offset;
        entry->last_offset  = last_offset;
        entry->ack_type     = ack_type;
        return entry;
}

/**
 * @brief Find the first ack error for the given (topic_id, partition) across
 *        all ack entries.  Returns NO_ERROR if no ack targeted this partition
 *        or all acks succeeded.
 */
static rd_kafka_resp_err_t
rd_kafka_mock_sgrp_ack_error_for_partition(const rd_list_t *ack_entries,
                                           rd_kafka_Uuid_t topic_id,
                                           int32_t partition) {
        int k;
        for (k = 0; k < rd_list_cnt(ack_entries); k++) {
                const struct rd_kafka_mock_sgrp_ack_entry *entry =
                    rd_list_elem(ack_entries, k);
                if (entry->partition == partition &&
                    !rd_kafka_Uuid_cmp(entry->topic_id, topic_id) && entry->err)
                        return entry->err;
        }
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}

/**
 * @brief Apply a single acknowledgement batch to share-group partition
 *        metadata.
 *
 * For GAP (0), ACCEPT (1) and REJECT (3): mark records as ARCHIVED.
 * For RELEASE (2): mark records as AVAILABLE.
 *
 * After applying, advance SPSO past contiguous ARCHIVED records so that
 * the share-partition start offset moves forward.
 *
 * @locks mcluster->lock MUST be held.
 */
static rd_kafka_resp_err_t
rd_kafka_mock_sgrp_apply_ack(rd_kafka_mock_sharegroup_t *sgrp,
                             rd_kafka_Uuid_t topic_id,
                             int32_t partition,
                             int64_t first_offset,
                             int64_t last_offset,
                             int8_t ack_type,
                             const rd_kafkap_str_t *member_id) {
        rd_kafka_mock_sgrp_partmeta_t *pmeta;
        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;
        int64_t offset;

        pmeta = rd_kafka_mock_sgrp_partmeta_find(sgrp, topic_id, partition);
        if (!pmeta)
                return RD_KAFKA_RESP_ERR_NO_ERROR;

        /* Pass 1: Validate all offsets in the range.
         * Acks for a partition in a single request are atomic —
         * all succeed or all fail together. */
        for (offset = first_offset; offset <= last_offset; offset++) {
                rd_kafka_mock_sgrp_record_state_t *state;

                /* Offsets below SPSO are already logically archived
                 * (e.g. due to log retention).  Acks for such
                 * records are silently accepted — no error is
                 * thrown for a record that is about to become
                 * Archived. */
                if (offset < pmeta->spso)
                        continue;

                state = rd_kafka_mock_sgrp_record_state_find(pmeta, offset);
                if (!state)
                        continue;

                /* Only the owning member may acknowledge acquired records.
                 * If the record's lock expired (reverted to Available),
                 * was re-acquired by another member, or is otherwise not
                 * in ACQUIRED state for this member, report
                 * INVALID_RECORD_STATE. */
                if (state->state != RD_KAFKA_MOCK_SGRP_RECORD_ACQUIRED ||
                    !state->owner_member_id ||
                    rd_kafkap_str_cmp_str(member_id, state->owner_member_id)) {
                        err = RD_KAFKA_RESP_ERR_INVALID_RECORD_STATE;
                        break;
                }
        }

        /* Pass 2: Apply state transitions only if validation passed. */
        if (!err) {
                for (offset = first_offset; offset <= last_offset; offset++) {
                        rd_kafka_mock_sgrp_record_state_t *state;

                        if (offset < pmeta->spso)
                                continue;

                        state =
                            rd_kafka_mock_sgrp_record_state_find(pmeta, offset);
                        if (!state)
                                continue;

                        switch (ack_type) {
                        case 1: /* ACCEPT -> Acknowledged */
                                pmeta->acquired_cnt--;
                                state->state =
                                    RD_KAFKA_MOCK_SGRP_RECORD_ACKNOWLEDGED;
                                rd_free(state->owner_member_id);
                                state->owner_member_id = NULL;
                                state->lock_expiry_ts  = 0;
                                break;
                        case 0: /* GAP -> Archived */
                        case 3: /* REJECT -> Archived */
                                pmeta->acquired_cnt--;
                                state->state =
                                    RD_KAFKA_MOCK_SGRP_RECORD_ARCHIVED;
                                rd_free(state->owner_member_id);
                                state->owner_member_id = NULL;
                                state->lock_expiry_ts  = 0;
                                break;
                        case 2: /* RELEASE */
                                rd_kafka_mock_sgrp_record_release(sgrp, pmeta,
                                                                  state);
                                break;
                        default:
                                break;
                        }
                }
        }

        /* Advance SPSO past contiguous ACKNOWLEDGED or ARCHIVED records
         * from the start, transitioning ACKNOWLEDGED to ARCHIVED. */
        while (pmeta->spso <= pmeta->speo) {
                rd_kafka_mock_sgrp_record_state_t *state =
                    rd_kafka_mock_sgrp_record_state_find(pmeta, pmeta->spso);
                if (!state ||
                    (state->state != RD_KAFKA_MOCK_SGRP_RECORD_ACKNOWLEDGED &&
                     state->state != RD_KAFKA_MOCK_SGRP_RECORD_ARCHIVED))
                        break;
                state->state = RD_KAFKA_MOCK_SGRP_RECORD_ARCHIVED;
                pmeta->spso++;
        }

        return err;
}

/**
 * @brief Write AcquiredRecords metadata for the given partition and member
 *        into the response buffer.
 *
 * Groups contiguous ACQUIRED records (owned by this member and not expired)
 * into ranges and writes each range as (FirstOffset, LastOffset,
 * DeliveryCount).
 *
 * @locks mcluster->lock MUST be held.
 */
static void rd_kafka_mock_sgrp_write_acquired_records_meta(
    rd_kafka_buf_t *resp,
    rd_kafka_mock_sgrp_partmeta_t *pmeta,
    const rd_kafkap_str_t *member_id,
    rd_ts_t now) {
        struct acquired_range {
                int64_t first_offset;
                int64_t last_offset;
                int16_t delivery_count;
        };
        rd_list_t ranges;
        int64_t offset;
        int i;

        rd_list_init(&ranges, 16, rd_free);

        for (offset = pmeta->spso; offset <= pmeta->speo; offset++) {
                rd_kafka_mock_sgrp_record_state_t *state =
                    rd_kafka_mock_sgrp_record_state_find(pmeta, offset);
                struct acquired_range *cur;

                if (!state ||
                    state->state != RD_KAFKA_MOCK_SGRP_RECORD_ACQUIRED ||
                    !state->owner_member_id ||
                    rd_kafkap_str_cmp_str(member_id, state->owner_member_id) ||
                    (state->lock_expiry_ts && state->lock_expiry_ts <= now))
                        continue;

                /* Try to extend the current range */
                if (rd_list_cnt(&ranges) > 0) {
                        cur = rd_list_elem(&ranges, rd_list_cnt(&ranges) - 1);
                        if (offset == cur->last_offset + 1 &&
                            (int16_t)state->delivery_count ==
                                cur->delivery_count) {
                                cur->last_offset = offset;
                                continue;
                        }
                }

                /* Start a new range */
                cur                 = rd_calloc(1, sizeof(*cur));
                cur->first_offset   = offset;
                cur->last_offset    = offset;
                cur->delivery_count = (int16_t)state->delivery_count;
                rd_list_add(&ranges, cur);
        }

        rd_kafka_buf_write_arraycnt(resp, rd_list_cnt(&ranges));

        for (i = 0; i < rd_list_cnt(&ranges); i++) {
                struct acquired_range *r = rd_list_elem(&ranges, i);
                rd_kafka_buf_write_i64(resp, r->first_offset);
                rd_kafka_buf_write_i64(resp, r->last_offset);
                rd_kafka_buf_write_i16(resp, r->delivery_count);
                rd_kafka_buf_write_tags_empty(resp);
        }

        rd_list_destroy(&ranges);
}

static int rd_kafka_mock_handle_ShareFetch(rd_kafka_mock_connection_t *mconn,
                                           rd_kafka_buf_t *rkbuf) {
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafkap_str_t GroupId, MemberId;
        int32_t SessionEpoch = -1, MaxWaitMs = 0, MinBytes = 0, MaxBytes = 0,
                MaxRecords = 0, BatchSize = 0;
        int32_t TopicsCnt;
        int32_t ForgottenTopicsCnt;
        rd_kafka_topic_partition_list_t *requested_partitions = NULL;
        rd_kafka_topic_partition_list_t *forgotten_partitions = NULL;
        rd_kafka_resp_err_t err          = RD_KAFKA_RESP_ERR_NO_ERROR;
        rd_bool_t ack_parse_err          = rd_false;
        rd_kafka_mock_sharegroup_t *sgrp = NULL;
        rd_kafka_mock_sgrp_fetch_session_t *session = NULL;
        rd_list_t ack_entries;
        rd_kafka_mock_broker_t *node_endpoints[64];
        int node_endpoint_cnt = 0;
        int k;

        (void)log_decode_errors;

        rd_list_init(&ack_entries, 8, rd_free);

        rd_kafka_buf_read_str(rkbuf, &GroupId);
        rd_kafka_buf_read_str(rkbuf, &MemberId);
        /* ShareFetch has ShareSessionEpoch only, no SessionId.
         * Sessions are keyed by (GroupId, MemberId, NodeId). */
        rd_kafka_buf_read_i32(rkbuf, &SessionEpoch);
        rd_kafka_buf_read_i32(rkbuf, &MaxWaitMs);
        rd_kafka_buf_read_i32(rkbuf, &MinBytes);
        rd_kafka_buf_read_i32(rkbuf, &MaxBytes);
        rd_kafka_buf_read_i32(rkbuf, &MaxRecords);
        rd_kafka_buf_read_i32(rkbuf, &BatchSize);

        requested_partitions = rd_kafka_topic_partition_list_new(0);

        rd_kafka_buf_read_arraycnt(rkbuf, &TopicsCnt, RD_KAFKAP_TOPICS_MAX);
        while (TopicsCnt-- > 0) {
                rd_kafka_Uuid_t TopicId = RD_KAFKA_UUID_ZERO;
                int32_t PartitionCnt;

                rd_kafka_buf_read_uuid(rkbuf, &TopicId);
                rd_kafka_buf_read_arraycnt(rkbuf, &PartitionCnt,
                                           RD_KAFKAP_PARTITIONS_MAX);

                while (PartitionCnt-- > 0) {
                        int32_t Partition;
                        int32_t AckBatchCnt;
                        int64_t prev_ack_last = -1;
                        rd_kafka_topic_partition_t *rktpar;

                        rd_kafka_buf_read_i32(rkbuf, &Partition);
                        rd_kafka_buf_read_arraycnt(rkbuf, &AckBatchCnt, -1);
                        while (AckBatchCnt-- > 0) {
                                int32_t AckTypeCnt;
                                int64_t AckFirstOffset, AckLastOffset;
                                int64_t range_len, ti;
                                int8_t *ack_types  = NULL;
                                int8_t single_type = -1;

                                rd_kafka_buf_read_i64(rkbuf, &AckFirstOffset);
                                rd_kafka_buf_read_i64(rkbuf, &AckLastOffset);

                                /* Validate ascending order and
                                 * non-overlapping ranges. */
                                if (prev_ack_last >= 0 &&
                                    AckFirstOffset <= prev_ack_last)
                                        ack_parse_err = rd_true;
                                prev_ack_last = AckLastOffset;

                                range_len = AckLastOffset - AckFirstOffset + 1;

                                rd_kafka_buf_read_arraycnt(rkbuf, &AckTypeCnt,
                                                           -1);

                                if (AckTypeCnt == 1) {
                                        /* Single type for entire range */
                                        rd_kafka_buf_read_i8(rkbuf,
                                                             &single_type);
                                } else if (AckTypeCnt > 1) {
                                        /* Per-offset types */
                                        ack_types =
                                            rd_alloca((size_t)AckTypeCnt *
                                                      sizeof(*ack_types));
                                        for (ti = 0; ti < AckTypeCnt; ti++)
                                                rd_kafka_buf_read_i8(
                                                    rkbuf, &ack_types[ti]);
                                }
                                rd_kafka_buf_skip_tags(rkbuf);

                                if (AckTypeCnt == 1 && single_type >= 0) {
                                        rd_list_add(
                                            &ack_entries,
                                            rd_kafka_mock_sgrp_ack_entry_new(
                                                TopicId, Partition,
                                                AckFirstOffset, AckLastOffset,
                                                single_type));
                                } else if (ack_types &&
                                           AckTypeCnt == range_len) {
                                        for (ti = 0; ti < range_len; ti++) {
                                                rd_list_add(
                                                    &ack_entries,
                                                    rd_kafka_mock_sgrp_ack_entry_new(
                                                        TopicId, Partition,
                                                        AckFirstOffset + ti,
                                                        AckFirstOffset + ti,
                                                        ack_types[ti]));
                                        }
                                } else if (AckTypeCnt > 0) {
                                        ack_parse_err = rd_true;
                                }
                        }

                        rktpar = rd_kafka_topic_partition_list_add(
                            requested_partitions, "", Partition);
                        rd_kafka_topic_partition_set_topic_id(rktpar, TopicId);

                        rd_kafka_buf_skip_tags(rkbuf);
                }

                rd_kafka_buf_skip_tags(rkbuf);
        }

        rd_kafka_buf_read_arraycnt(rkbuf, &ForgottenTopicsCnt,
                                   RD_KAFKAP_TOPICS_MAX);
        if (ForgottenTopicsCnt > 0)
                forgotten_partitions =
                    rd_kafka_topic_partition_list_new(ForgottenTopicsCnt);
        while (ForgottenTopicsCnt-- > 0) {
                rd_kafka_Uuid_t ForgTopicId = RD_KAFKA_UUID_ZERO;
                int32_t ForgPartCnt;
                rd_kafka_buf_read_uuid(rkbuf, &ForgTopicId);
                rd_kafka_buf_read_arraycnt(rkbuf, &ForgPartCnt,
                                           RD_KAFKAP_PARTITIONS_MAX);
                while (ForgPartCnt-- > 0) {
                        int32_t ForgPartition;
                        rd_kafka_topic_partition_t *ftp;
                        rd_kafka_buf_read_i32(rkbuf, &ForgPartition);

                        /* Record in forgotten list for session
                         * removal and inflight release. */
                        ftp = rd_kafka_topic_partition_list_add(
                            forgotten_partitions, "", ForgPartition);
                        rd_kafka_topic_partition_set_topic_id(ftp, ForgTopicId);

                        /* Remove from requested_partitions so they
                         * are not fetched in this request. */
                        if (requested_partitions) {
                                int idx =
                                    rd_kafka_topic_partition_list_find_idx_by_id(
                                        requested_partitions, ForgTopicId,
                                        ForgPartition);
                                if (idx >= 0)
                                        rd_kafka_topic_partition_list_del_by_idx(
                                            requested_partitions, idx);
                        }
                }
                /* ForgottenTopic tags */
                rd_kafka_buf_skip_tags(rkbuf);
        }

        /* Top-level tags */
        rd_kafka_buf_skip_tags(rkbuf);

        rd_kafka_dbg(mconn->broker->cluster->rk, MOCK, "MOCK",
                     "ShareFetch parsed: group %.*s member %.*s "
                     "session_epoch %" PRId32 " max_wait %" PRId32
                     " min_bytes %" PRId32 " max_bytes %" PRId32
                     " max_records %" PRId32 " batch_size %" PRId32,
                     RD_KAFKAP_STR_PR(&GroupId), RD_KAFKAP_STR_PR(&MemberId),
                     SessionEpoch, MaxWaitMs, MinBytes, MaxBytes, MaxRecords,
                     BatchSize);

        err = rd_kafka_mock_next_request_error(mconn, resp);

        if (!err && ack_parse_err)
                err = RD_KAFKA_RESP_ERR_INVALID_REQUEST;

        if (!err) {
                int64_t remaining_records =
                    MaxRecords > 0 ? (int64_t)MaxRecords : -1;
                int64_t remaining_bytes = MaxBytes > 0 ? (int64_t)MaxBytes : -1;
                int acquired_cnt        = 0;
                int64_t acquired_bytes  = 0;
                rd_ts_t now             = rd_clock();

                /* Session management.
                 * Sessions are keyed by (GroupId, MemberId).
                 * SessionEpoch: 0 = open new session,
                 *              -1 = close session,
                 *              >0 = continue (must match expected epoch).
                 *
                 * session->partitions is the source of truth for the
                 * full partition set.  For epoch=0, it is set from the
                 * request.  For epoch>0, the request only carries
                 * additions; an empty list means "no changes".
                 * Forgotten partitions are removed below.
                 * Acquisition and response writing always use
                 * session->partitions. */
                mtx_lock(&mcluster->lock);
                sgrp = rd_kafka_mock_sharegroup_get(mcluster, &GroupId);

                /* epoch=0 (full fetch / new session) must not
                 * contain acknowledgements.  Check BEFORE
                 * session_validate to avoid destroying an existing
                 * session for a malformed request. */
                if (SessionEpoch == 0 && rd_list_cnt(&ack_entries) > 0) {
                        rd_kafka_dbg(mconn->broker->cluster->rk, MOCK, "MOCK",
                                     "ShareFetch: rejecting epoch=0 request "
                                     "with %d ack(s) (INVALID_REQUEST)",
                                     rd_list_cnt(&ack_entries));
                        err = RD_KAFKA_RESP_ERR_INVALID_REQUEST;
                }

                /* Common validation: member check, session lookup,
                 * epoch -1 close, epoch > 0 validation. */
                if (!err)
                        err = rd_kafka_mock_sgrp_session_validate(
                            sgrp, &MemberId, mconn->broker->id, SessionEpoch,
                            &session, "ShareFetch");

                if (!err && SessionEpoch == 0) {
                        /* Open a new session (or reuse if one already exists
                         * for this member on this broker). */
                        int broker_session_cnt = 0;
                        rd_kafka_mock_sharegroup_t *sg;
                        rd_kafka_mock_sgrp_fetch_session_t *s;
                        /* Count sessions across ALL share groups on this
                         * broker.  group.share.max.share.sessions is a
                         * per-broker limit with cache key (GroupId,
                         * MemberId). */
                        TAILQ_FOREACH(sg, &mcluster->sharegrps, link) {
                                TAILQ_FOREACH(s, &sg->fetch_sessions, link) {
                                        if (s->node_id == mconn->broker->id)
                                                broker_session_cnt++;
                                }
                        }
                        if (!session && sgrp->max_fetch_sessions > 0 &&
                            broker_session_cnt >= sgrp->max_fetch_sessions) {
                                /* Session cache is full for this broker. */
                                err =
                                    RD_KAFKA_RESP_ERR_SHARE_SESSION_LIMIT_REACHED;
                        } else if (!session) {
                                session = rd_calloc(1, sizeof(*session));
                                session->member_id =
                                    RD_KAFKAP_STR_DUP(&MemberId);
                                session->node_id       = mconn->broker->id;
                                session->session_epoch = 0;
                                session->partitions =
                                    rd_kafka_topic_partition_list_copy(
                                        requested_partitions);
                                TAILQ_INSERT_TAIL(&sgrp->fetch_sessions,
                                                  session, link);
                                sgrp->fetch_session_cnt++;
                        } else {
                                /* Session already exists for this member;
                                 * reset it. */
                                session->session_epoch = 0;
                                RD_IF_FREE(
                                    session->partitions,
                                    rd_kafka_topic_partition_list_destroy);
                                session->partitions =
                                    rd_kafka_topic_partition_list_copy(
                                        requested_partitions);
                        }
                } else if (!err && session && SessionEpoch > 0) {
                        /* Session continuation: merge additions from the
                         * request into session->partitions.  An empty
                         * request list means "no changes". */
                        if (requested_partitions &&
                            requested_partitions->cnt > 0) {
                                rd_kafka_topic_partition_t *rp;
                                if (!session->partitions)
                                        session->partitions =
                                            rd_kafka_topic_partition_list_new(
                                                requested_partitions->cnt);
                                RD_KAFKA_TPLIST_FOREACH(rp,
                                                        requested_partitions) {
                                        rd_kafka_Uuid_t tid =
                                            rd_kafka_topic_partition_get_topic_id(
                                                rp);
                                        if (rd_kafka_topic_partition_list_find_idx_by_id(
                                                session->partitions, tid,
                                                rp->partition) < 0) {
                                                rd_kafka_topic_partition_t *np =
                                                    rd_kafka_topic_partition_list_add(
                                                        session->partitions, "",
                                                        rp->partition);
                                                rd_kafka_topic_partition_set_topic_id(
                                                    np, tid);
                                        }
                                }
                        }
                }

                /* For all successful, non-close requests: update activity
                 * timestamp and increment epoch for next request. */
                if (!err && session && SessionEpoch != -1) {
                        session->ts_last_activity = rd_clock();
                        session->session_epoch++;
                }

                /* epoch=-1 (final fetch / close session) must not
                 * contain ForgottenTopicsData.  Partitions
                 * in the Topics array ARE allowed — they carry
                 * piggybacked acks for the final request. */
                if (!err && SessionEpoch == -1 &&
                    (forgotten_partitions && forgotten_partitions->cnt > 0)) {
                        rd_kafka_dbg(
                            mconn->broker->cluster->rk, MOCK, "MOCK",
                            "ShareFetch: rejecting epoch=-1 request "
                            "with ForgottenTopicsData (INVALID_REQUEST)");
                        err = RD_KAFKA_RESP_ERR_INVALID_REQUEST;
                }

                /* Apply piggy-backed acknowledgements BEFORE forgotten
                 * partition processing, so that acks for partitions
                 * being removed are applied while the records are still
                 * in ACQUIRED state. */
                if (!err && sgrp && rd_list_cnt(&ack_entries) > 0) {
                        int k;
                        rd_kafka_dbg(mconn->broker->cluster->rk, MOCK, "MOCK",
                                     "ShareFetch: applying %d acknowledgement "
                                     "batch(es) for member %.*s",
                                     rd_list_cnt(&ack_entries),
                                     RD_KAFKAP_STR_PR(&MemberId));
                        for (k = 0; k < rd_list_cnt(&ack_entries); k++) {
                                struct rd_kafka_mock_sgrp_ack_entry *entry =
                                    rd_list_elem(&ack_entries, k);
                                entry->err = rd_kafka_mock_sgrp_apply_ack(
                                    sgrp, entry->topic_id, entry->partition,
                                    entry->first_offset, entry->last_offset,
                                    entry->ack_type, &MemberId);
                        }
                }

                /* Remove forgotten partitions from session and release
                 * any remaining ACQUIRED records owned by this member.
                 * Runs AFTER ack application so that acks for partitions
                 * being removed have already been processed. */
                if (!err && session && forgotten_partitions &&
                    forgotten_partitions->cnt > 0) {
                        rd_kafka_topic_partition_t *ftp;
                        RD_KAFKA_TPLIST_FOREACH(ftp, forgotten_partitions) {
                                rd_kafka_Uuid_t ftid =
                                    rd_kafka_topic_partition_get_topic_id(ftp);
                                rd_kafka_mock_sgrp_partmeta_t *pmeta;

                                /* Remove from session partition list */
                                if (session->partitions) {
                                        int idx =
                                            rd_kafka_topic_partition_list_find_idx_by_id(
                                                session->partitions, ftid,
                                                ftp->partition);
                                        if (idx >= 0)
                                                rd_kafka_topic_partition_list_del_by_idx(
                                                    session->partitions, idx);
                                }

                                /* Release ACQUIRED records for this
                                 * member on this partition, but only
                                 * if this broker currently leads it:
                                 * forgetting a partition that moved to
                                 * another leader must not release the
                                 * locks now held through the new
                                 * leader's session. */
                                rd_kafka_mock_topic_t *ftopic =
                                    rd_kafka_mock_topic_find_by_id(mcluster,
                                                                   ftid);
                                rd_kafka_mock_partition_t *fpart =
                                    ftopic ? rd_kafka_mock_partition_find(
                                                 ftopic, ftp->partition)
                                           : NULL;
                                if (!fpart || fpart->leader != mconn->broker)
                                        continue;

                                pmeta = rd_kafka_mock_sgrp_partmeta_find(
                                    sgrp, ftid, ftp->partition);
                                if (pmeta) {
                                        rd_kafka_mock_sgrp_record_state_t
                                            *state,
                                            *tmp;
                                        TAILQ_FOREACH_SAFE(state,
                                                           &pmeta->inflight,
                                                           link, tmp) {
                                                if (state->state !=
                                                    RD_KAFKA_MOCK_SGRP_RECORD_ACQUIRED)
                                                        continue;
                                                if (!state->owner_member_id)
                                                        continue;
                                                if (rd_kafkap_str_cmp_str(
                                                        &MemberId,
                                                        state->owner_member_id))
                                                        continue;
                                                rd_kafka_mock_sgrp_record_release(
                                                    sgrp, pmeta, state);
                                        }
                                }
                        }
                }

                /* epoch=-1 is a final fetch: no new records are
                 * acquired ("No data will be fetched"). */
                if (!err && SessionEpoch != -1 && sgrp && session &&
                    session->partitions && session->partitions->cnt > 0) {
                        int pi, pcnt = session->partitions->cnt;
                        int start = session->partition_start_idx % pcnt;

                        for (pi = 0; pi < pcnt; pi++) {
                                int idx = (start + pi) % pcnt;
                                rd_kafka_topic_partition_t *rktpar =
                                    &session->partitions->elems[idx];
                                rd_kafka_Uuid_t topic_id =
                                    rd_kafka_topic_partition_get_topic_id(
                                        rktpar);
                                rd_kafka_mock_topic_t *mtopic =
                                    rd_kafka_mock_topic_find_by_id(mcluster,
                                                                   topic_id);
                                rd_kafka_mock_partition_t *mpart;

                                if (!mtopic ||
                                    !(mpart = rd_kafka_mock_partition_find(
                                          mtopic, rktpar->partition))) {
                                        /* Per-partition error: skip this
                                         * partition but continue with others.
                                         * The response writer handles the
                                         * error via mpart==NULL check. */
                                        continue;
                                }

                                /* Skip acquisition if this broker is
                                 * not the partition leader.  The
                                 * response writer returns
                                 * NOT_LEADER_OR_FOLLOWER. */
                                if (mpart->leader != mconn->broker)
                                        continue;

                                /* Injected partition error: skip acquisition
                                 * so no records are locked for a partition
                                 * the client will see as failed.  The error
                                 * is stashed on the session's partition list
                                 * element and consumed (read and cleared) by
                                 * the response writer below. */
                                rktpar->err =
                                    rd_kafka_mock_partition_next_request_error(
                                        mpart, rkbuf->rkbuf_reqhdr.ApiKey);
                                if (rktpar->err)
                                        continue;

                                rd_kafka_mock_sgrp_partmeta_t *pmeta =
                                    rd_kafka_mock_sgrp_partmeta_get(
                                        sgrp, topic_id, rktpar->partition,
                                        mpart);
                                rd_kafka_mock_sgrp_partmeta_prune_archived(
                                    pmeta);
                                rd_kafka_mock_sgrp_acquire_available_offsets(
                                    pmeta, mpart, &MemberId,
                                    now + ((sgrp->record_lock_duration_ms > 0
                                                ? sgrp->record_lock_duration_ms
                                                : sgrp->session_timeout_ms) *
                                           1000),
                                    sgrp->max_delivery_attempts,
                                    sgrp->max_record_locks,
                                    MaxRecords > 0 ? &remaining_records : NULL,
                                    MaxBytes > 0 ? &remaining_bytes : NULL,
                                    &acquired_cnt, &acquired_bytes,
                                    sgrp->isolation_level);
                        }

                        /* Rotate start index for next request */
                        session->partition_start_idx = (start + 1) % pcnt;
                }

                rd_kafka_dbg(mconn->broker->cluster->rk, MOCK, "MOCK",
                             "ShareFetch acquired: %d records, %" PRId64
                             " bytes",
                             acquired_cnt, acquired_bytes);

                /* Response: ThrottleTimeMs */
                rd_kafka_buf_write_i32(resp, 0);
                /* Response: ErrorCode */
                rd_kafka_buf_write_i16(resp, err);
                /* Response: ErrorMessage */
                if (err)
                        rd_kafka_buf_write_str(resp, rd_kafka_err2str(err), -1);
                else
                        rd_kafka_buf_write_str(resp, NULL, -1);
                /* Response: AcquisitionLockTimeoutMs — use the effective
                 * lock duration (same logic as the acquisition path). */
                rd_kafka_buf_write_i32(
                    resp, sgrp ? (sgrp->record_lock_duration_ms > 0
                                      ? sgrp->record_lock_duration_ms
                                      : sgrp->session_timeout_ms)
                               : 0);

                if (session && session->partitions)
                        rd_kafka_topic_partition_list_sort_by_topic_id(
                            session->partitions);

                {
                        int i                         = 0;
                        int topic_cnt                 = 0;
                        rd_kafka_Uuid_t current_topic = RD_KAFKA_UUID_ZERO;

                        for (i = 0; session && session->partitions &&
                                    i < session->partitions->cnt;
                             i++) {
                                rd_kafka_topic_partition_t *rktpar =
                                    &session->partitions->elems[i];
                                rd_kafka_Uuid_t topic_id =
                                    rd_kafka_topic_partition_get_topic_id(
                                        rktpar);
                                if (i == 0 ||
                                    rd_kafka_Uuid_cmp(topic_id,
                                                      current_topic) != 0) {
                                        topic_cnt++;
                                        current_topic = topic_id;
                                }
                        }

                        /* Response: #Topics */
                        rd_kafka_buf_write_arraycnt(resp, topic_cnt);

                        i = 0;
                        while (session && session->partitions &&
                               i < session->partitions->cnt) {
                                int j;
                                rd_kafka_Uuid_t topic_id =
                                    rd_kafka_topic_partition_get_topic_id(
                                        &session->partitions->elems[i]);
                                int part_cnt = 0;

                                for (j = i; j < session->partitions->cnt; j++) {
                                        rd_kafka_Uuid_t next_topic_id =
                                            rd_kafka_topic_partition_get_topic_id(
                                                &session->partitions->elems[j]);
                                        if (rd_kafka_Uuid_cmp(
                                                topic_id, next_topic_id) != 0)
                                                break;
                                        part_cnt++;
                                }

                                /* Response: TopicId */
                                rd_kafka_buf_write_uuid(resp, &topic_id);
                                /* Response: #Partitions */
                                rd_kafka_buf_write_arraycnt(resp, part_cnt);

                                for (j = i; j < i + part_cnt; j++) {
                                        rd_kafka_topic_partition_t *rktpar =
                                            &session->partitions->elems[j];
                                        rd_kafka_mock_topic_t *mtopic =
                                            rd_kafka_mock_topic_find_by_id(
                                                mcluster, topic_id);
                                        rd_kafka_mock_partition_t *mpart =
                                            mtopic
                                                ? rd_kafka_mock_partition_find(
                                                      mtopic, rktpar->partition)
                                                : NULL;
                                        rd_kafka_mock_sgrp_partmeta_t *pmeta =
                                            mpart
                                                ? rd_kafka_mock_sgrp_partmeta_find(
                                                      sgrp, topic_id,
                                                      rktpar->partition)
                                                : NULL;
                                        rd_kafka_resp_err_t ack_err;
                                        rd_kafka_resp_err_t part_err;

                                        if (!mpart)
                                                part_err =
                                                    RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;
                                        else if (mpart->leader != mconn->broker)
                                                part_err =
                                                    RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER;
                                        else
                                                part_err = rktpar->err;

                                        /* Consume the stashed injected error
                                         * so it doesn't leak into subsequent
                                         * responses. */
                                        rktpar->err =
                                            RD_KAFKA_RESP_ERR_NO_ERROR;

                                        /* Response: Partition */
                                        rd_kafka_buf_write_i32(
                                            resp, rktpar->partition);
                                        /* Response: PartitionFetchErrorCode */
                                        rd_kafka_buf_write_i16(resp, part_err);
                                        /* Response: PartitionFetchErrorString
                                         */
                                        if (part_err)
                                                rd_kafka_buf_write_str(
                                                    resp,
                                                    rd_kafka_err2str(part_err),
                                                    -1);
                                        else
                                                rd_kafka_buf_write_str(
                                                    resp, NULL, -1);
                                        /* Response: AcknowledgementErrorCode */
                                        ack_err =
                                            rd_kafka_mock_sgrp_ack_error_for_partition(
                                                &ack_entries, topic_id,
                                                rktpar->partition);
                                        rd_kafka_buf_write_i16(resp, ack_err);
                                        /* Response:
                                         * AcknowledgementErrorString */
                                        if (ack_err)
                                                rd_kafka_buf_write_str(
                                                    resp,
                                                    rd_kafka_err2str(ack_err),
                                                    -1);
                                        else
                                                rd_kafka_buf_write_str(
                                                    resp, NULL, -1);
                                        /* Response: CurrentLeader.
                                         * Populated only when the
                                         * per-partition error signals stale
                                         * leader info. */
                                        if (mpart && mpart->leader &&
                                            (part_err ==
                                                 RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER ||
                                             part_err ==
                                                 RD_KAFKA_RESP_ERR_FENCED_LEADER_EPOCH)) {
                                                int found = 0;
                                                rd_kafka_buf_write_i32(
                                                    resp, mpart->leader->id);
                                                rd_kafka_buf_write_i32(
                                                    resp, mpart->leader_epoch);
                                                for (k = 0;
                                                     k < node_endpoint_cnt;
                                                     k++) {
                                                        if (node_endpoints[k] ==
                                                            mpart->leader) {
                                                                found = 1;
                                                                break;
                                                        }
                                                }
                                                if (!found &&
                                                    node_endpoint_cnt < 64)
                                                        node_endpoints
                                                            [node_endpoint_cnt++] =
                                                                mpart->leader;
                                        } else {
                                                rd_kafka_buf_write_i32(resp,
                                                                       -1);
                                                rd_kafka_buf_write_i32(resp,
                                                                       -1);
                                        }
                                        rd_kafka_buf_write_tags_empty(resp);
                                        /* Response: Records (all acquired
                                         * batches concatenated) */
                                        if (mpart && pmeta && !part_err)
                                                rd_kafka_mock_sgrp_write_acquired_records(
                                                    resp, pmeta, mpart,
                                                    &MemberId, now);
                                        else
                                                rd_kafka_buf_write_uvarint(resp,
                                                                           1);
                                        /* Response: AcquiredRecords */
                                        if (mpart && pmeta && !part_err)
                                                rd_kafka_mock_sgrp_write_acquired_records_meta(
                                                    resp, pmeta, &MemberId,
                                                    now);
                                        else
                                                rd_kafka_buf_write_arraycnt(
                                                    resp, 0);
                                        /* Response: Partition tags */
                                        rd_kafka_buf_write_tags_empty(resp);
                                }

                                /* Response: Topic tags */
                                rd_kafka_buf_write_tags_empty(resp);

                                i += part_cnt;
                        }
                }

                /* Response: NodeEndpoints */
                rd_kafka_buf_write_arraycnt(resp, node_endpoint_cnt);
                for (k = 0; k < node_endpoint_cnt; k++) {
                        rd_kafka_mock_broker_t *nb = node_endpoints[k];
                        rd_kafka_buf_write_i32(resp, nb->id);
                        rd_kafka_buf_write_str(resp, nb->advertised_listener,
                                               -1);
                        rd_kafka_buf_write_i32(resp, (int32_t)nb->port);
                        rd_kafka_buf_write_str(resp, nb->rack, -1);
                        rd_kafka_buf_write_tags_empty(resp);
                }
                /* Response: Top-level tags */
                rd_kafka_buf_write_tags_empty(resp);

                /* epoch=-1 (final fetch) → release remaining acquired
                 * records and close the session. */
                if (!err && session && SessionEpoch == -1) {
                        rd_kafka_mock_sgrp_release_session_locks(sgrp, session);
                        TAILQ_REMOVE(&sgrp->fetch_sessions, session, link);
                        sgrp->fetch_session_cnt--;
                        rd_kafka_mock_sgrp_fetch_session_destroy(session);
                        session = NULL;
                }

                mtx_unlock(&mcluster->lock);

                /* Emulate real broker MaxWaitMs behaviour: when no
                 * records were acquired, delay the response to avoid
                 * a tight fetch loop that starves the client's
                 * shutdown path. Cap the delay at 100ms so tests
                 * remain fast. */
                if (acquired_cnt == 0 && MaxWaitMs > 0) {
                        int32_t delay_ms    = MaxWaitMs < 100 ? MaxWaitMs : 100;
                        resp->rkbuf_ts_sent = (rd_ts_t)delay_ms * 1000; /* us */
                }

                rd_kafka_mock_connection_send_response0(mconn, resp, rd_true);

                rd_kafka_topic_partition_list_destroy(requested_partitions);
                RD_IF_FREE(forgotten_partitions,
                           rd_kafka_topic_partition_list_destroy);
                rd_list_destroy(&ack_entries);
                return 0;
        }

        /* Error response */
        rd_kafka_buf_write_i32(resp, 0);
        rd_kafka_buf_write_i16(resp, err);
        rd_kafka_buf_write_str(resp, rd_kafka_err2str(err), -1);
        rd_kafka_buf_write_i32(resp, 0);
        rd_kafka_buf_write_arraycnt(resp, 0);
        rd_kafka_buf_write_arraycnt(resp, 0);
        rd_kafka_buf_write_tags_empty(resp);

        rd_kafka_mock_connection_send_response0(mconn, resp, rd_true);
        rd_kafka_topic_partition_list_destroy(requested_partitions);
        RD_IF_FREE(forgotten_partitions, rd_kafka_topic_partition_list_destroy);
        rd_list_destroy(&ack_entries);
        return 0;

err_parse:
        RD_IF_FREE(requested_partitions, rd_kafka_topic_partition_list_destroy);
        RD_IF_FREE(forgotten_partitions, rd_kafka_topic_partition_list_destroy);
        rd_list_destroy(&ack_entries);
        rd_kafka_buf_destroy(resp);
        return -1;
}

/**
 * @brief Handle ShareAcknowledgeRequest.
 *
 * This is the standalone acknowledgement API (key 79).  It has the same
 * acknowledgement-batch wire format as the piggy-backed acks inside
 * ShareFetch, but does NOT return any fetched records.
 *
 * Request:  GroupId, MemberId, ShareSessionEpoch, Topics[TopicId,
 *           Partitions[PartitionIndex, AcknowledgementBatches[FirstOffset,
 *           LastOffset, AcknowledgeTypes[]]]]
 *
 * Response: ThrottleTimeMs, ErrorCode, ErrorMessage,
 *           Responses[TopicId, Partitions[PartitionIndex, ErrorCode,
 *           ErrorMessage, CurrentLeader{LeaderId, LeaderEpoch}]],
 *           NodeEndpoints[]
 */
static int
rd_kafka_mock_handle_ShareAcknowledge(rd_kafka_mock_connection_t *mconn,
                                      rd_kafka_buf_t *rkbuf) {
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        rd_kafkap_str_t GroupId, MemberId;
        int32_t SessionEpoch = -1;
        int32_t TopicsCnt;
        rd_kafka_topic_partition_list_t *ack_partitions = NULL;
        rd_kafka_resp_err_t err          = RD_KAFKA_RESP_ERR_NO_ERROR;
        rd_bool_t ack_parse_err          = rd_false;
        rd_kafka_mock_sharegroup_t *sgrp = NULL;
        rd_list_t ack_entries;
        rd_kafka_mock_broker_t *node_endpoints[64];
        int node_endpoint_cnt = 0;
        int k;

        (void)log_decode_errors;

        rd_list_init(&ack_entries, 8, rd_free);

        /* ---- Parse request ---- */

        rd_kafka_buf_read_str(rkbuf, &GroupId);
        rd_kafka_buf_read_str(rkbuf, &MemberId);
        rd_kafka_buf_read_i32(rkbuf, &SessionEpoch);

        ack_partitions = rd_kafka_topic_partition_list_new(0);

        rd_kafka_buf_read_arraycnt(rkbuf, &TopicsCnt, RD_KAFKAP_TOPICS_MAX);
        while (TopicsCnt-- > 0) {
                rd_kafka_Uuid_t TopicId = RD_KAFKA_UUID_ZERO;
                int32_t PartitionCnt;

                rd_kafka_buf_read_uuid(rkbuf, &TopicId);
                rd_kafka_buf_read_arraycnt(rkbuf, &PartitionCnt,
                                           RD_KAFKAP_PARTITIONS_MAX);

                while (PartitionCnt-- > 0) {
                        int32_t Partition;
                        int32_t AckBatchCnt;
                        int64_t prev_ack_last = -1;
                        rd_kafka_topic_partition_t *rktpar;

                        rd_kafka_buf_read_i32(rkbuf, &Partition);
                        rd_kafka_buf_read_arraycnt(rkbuf, &AckBatchCnt, -1);
                        while (AckBatchCnt-- > 0) {
                                int32_t AckTypeCnt;
                                int64_t AckFirstOffset, AckLastOffset;
                                int64_t range_len, ti;
                                int8_t *ack_types  = NULL;
                                int8_t single_type = -1;

                                rd_kafka_buf_read_i64(rkbuf, &AckFirstOffset);
                                rd_kafka_buf_read_i64(rkbuf, &AckLastOffset);

                                /* Validate ascending order and
                                 * non-overlapping ranges. */
                                if (prev_ack_last >= 0 &&
                                    AckFirstOffset <= prev_ack_last)
                                        ack_parse_err = rd_true;
                                prev_ack_last = AckLastOffset;

                                range_len = AckLastOffset - AckFirstOffset + 1;

                                rd_kafka_buf_read_arraycnt(rkbuf, &AckTypeCnt,
                                                           -1);

                                if (AckTypeCnt == 1) {
                                        /* Single type for entire range */
                                        rd_kafka_buf_read_i8(rkbuf,
                                                             &single_type);
                                } else if (AckTypeCnt > 1) {
                                        /* Per-offset types */
                                        ack_types =
                                            rd_alloca((size_t)AckTypeCnt *
                                                      sizeof(*ack_types));
                                        for (ti = 0; ti < AckTypeCnt; ti++)
                                                rd_kafka_buf_read_i8(
                                                    rkbuf, &ack_types[ti]);
                                }
                                rd_kafka_buf_skip_tags(rkbuf);

                                if (AckTypeCnt == 1 && single_type >= 0) {
                                        rd_list_add(
                                            &ack_entries,
                                            rd_kafka_mock_sgrp_ack_entry_new(
                                                TopicId, Partition,
                                                AckFirstOffset, AckLastOffset,
                                                single_type));
                                } else if (ack_types &&
                                           AckTypeCnt == range_len) {
                                        for (ti = 0; ti < range_len; ti++) {
                                                rd_list_add(
                                                    &ack_entries,
                                                    rd_kafka_mock_sgrp_ack_entry_new(
                                                        TopicId, Partition,
                                                        AckFirstOffset + ti,
                                                        AckFirstOffset + ti,
                                                        ack_types[ti]));
                                        }
                                } else if (AckTypeCnt > 0) {
                                        ack_parse_err = rd_true;
                                }
                        }

                        rktpar = rd_kafka_topic_partition_list_add(
                            ack_partitions, "", Partition);
                        rd_kafka_topic_partition_set_topic_id(rktpar, TopicId);

                        rd_kafka_buf_skip_tags(rkbuf);
                }

                rd_kafka_buf_skip_tags(rkbuf);
        }

        /* Top-level tags */
        rd_kafka_buf_skip_tags(rkbuf);

        rd_kafka_dbg(mconn->broker->cluster->rk, MOCK, "MOCK",
                     "ShareAcknowledge parsed: group %.*s member %.*s "
                     "session_epoch %" PRId32 " ack_entries %d",
                     RD_KAFKAP_STR_PR(&GroupId), RD_KAFKAP_STR_PR(&MemberId),
                     SessionEpoch, rd_list_cnt(&ack_entries));

        /* ---- Inject errors if configured ---- */
        err = rd_kafka_mock_next_request_error(mconn, resp);

        if (!err && ack_parse_err)
                err = RD_KAFKA_RESP_ERR_INVALID_REQUEST;

        if (!err) {
                rd_kafka_mock_sgrp_fetch_session_t *session = NULL;

                mtx_lock(&mcluster->lock);
                sgrp = rd_kafka_mock_sharegroup_get(mcluster, &GroupId);

                /* Common validation: member check, session lookup,
                 * epoch -1 close, epoch > 0 validation. */
                err = rd_kafka_mock_sgrp_session_validate(
                    sgrp, &MemberId, mconn->broker->id, SessionEpoch, &session,
                    "ShareAcknowledge");

                /* ShareAcknowledge must not use epoch=0
                 * (only ShareFetch can open sessions). */
                if (!err && SessionEpoch == 0) {
                        err = RD_KAFKA_RESP_ERR_INVALID_SHARE_SESSION_EPOCH;
                }

                /* For all successful, non-close requests: update activity
                 * timestamp and increment epoch for next request.
                 * Skip for epoch=-1 (final/close). */
                if (!err && session && SessionEpoch != -1) {
                        session->ts_last_activity = rd_clock();
                        session->session_epoch++;
                }

                /* Pop injected partition-level errors and stash them on
                 * the request-local partition list.  Done before ack
                 * application so that acks for an errored partition are
                 * NOT applied, keeping mock record state consistent with
                 * the reported error. */
                if (!err) {
                        int p;
                        for (p = 0; p < ack_partitions->cnt; p++) {
                                rd_kafka_topic_partition_t *rktpar =
                                    &ack_partitions->elems[p];
                                rd_kafka_mock_topic_t *mtopic =
                                    rd_kafka_mock_topic_find_by_id(
                                        mcluster,
                                        rd_kafka_topic_partition_get_topic_id(
                                            rktpar));
                                rd_kafka_mock_partition_t *mpart =
                                    mtopic ? rd_kafka_mock_partition_find(
                                                 mtopic, rktpar->partition)
                                           : NULL;

                                rktpar->err = RD_KAFKA_RESP_ERR_NO_ERROR;
                                if (mpart && mpart->leader == mconn->broker)
                                        rktpar->err =
                                            rd_kafka_mock_partition_next_request_error(
                                                mpart,
                                                rkbuf->rkbuf_reqhdr.ApiKey);
                        }
                }

                /* Apply acknowledgement batches */
                if (!err && sgrp && rd_list_cnt(&ack_entries) > 0) {
                        int k;
                        rd_kafka_dbg(
                            mconn->broker->cluster->rk, MOCK, "MOCK",
                            "ShareAcknowledge: applying %d acknowledgement "
                            "batch(es) for member %.*s",
                            rd_list_cnt(&ack_entries),
                            RD_KAFKAP_STR_PR(&MemberId));
                        for (k = 0; k < rd_list_cnt(&ack_entries); k++) {
                                struct rd_kafka_mock_sgrp_ack_entry *entry =
                                    rd_list_elem(&ack_entries, k);
                                int idx =
                                    rd_kafka_topic_partition_list_find_idx_by_id(
                                        ack_partitions, entry->topic_id,
                                        entry->partition);

                                /* Skip ack application for partitions with
                                 * an injected error. */
                                if (idx >= 0 && ack_partitions->elems[idx].err)
                                        continue;

                                entry->err = rd_kafka_mock_sgrp_apply_ack(
                                    sgrp, entry->topic_id, entry->partition,
                                    entry->first_offset, entry->last_offset,
                                    entry->ack_type, &MemberId);
                        }
                }

                /* epoch=-1 (final ack) → release remaining
                 * acquired records and close the session. */
                if (!err && session && SessionEpoch == -1) {
                        rd_kafka_mock_sgrp_release_session_locks(sgrp, session);
                        TAILQ_REMOVE(&sgrp->fetch_sessions, session, link);
                        sgrp->fetch_session_cnt--;
                        rd_kafka_mock_sgrp_fetch_session_destroy(session);
                        session = NULL;
                }

                /* ---- Write success response ---- */

                /* ThrottleTimeMs */
                rd_kafka_buf_write_i32(resp, 0);
                /* ErrorCode */
                rd_kafka_buf_write_i16(resp, err);
                /* ErrorMessage */
                if (err)
                        rd_kafka_buf_write_str(resp, rd_kafka_err2str(err), -1);
                else
                        rd_kafka_buf_write_str(resp, NULL, -1);

                /* Responses (per-topic) */
                rd_kafka_topic_partition_list_sort_by_topic_id(ack_partitions);

                {
                        int i                         = 0;
                        int topic_cnt                 = 0;
                        rd_kafka_Uuid_t current_topic = RD_KAFKA_UUID_ZERO;

                        /* Count distinct topics */
                        for (i = 0; i < ack_partitions->cnt; i++) {
                                rd_kafka_topic_partition_t *rktpar =
                                    &ack_partitions->elems[i];
                                rd_kafka_Uuid_t topic_id =
                                    rd_kafka_topic_partition_get_topic_id(
                                        rktpar);
                                if (i == 0 ||
                                    rd_kafka_Uuid_cmp(topic_id,
                                                      current_topic) != 0) {
                                        topic_cnt++;
                                        current_topic = topic_id;
                                }
                        }

                        /* #Responses (topics) */
                        rd_kafka_buf_write_arraycnt(resp, topic_cnt);

                        i = 0;
                        while (i < ack_partitions->cnt) {
                                int j;
                                rd_kafka_Uuid_t topic_id =
                                    rd_kafka_topic_partition_get_topic_id(
                                        &ack_partitions->elems[i]);
                                int part_cnt = 0;

                                /* Count partitions for this topic */
                                for (j = i; j < ack_partitions->cnt; j++) {
                                        rd_kafka_Uuid_t next_topic_id =
                                            rd_kafka_topic_partition_get_topic_id(
                                                &ack_partitions->elems[j]);
                                        if (rd_kafka_Uuid_cmp(
                                                topic_id, next_topic_id) != 0)
                                                break;
                                        part_cnt++;
                                }

                                /* TopicId */
                                rd_kafka_buf_write_uuid(resp, &topic_id);
                                /* #Partitions */
                                rd_kafka_buf_write_arraycnt(resp, part_cnt);

                                for (j = i; j < i + part_cnt; j++) {
                                        rd_kafka_topic_partition_t *rktpar =
                                            &ack_partitions->elems[j];
                                        rd_kafka_mock_topic_t *mtopic =
                                            rd_kafka_mock_topic_find_by_id(
                                                mcluster, topic_id);
                                        rd_kafka_mock_partition_t *mpart =
                                            mtopic
                                                ? rd_kafka_mock_partition_find(
                                                      mtopic, rktpar->partition)
                                                : NULL;
                                        rd_kafka_resp_err_t part_err;

                                        if (!mpart)
                                                part_err =
                                                    RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;
                                        else if (mpart->leader != mconn->broker)
                                                part_err =
                                                    RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER;
                                        else if (rktpar->err)
                                                /* Injected partition error
                                                 * stashed before ack
                                                 * application. */
                                                part_err = rktpar->err;
                                        else
                                                part_err =
                                                    rd_kafka_mock_sgrp_ack_error_for_partition(
                                                        &ack_entries, topic_id,
                                                        rktpar->partition);

                                        /* PartitionIndex */
                                        rd_kafka_buf_write_i32(
                                            resp, rktpar->partition);
                                        /* ErrorCode */
                                        rd_kafka_buf_write_i16(resp, part_err);
                                        /* ErrorMessage */
                                        if (part_err)
                                                rd_kafka_buf_write_str(
                                                    resp,
                                                    rd_kafka_err2str(part_err),
                                                    -1);
                                        else
                                                rd_kafka_buf_write_str(
                                                    resp, NULL, -1);
                                        /* CurrentLeader — populated only
                                         * when the per-partition error
                                         * signals stale leader info. */
                                        if (mpart && mpart->leader &&
                                            (part_err ==
                                                 RD_KAFKA_RESP_ERR_NOT_LEADER_OR_FOLLOWER ||
                                             part_err ==
                                                 RD_KAFKA_RESP_ERR_FENCED_LEADER_EPOCH)) {
                                                int found = 0;
                                                rd_kafka_buf_write_i32(
                                                    resp, mpart->leader->id);
                                                rd_kafka_buf_write_i32(
                                                    resp, mpart->leader_epoch);
                                                for (k = 0;
                                                     k < node_endpoint_cnt;
                                                     k++) {
                                                        if (node_endpoints[k] ==
                                                            mpart->leader) {
                                                                found = 1;
                                                                break;
                                                        }
                                                }
                                                if (!found &&
                                                    node_endpoint_cnt < 64)
                                                        node_endpoints
                                                            [node_endpoint_cnt++] =
                                                                mpart->leader;
                                        } else {
                                                rd_kafka_buf_write_i32(
                                                    resp, -1); /* LeaderId */
                                                rd_kafka_buf_write_i32(
                                                    resp, -1); /* LeaderEpoch */
                                        }
                                        /* CurrentLeader tags */
                                        rd_kafka_buf_write_tags_empty(resp);

                                        /* Partition tags */
                                        rd_kafka_buf_write_tags_empty(resp);
                                }

                                /* Topic tags */
                                rd_kafka_buf_write_tags_empty(resp);

                                i += part_cnt;
                        }
                }

                /* NodeEndpoints */
                rd_kafka_buf_write_arraycnt(resp, node_endpoint_cnt);
                for (k = 0; k < node_endpoint_cnt; k++) {
                        rd_kafka_mock_broker_t *nb = node_endpoints[k];
                        rd_kafka_buf_write_i32(resp, nb->id);
                        rd_kafka_buf_write_str(resp, nb->advertised_listener,
                                               -1);
                        rd_kafka_buf_write_i32(resp, (int32_t)nb->port);
                        rd_kafka_buf_write_str(resp, nb->rack, -1);
                        rd_kafka_buf_write_tags_empty(resp);
                }
                /* Top-level tags */
                rd_kafka_buf_write_tags_empty(resp);

                mtx_unlock(&mcluster->lock);

                rd_kafka_mock_connection_send_response0(mconn, resp, rd_true);

                rd_kafka_topic_partition_list_destroy(ack_partitions);
                rd_list_destroy(&ack_entries);
                return 0;
        }

        /* ---- Error response ---- */
        rd_kafka_buf_write_i32(resp, 0);   /* ThrottleTimeMs */
        rd_kafka_buf_write_i16(resp, err); /* ErrorCode */
        rd_kafka_buf_write_str(resp, rd_kafka_err2str(err), -1); /* ErrorMsg */
        rd_kafka_buf_write_arraycnt(resp, 0); /* Responses (empty) */
        rd_kafka_buf_write_arraycnt(resp, 0); /* NodeEndpoints (empty) */
        rd_kafka_buf_write_tags_empty(resp);

        rd_kafka_mock_connection_send_response0(mconn, resp, rd_true);
        rd_kafka_topic_partition_list_destroy(ack_partitions);
        rd_list_destroy(&ack_entries);
        return 0;

err_parse:
        RD_IF_FREE(ack_partitions, rd_kafka_topic_partition_list_destroy);
        rd_list_destroy(&ack_entries);
        rd_kafka_buf_destroy(resp);
        return -1;
}

/**
 * @brief Default request handlers
 */
const struct rd_kafka_mock_api_handler
    rd_kafka_mock_api_handlers[RD_KAFKAP__NUM] = {
        /* [request-type] = { MinVersion, MaxVersion, FlexVersion, callback } */
        [RD_KAFKAP_Produce]      = {0, 10, 9, rd_kafka_mock_handle_Produce},
        [RD_KAFKAP_Fetch]        = {0, 16, 12, rd_kafka_mock_handle_Fetch},
        [RD_KAFKAP_ListOffsets]  = {0, 7, 6, rd_kafka_mock_handle_ListOffsets},
        [RD_KAFKAP_OffsetFetch]  = {0, 6, 6, rd_kafka_mock_handle_OffsetFetch},
        [RD_KAFKAP_OffsetCommit] = {0, 9, 8, rd_kafka_mock_handle_OffsetCommit},
        [RD_KAFKAP_ApiVersion]   = {0, 2, 3, rd_kafka_mock_handle_ApiVersion},
        [RD_KAFKAP_Metadata]     = {0, 12, 9, rd_kafka_mock_handle_Metadata},
        [RD_KAFKAP_FindCoordinator] = {0, 3, 3,
                                       rd_kafka_mock_handle_FindCoordinator},
        [RD_KAFKAP_InitProducerId]  = {0, 4, 2,
                                       rd_kafka_mock_handle_InitProducerId},
        [RD_KAFKAP_JoinGroup]       = {0, 6, 6, rd_kafka_mock_handle_JoinGroup},
        [RD_KAFKAP_Heartbeat]       = {0, 5, 4, rd_kafka_mock_handle_Heartbeat},
        [RD_KAFKAP_LeaveGroup] = {0, 4, 4, rd_kafka_mock_handle_LeaveGroup},
        [RD_KAFKAP_SyncGroup]  = {0, 4, 4, rd_kafka_mock_handle_SyncGroup},
        [RD_KAFKAP_AddPartitionsToTxn] =
            {0, 1, -1, rd_kafka_mock_handle_AddPartitionsToTxn},
        [RD_KAFKAP_AddOffsetsToTxn] = {0, 1, -1,
                                       rd_kafka_mock_handle_AddOffsetsToTxn},
        [RD_KAFKAP_TxnOffsetCommit] = {0, 3, 3,
                                       rd_kafka_mock_handle_TxnOffsetCommit},
        [RD_KAFKAP_EndTxn]          = {0, 1, -1, rd_kafka_mock_handle_EndTxn},
        [RD_KAFKAP_OffsetForLeaderEpoch] =
            {2, 2, -1, rd_kafka_mock_handle_OffsetForLeaderEpoch},
        [RD_KAFKAP_ConsumerGroupHeartbeat] =
            {1, 1, 1, rd_kafka_mock_handle_ConsumerGroupHeartbeat},
        [RD_KAFKAP_ShareGroupHeartbeat] =
            {1, 1, 1, rd_kafka_mock_handle_ShareGroupHeartbeat},
        [RD_KAFKAP_GetTelemetrySubscriptions] =
            {0, 0, 0, rd_kafka_mock_handle_GetTelemetrySubscriptions},
        [RD_KAFKAP_PushTelemetry] = {0, 0, 0,
                                     rd_kafka_mock_handle_PushTelemetry},
        [RD_KAFKAP_ShareFetch]    = {1, 1, 1, rd_kafka_mock_handle_ShareFetch},
        [RD_KAFKAP_ShareAcknowledge] = {1, 1, 1,
                                        rd_kafka_mock_handle_ShareAcknowledge},
};



/**
 * @brief Handle ApiVersionRequest.
 *
 * @remark This is the only handler that needs to handle unsupported
 * ApiVersions.
 */
static int rd_kafka_mock_handle_ApiVersion(rd_kafka_mock_connection_t *mconn,
                                           rd_kafka_buf_t *rkbuf) {
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_buf_t *resp = rd_kafka_mock_buf_new_response(rkbuf);
        size_t of_ApiKeysCnt;
        int cnt                 = 0;
        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;
        int i;

        /* Inject error */
        err = rd_kafka_mock_next_request_error(mconn, resp);

        if (!err && !rd_kafka_mock_cluster_ApiVersion_check(
                        mcluster, rkbuf->rkbuf_reqhdr.ApiKey,
                        rkbuf->rkbuf_reqhdr.ApiVersion))
                err = RD_KAFKA_RESP_ERR_UNSUPPORTED_VERSION;

        /* ApiVersionRequest/Response with flexver (>=v3) has a mix
         * of flexver and standard fields for backwards compatibility reasons,
         * so we handcraft the response instead. */
        resp->rkbuf_flags &= ~RD_KAFKA_OP_F_FLEXVER;

        /* ErrorCode */
        rd_kafka_buf_write_i16(resp, err);

        /* #ApiKeys (updated later) */
        /* FIXME: FLEXVER: This is a uvarint and will require more than 1 byte
         *        if the array count exceeds 126. */
        if (rkbuf->rkbuf_flags & RD_KAFKA_OP_F_FLEXVER)
                of_ApiKeysCnt = rd_kafka_buf_write_i8(resp, 0);
        else
                of_ApiKeysCnt = rd_kafka_buf_write_i32(resp, 0);

        for (i = 0; i < RD_KAFKAP__NUM; i++) {
                if (!mcluster->api_handlers[i].cb ||
                    mcluster->api_handlers[i].MaxVersion == -1)
                        continue;


                if (rkbuf->rkbuf_reqhdr.ApiVersion >= 3) {
                        if (err && i != RD_KAFKAP_ApiVersion)
                                continue;
                }

                /* ApiKey */
                rd_kafka_buf_write_i16(resp, (int16_t)i);
                /* MinVersion */
                rd_kafka_buf_write_i16(resp,
                                       mcluster->api_handlers[i].MinVersion);
                /* MaxVersion */
                rd_kafka_buf_write_i16(resp,
                                       mcluster->api_handlers[i].MaxVersion);

                cnt++;
        }

        /* FIXME: uvarint */
        if (rkbuf->rkbuf_flags & RD_KAFKA_OP_F_FLEXVER) {
                rd_assert(cnt <= 126);
                rd_kafka_buf_update_i8(resp, of_ApiKeysCnt, cnt);
        } else
                rd_kafka_buf_update_i32(resp, of_ApiKeysCnt, cnt);

        if (rkbuf->rkbuf_reqhdr.ApiVersion >= 1) {
                /* ThrottletimeMs */
                rd_kafka_buf_write_i32(resp, 0);
        }

        rd_kafka_mock_connection_send_response(mconn, resp);

        return 0;
}
