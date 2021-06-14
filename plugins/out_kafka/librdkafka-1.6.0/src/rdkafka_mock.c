/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019 Magnus Edenhill
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
 * Mocks
 *
 */

#include "rdkafka_int.h"
#include "rdbuf.h"
#include "rdrand.h"
#include "rdkafka_interceptor.h"
#include "rdkafka_mock_int.h"
#include "rdkafka_transport_int.h"

#include <stdarg.h>

static void
rd_kafka_mock_cluster_destroy0 (rd_kafka_mock_cluster_t *mcluster);


static rd_kafka_mock_broker_t *
rd_kafka_mock_broker_find (const rd_kafka_mock_cluster_t *mcluster,
                           int32_t broker_id) {
        const rd_kafka_mock_broker_t *mrkb;

        TAILQ_FOREACH(mrkb, &mcluster->brokers, link)
                if (mrkb->id == broker_id)
                        return (rd_kafka_mock_broker_t *)mrkb;

        return NULL;
}




/**
 * @brief Unlink and free message set.
 */
static void rd_kafka_mock_msgset_destroy (rd_kafka_mock_partition_t *mpart,
                                          rd_kafka_mock_msgset_t *mset) {
        const rd_kafka_mock_msgset_t *next = TAILQ_NEXT(mset, link);

        /* Removing last messageset */
        if (!next)
                mpart->start_offset = mpart->end_offset;
        else if (mset == TAILQ_FIRST(&mpart->msgsets))
                /* Removing first messageset */
                mpart->start_offset = next->first_offset;

        if (mpart->update_follower_start_offset)
                mpart->follower_start_offset = mpart->start_offset;

        rd_assert(mpart->cnt > 0);
        mpart->cnt--;
        mpart->size -= RD_KAFKAP_BYTES_LEN(&mset->bytes);
        TAILQ_REMOVE(&mpart->msgsets, mset, link);
        rd_free(mset);
}


/**
 * @brief Create a new msgset object with a copy of \p bytes
 *        and appends it to the partition log.
 */
static rd_kafka_mock_msgset_t *
rd_kafka_mock_msgset_new (rd_kafka_mock_partition_t *mpart,
                          const rd_kafkap_bytes_t *bytes, size_t msgcnt) {
        rd_kafka_mock_msgset_t *mset;
        size_t totsize = sizeof(*mset) + RD_KAFKAP_BYTES_LEN(bytes);
        int64_t BaseOffset;
        int64_t orig_start_offset = mpart->start_offset;

        rd_assert(!RD_KAFKAP_BYTES_IS_NULL(bytes));

        mset = rd_malloc(totsize);
        rd_assert(mset != NULL);

        mset->first_offset = mpart->end_offset;
        mset->last_offset = mset->first_offset + msgcnt - 1;
        mpart->end_offset = mset->last_offset + 1;
        if (mpart->update_follower_end_offset)
                mpart->follower_end_offset = mpart->end_offset;
        mpart->cnt++;

        mset->bytes.len = bytes->len;


        mset->bytes.data = (void *)(mset+1);
        memcpy((void *)mset->bytes.data, bytes->data, mset->bytes.len);
        mpart->size += mset->bytes.len;

        /* Update the base Offset in the MessageSet with the
         * actual absolute log offset. */
        BaseOffset = htobe64(mset->first_offset);
        memcpy((void *)mset->bytes.data, &BaseOffset, sizeof(BaseOffset));


        /* Remove old msgsets until within limits */
        while (mpart->cnt > 1 &&
               (mpart->cnt > mpart->max_cnt ||
                mpart->size > mpart->max_size))
                rd_kafka_mock_msgset_destroy(mpart,
                                             TAILQ_FIRST(&mpart->msgsets));

        TAILQ_INSERT_TAIL(&mpart->msgsets, mset, link);

        rd_kafka_dbg(mpart->topic->cluster->rk, MOCK, "MOCK",
                     "Broker %"PRId32": Log append %s [%"PRId32"] "
                     "%"PRIusz" messages, %"PRId32" bytes at offset %"PRId64
                     " (log now %"PRId64"..%"PRId64", "
                     "original start %"PRId64")",
                     mpart->leader->id, mpart->topic->name, mpart->id,
                     msgcnt, RD_KAFKAP_BYTES_LEN(&mset->bytes),
                     mset->first_offset,
                     mpart->start_offset, mpart->end_offset,
                     orig_start_offset);

        return mset;
}

/**
 * @brief Find message set containing \p offset
 */
const rd_kafka_mock_msgset_t *
rd_kafka_mock_msgset_find (const rd_kafka_mock_partition_t *mpart,
                           int64_t offset, rd_bool_t on_follower) {
        const rd_kafka_mock_msgset_t *mset;

        if (!on_follower &&
            (offset < mpart->start_offset ||
             offset > mpart->end_offset))
                return NULL;

        if (on_follower &&
            (offset < mpart->follower_start_offset ||
             offset > mpart->follower_end_offset))
                return NULL;

        /* FIXME: Maintain an index */

        TAILQ_FOREACH(mset, &mpart->msgsets, link) {
                if (mset->first_offset <= offset &&
                    offset <= mset->last_offset)
                        return mset;
        }

        return NULL;
}


/**
 * @brief Append the MessageSets in \p bytes to the \p mpart partition log.
 *
 * @param BaseOffset will contain the first assigned offset of the message set.
 */
rd_kafka_resp_err_t
rd_kafka_mock_partition_log_append (rd_kafka_mock_partition_t *mpart,
                                    const rd_kafkap_bytes_t *bytes,
                                    int64_t *BaseOffset) {
        const int log_decode_errors = LOG_ERR;
        rd_kafka_buf_t *rkbuf;
        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;
        int8_t MagicByte;
        int32_t RecordCount;
        rd_kafka_mock_msgset_t *mset;

        /* Partially parse the MessageSet in \p bytes to get
         * the message count. */
        rkbuf = rd_kafka_buf_new_shadow(bytes->data,
                                        RD_KAFKAP_BYTES_LEN(bytes), NULL);

        rd_kafka_buf_peek_i8(rkbuf, 8+4+4, &MagicByte);
        if (MagicByte != 2) {
                /* We only support MsgVersion 2 for now */
                err = RD_KAFKA_RESP_ERR_UNSUPPORTED_VERSION;
                goto err;
        }

        rd_kafka_buf_peek_i32(rkbuf, RD_KAFKAP_MSGSET_V2_OF_RecordCount,
                              &RecordCount);

        if (RecordCount < 1 ||
            (size_t)RecordCount >
            RD_KAFKAP_BYTES_LEN(bytes) / RD_KAFKAP_MESSAGE_V2_MIN_OVERHEAD) {
                err = RD_KAFKA_RESP_ERR_INVALID_MSG_SIZE;
                goto err;
        }

        rd_kafka_buf_destroy(rkbuf);

        mset = rd_kafka_mock_msgset_new(mpart, bytes, (size_t)RecordCount);

        *BaseOffset = mset->first_offset;

        return RD_KAFKA_RESP_ERR_NO_ERROR;

 err_parse:
        err = rkbuf->rkbuf_err;
 err:
        rd_kafka_buf_destroy(rkbuf);
        return err;
}


/**
 * @brief Set the partition leader, or NULL for leader-less.
 */
static void
rd_kafka_mock_partition_set_leader0 (rd_kafka_mock_partition_t *mpart,
                                     rd_kafka_mock_broker_t *mrkb) {
        mpart->leader = mrkb;
}


/**
 * @brief Automatically assign replicas for partition
 */
static void
rd_kafka_mock_partition_assign_replicas (rd_kafka_mock_partition_t *mpart) {
        rd_kafka_mock_cluster_t *mcluster = mpart->topic->cluster;
        int replica_cnt = RD_MIN(mcluster->defaults.replication_factor,
                                 mcluster->broker_cnt);
        rd_kafka_mock_broker_t *mrkb;
        int i = 0;

        if (mpart->replicas)
                rd_free(mpart->replicas);

        mpart->replicas = rd_calloc(replica_cnt, sizeof(*mpart->replicas));
        mpart->replica_cnt = replica_cnt;

        /* FIXME: randomize this using perhaps reservoir sampling */
        TAILQ_FOREACH(mrkb, &mcluster->brokers, link) {
                if (i == mpart->replica_cnt)
                        break;
                mpart->replicas[i++] = mrkb;
        }

        /* Select a random leader */
        rd_kafka_mock_partition_set_leader0(
                mpart, mpart->replicas[rd_jitter(0, replica_cnt-1)]);
}



/**
 * @brief Unlink and destroy committed offset
 */
static void
rd_kafka_mock_committed_offset_destroy (rd_kafka_mock_partition_t *mpart,
                                        rd_kafka_mock_committed_offset_t *coff){
        rd_kafkap_str_destroy(coff->metadata);
        TAILQ_REMOVE(&mpart->committed_offsets, coff, link);
        rd_free(coff);
}


/**
 * @brief Find previously committed offset for group.
 */
rd_kafka_mock_committed_offset_t *
rd_kafka_mock_committed_offset_find (const rd_kafka_mock_partition_t *mpart,
                                     const rd_kafkap_str_t *group) {
        const rd_kafka_mock_committed_offset_t *coff;

        TAILQ_FOREACH(coff, &mpart->committed_offsets, link) {
                if (!rd_kafkap_str_cmp_str(group, coff->group))
                        return (rd_kafka_mock_committed_offset_t *)coff;
        }

        return NULL;
}


/**
 * @brief Commit offset for group
 */
rd_kafka_mock_committed_offset_t *
rd_kafka_mock_commit_offset (rd_kafka_mock_partition_t *mpart,
                             const rd_kafkap_str_t *group, int64_t offset,
                             const rd_kafkap_str_t *metadata) {
        rd_kafka_mock_committed_offset_t *coff;

        if (!(coff = rd_kafka_mock_committed_offset_find(mpart, group))) {
                size_t slen = (size_t)RD_KAFKAP_STR_LEN(group);

                coff = rd_malloc(sizeof(*coff) + slen + 1);

                coff->group = (char *)(coff + 1);
                memcpy(coff->group, group->str, slen);
                coff->group[slen] = '\0';

                coff->metadata = NULL;

                TAILQ_INSERT_HEAD(&mpart->committed_offsets, coff, link);
        }

        if (coff->metadata)
                rd_kafkap_str_destroy(coff->metadata);

        coff->metadata = rd_kafkap_str_copy(metadata);

        coff->offset = offset;

        rd_kafka_dbg(mpart->topic->cluster->rk, MOCK, "MOCK",
                     "Topic %s [%"PRId32"] committing offset %"PRId64
                     " for group %.*s",
                     mpart->topic->name, mpart->id, offset,
                     RD_KAFKAP_STR_PR(group));

        return coff;
}

/**
 * @brief Destroy resources for partition, but the \p mpart itself is not freed.
 */
static void rd_kafka_mock_partition_destroy (rd_kafka_mock_partition_t *mpart) {
        rd_kafka_mock_msgset_t *mset, *tmp;
        rd_kafka_mock_committed_offset_t *coff, *tmpcoff;

        TAILQ_FOREACH_SAFE(mset, &mpart->msgsets, link, tmp)
                rd_kafka_mock_msgset_destroy(mpart, mset);

        TAILQ_FOREACH_SAFE(coff, &mpart->committed_offsets, link, tmpcoff)
                rd_kafka_mock_committed_offset_destroy(mpart, coff);

        rd_free(mpart->replicas);
}


static void rd_kafka_mock_partition_init (rd_kafka_mock_topic_t *mtopic,
                                          rd_kafka_mock_partition_t *mpart,
                                          int id, int replication_factor) {
        mpart->topic = mtopic;
        mpart->id = id;

        mpart->follower_id = -1;

        TAILQ_INIT(&mpart->msgsets);

        mpart->max_size = 1024*1024*5;
        mpart->max_cnt = 100000;

        mpart->update_follower_start_offset = rd_true;
        mpart->update_follower_end_offset = rd_true;

        TAILQ_INIT(&mpart->committed_offsets);

        rd_kafka_mock_partition_assign_replicas(mpart);
}

rd_kafka_mock_partition_t *
rd_kafka_mock_partition_find (const rd_kafka_mock_topic_t *mtopic,
                              int32_t partition) {
        if (partition < 0 || partition >= mtopic->partition_cnt)
                return NULL;

        return (rd_kafka_mock_partition_t *)&mtopic->partitions[partition];
}


static void rd_kafka_mock_topic_destroy (rd_kafka_mock_topic_t *mtopic) {
        int i;

        for (i = 0 ; i < mtopic->partition_cnt ; i++)
                rd_kafka_mock_partition_destroy(&mtopic->partitions[i]);

        TAILQ_REMOVE(&mtopic->cluster->topics, mtopic, link);
        mtopic->cluster->topic_cnt--;

        rd_free(mtopic->partitions);
        rd_free(mtopic->name);
        rd_free(mtopic);
}


static rd_kafka_mock_topic_t *
rd_kafka_mock_topic_new (rd_kafka_mock_cluster_t *mcluster, const char *topic,
                         int partition_cnt, int replication_factor) {
        rd_kafka_mock_topic_t *mtopic;
        int i;

        mtopic = rd_calloc(1, sizeof(*mtopic));
        mtopic->name = rd_strdup(topic);
        mtopic->cluster = mcluster;

        mtopic->partition_cnt = partition_cnt;
        mtopic->partitions = rd_calloc(partition_cnt,
                                       sizeof(*mtopic->partitions));

        for (i = 0 ; i < partition_cnt ; i++)
                rd_kafka_mock_partition_init(mtopic, &mtopic->partitions[i],
                                             i, replication_factor);

        TAILQ_INSERT_TAIL(&mcluster->topics, mtopic, link);
        mcluster->topic_cnt++;

        rd_kafka_dbg(mcluster->rk, MOCK, "MOCK",
                     "Created topic \"%s\" with %d partition(s) and "
                     "replication-factor %d",
                     mtopic->name, mtopic->partition_cnt, replication_factor);

        return mtopic;
}


rd_kafka_mock_topic_t *
rd_kafka_mock_topic_find (const rd_kafka_mock_cluster_t *mcluster,
                          const char *name) {
        const rd_kafka_mock_topic_t *mtopic;

        TAILQ_FOREACH(mtopic, &mcluster->topics, link) {
                if (!strcmp(mtopic->name, name))
                        return (rd_kafka_mock_topic_t *)mtopic;
        }

        return NULL;
}


rd_kafka_mock_topic_t *
rd_kafka_mock_topic_find_by_kstr (const rd_kafka_mock_cluster_t *mcluster,
                                  const rd_kafkap_str_t *kname) {
        const rd_kafka_mock_topic_t *mtopic;

        TAILQ_FOREACH(mtopic, &mcluster->topics, link) {
                if (!strncmp(mtopic->name, kname->str,
                             RD_KAFKAP_STR_LEN(kname)) &&
                    mtopic->name[RD_KAFKAP_STR_LEN(kname)] == '\0')
                        return (rd_kafka_mock_topic_t *)mtopic;
        }

        return NULL;
}


/**
 * @brief Create a topic using default settings.
 *        The topic must not already exist.
 *
 * @param errp will be set to an error code that is consistent with
 *             new topics on real clusters.
 */
rd_kafka_mock_topic_t *
rd_kafka_mock_topic_auto_create (rd_kafka_mock_cluster_t *mcluster,
                                 const char *topic, int partition_cnt,
                                 rd_kafka_resp_err_t *errp) {
        rd_assert(!rd_kafka_mock_topic_find(mcluster, topic));
        *errp = 0; // FIXME? RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE;
        return rd_kafka_mock_topic_new(mcluster, topic,
                                       partition_cnt == -1 ?
                                       mcluster->defaults.partition_cnt :
                                       partition_cnt,
                                       mcluster->defaults.replication_factor);
}


/**
 * @brief Find or create topic.
 *
 * @param partition_cnt If not -1 and the topic does not exist, the automatic
 *                      topic creation will create this number of topics.
 *                      Otherwise use the default.
 */
rd_kafka_mock_topic_t *
rd_kafka_mock_topic_get (rd_kafka_mock_cluster_t *mcluster, const char *topic,
                         int partition_cnt) {
        rd_kafka_mock_topic_t *mtopic;
        rd_kafka_resp_err_t err;

        if ((mtopic = rd_kafka_mock_topic_find(mcluster, topic)))
                return mtopic;

        return rd_kafka_mock_topic_auto_create(mcluster, topic,
                                               partition_cnt, &err);
}

/**
 * @brief Find or create a partition.
 *
 * @returns NULL if topic already exists and partition is out of range.
 */
static rd_kafka_mock_partition_t *
rd_kafka_mock_partition_get (rd_kafka_mock_cluster_t *mcluster,
                             const char *topic, int32_t partition) {
        rd_kafka_mock_topic_t *mtopic;
        rd_kafka_resp_err_t err;

        if (!(mtopic = rd_kafka_mock_topic_find(mcluster, topic)))
                mtopic = rd_kafka_mock_topic_auto_create(mcluster, topic,
                                                         partition+1, &err);

        if (partition >= mtopic->partition_cnt)
                return NULL;

        return &mtopic->partitions[partition];
}


/**
 * @brief Set IO events for fd
 */
static void
rd_kafka_mock_cluster_io_set_events (rd_kafka_mock_cluster_t *mcluster,
                                     rd_socket_t fd, int events) {
        int i;

        for (i = 0 ; i < mcluster->fd_cnt ; i++) {
                if (mcluster->fds[i].fd == fd) {
                        mcluster->fds[i].events |= events;
                        return;
                }
        }

        rd_assert(!*"mock_cluster_io_set_events: fd not found");
}

/**
 * @brief Set or clear single IO events for fd
 */
static void
rd_kafka_mock_cluster_io_set_event (rd_kafka_mock_cluster_t *mcluster,
                                    rd_socket_t fd, rd_bool_t set, int event) {
        int i;

        for (i = 0 ; i < mcluster->fd_cnt ; i++) {
                if (mcluster->fds[i].fd == fd) {
                        if (set)
                                mcluster->fds[i].events |= event;
                        else
                                mcluster->fds[i].events &= ~event;
                        return;
                }
        }

        rd_assert(!*"mock_cluster_io_set_event: fd not found");
}


/**
 * @brief Clear IO events for fd
 */
static void
rd_kafka_mock_cluster_io_clear_events (rd_kafka_mock_cluster_t *mcluster,
                                       rd_socket_t fd, int events) {
        int i;

        for (i = 0 ; i < mcluster->fd_cnt ; i++) {
                if (mcluster->fds[i].fd == fd) {
                        mcluster->fds[i].events &= ~events;
                        return;
                }
        }

        rd_assert(!*"mock_cluster_io_set_events: fd not found");
}


static void rd_kafka_mock_cluster_io_del (rd_kafka_mock_cluster_t *mcluster,
                                          rd_socket_t fd) {
        int i;

        for (i = 0 ; i < mcluster->fd_cnt ; i++) {
                if (mcluster->fds[i].fd == fd) {
                        if (i + 1 < mcluster->fd_cnt) {
                                memmove(&mcluster->fds[i],
                                        &mcluster->fds[i+1],
                                        sizeof(*mcluster->fds) *
                                        (mcluster->fd_cnt - i));
                                memmove(&mcluster->handlers[i],
                                        &mcluster->handlers[i+1],
                                        sizeof(*mcluster->handlers) *
                                        (mcluster->fd_cnt - i));
                        }

                        mcluster->fd_cnt--;
                        return;
                }
        }

        rd_assert(!*"mock_cluster_io_del: fd not found");
}


/**
 * @brief Add \p fd to IO poll with initial desired events (POLLIN, et.al).
 */
static void rd_kafka_mock_cluster_io_add (rd_kafka_mock_cluster_t *mcluster,
                                          rd_socket_t fd, int events,
                                          rd_kafka_mock_io_handler_t handler,
                                          void *opaque) {

        if (mcluster->fd_cnt + 1 >= mcluster->fd_size) {
                mcluster->fd_size += 8;

                mcluster->fds = rd_realloc(mcluster->fds,
                                           sizeof(*mcluster->fds) *
                                           mcluster->fd_size);
                mcluster->handlers = rd_realloc(mcluster->handlers,
                                                sizeof(*mcluster->handlers) *
                                                mcluster->fd_size);
        }

        memset(&mcluster->fds[mcluster->fd_cnt], 0,
               sizeof(mcluster->fds[mcluster->fd_cnt]));
        mcluster->fds[mcluster->fd_cnt].fd = fd;
        mcluster->fds[mcluster->fd_cnt].events = events;
        mcluster->fds[mcluster->fd_cnt].revents = 0;
        mcluster->handlers[mcluster->fd_cnt].cb = handler;
        mcluster->handlers[mcluster->fd_cnt].opaque = opaque;
        mcluster->fd_cnt++;
}


static void rd_kafka_mock_connection_close (rd_kafka_mock_connection_t *mconn,
                                            const char *reason) {
        rd_kafka_buf_t *rkbuf;

        rd_kafka_dbg(mconn->broker->cluster->rk, MOCK, "MOCK",
                     "Broker %"PRId32": Connection from %s closed: %s",
                     mconn->broker->id,
                     rd_sockaddr2str(&mconn->peer, RD_SOCKADDR2STR_F_PORT),
                     reason);

        rd_kafka_mock_cgrps_connection_closed(mconn->broker->cluster, mconn);

        rd_kafka_timer_stop(&mconn->broker->cluster->timers,
                            &mconn->write_tmr, rd_true);

        while ((rkbuf = TAILQ_FIRST(&mconn->outbufs.rkbq_bufs))) {
                rd_kafka_bufq_deq(&mconn->outbufs, rkbuf);
                rd_kafka_buf_destroy(rkbuf);
        }

        if (mconn->rxbuf)
                rd_kafka_buf_destroy(mconn->rxbuf);

        rd_kafka_mock_cluster_io_del(mconn->broker->cluster,
                                     mconn->transport->rktrans_s);
        TAILQ_REMOVE(&mconn->broker->connections, mconn, link);
        rd_kafka_transport_close(mconn->transport);
        rd_free(mconn);
}


void rd_kafka_mock_connection_send_response (rd_kafka_mock_connection_t *mconn,
                                             rd_kafka_buf_t *resp) {

        resp->rkbuf_ts_sent = rd_clock();

        resp->rkbuf_reshdr.Size =
                (int32_t)(rd_buf_write_pos(&resp->rkbuf_buf) - 4);

        rd_kafka_buf_update_i32(resp, 0, resp->rkbuf_reshdr.Size);

        rd_kafka_dbg(mconn->broker->cluster->rk, MOCK, "MOCK",
                     "Broker %"PRId32": Sending %sResponseV%hd to %s",
                     mconn->broker->id,
                     rd_kafka_ApiKey2str(resp->rkbuf_reqhdr.ApiKey),
                     resp->rkbuf_reqhdr.ApiVersion,
                     rd_sockaddr2str(&mconn->peer, RD_SOCKADDR2STR_F_PORT));

        /* Set up a buffer reader for sending the buffer. */
        rd_slice_init_full(&resp->rkbuf_reader, &resp->rkbuf_buf);

        rd_kafka_bufq_enq(&mconn->outbufs, resp);

        rd_kafka_mock_cluster_io_set_events(mconn->broker->cluster,
                                            mconn->transport->rktrans_s,
                                            POLLOUT);
}


/**
 * @returns 1 if a complete request is available in which case \p slicep
 *          is set to a new slice containing the data,
 *          0 if a complete request is not yet available,
 *          -1 on error.
 */
static int
rd_kafka_mock_connection_read_request (rd_kafka_mock_connection_t *mconn,
                                       rd_kafka_buf_t **rkbufp) {
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_t *rk = mcluster->rk;
        const rd_bool_t log_decode_errors = rd_true;
        rd_kafka_buf_t *rkbuf;
        char errstr[128];
        ssize_t r;

        if (!(rkbuf = mconn->rxbuf)) {
                /* Initial read for a protocol request.
                 * Allocate enough room for the protocol header
                 * (where the total size is located). */
                rkbuf = mconn->rxbuf = rd_kafka_buf_new(2,
                                                        RD_KAFKAP_REQHDR_SIZE);

                /* Protocol parsing code needs the rkb for logging */
                rkbuf->rkbuf_rkb = mconn->broker->cluster->dummy_rkb;
                rd_kafka_broker_keep(rkbuf->rkbuf_rkb);

                /* Make room for request header */
                rd_buf_write_ensure(&rkbuf->rkbuf_buf,
                                    RD_KAFKAP_REQHDR_SIZE,
                                    RD_KAFKAP_REQHDR_SIZE);
        }

        /* Read as much data as possible from the socket into the
         * connection receive buffer. */
        r = rd_kafka_transport_recv(mconn->transport, &rkbuf->rkbuf_buf,
                                    errstr, sizeof(errstr));
        if (r == -1) {
                rd_kafka_dbg(rk, MOCK, "MOCK",
                             "Broker %"PRId32": Connection %s: "
                             "receive failed: %s",
                             mconn->broker->id,
                             rd_sockaddr2str(&mconn->peer,
                                             RD_SOCKADDR2STR_F_PORT),
                             errstr);
                return -1;
        } else if (r == 0) {
                return 0; /* Need more data */
        }

        if (rd_buf_write_pos(&rkbuf->rkbuf_buf) ==
            RD_KAFKAP_REQHDR_SIZE) {
                /* Received the full header, now check full request
                 * size and allocate the buffer accordingly. */

                /* Initialize reader */
                rd_slice_init(&rkbuf->rkbuf_reader,
                              &rkbuf->rkbuf_buf, 0,
                              RD_KAFKAP_REQHDR_SIZE);

                rd_kafka_buf_read_i32(rkbuf,
                                      &rkbuf->rkbuf_reqhdr.Size);
                rd_kafka_buf_read_i16(rkbuf,
                                      &rkbuf->rkbuf_reqhdr.ApiKey);
                rd_kafka_buf_read_i16(rkbuf,
                                      &rkbuf->rkbuf_reqhdr.ApiVersion);

                if (rkbuf->rkbuf_reqhdr.ApiKey < 0 ||
                    rkbuf->rkbuf_reqhdr.ApiKey >= RD_KAFKAP__NUM) {
                        rd_kafka_buf_parse_fail(rkbuf,
                                                "Invalid ApiKey %hd from %s",
                                                rkbuf->rkbuf_reqhdr.ApiKey,
                                                rd_sockaddr2str(
                                                        &mconn->peer,
                                                        RD_SOCKADDR2STR_F_PORT));
                        RD_NOTREACHED();
                }

                /* Check if request version has flexible fields (KIP-482) */
                if (mcluster->api_handlers[rkbuf->rkbuf_reqhdr.ApiKey].
                    FlexVersion != -1 &&
                    rkbuf->rkbuf_reqhdr.ApiVersion >=
                    mcluster->api_handlers[rkbuf->rkbuf_reqhdr.ApiKey].
                    FlexVersion)
                        rkbuf->rkbuf_flags |= RD_KAFKA_OP_F_FLEXVER;


                rd_kafka_buf_read_i32(rkbuf,
                                      &rkbuf->rkbuf_reqhdr.CorrId);

                rkbuf->rkbuf_totlen = rkbuf->rkbuf_reqhdr.Size + 4;

                if (rkbuf->rkbuf_totlen < RD_KAFKAP_REQHDR_SIZE + 2 ||
                    rkbuf->rkbuf_totlen >
                    (size_t)rk->rk_conf.recv_max_msg_size) {
                        rd_kafka_buf_parse_fail(
                                rkbuf,
                                "Invalid request size %"PRId32
                                " from %s",
                                rkbuf->rkbuf_reqhdr.Size,
                                rd_sockaddr2str(
                                        &mconn->peer,
                                        RD_SOCKADDR2STR_F_PORT));
                        RD_NOTREACHED();
                }

                /* Now adjust totlen to skip the header */
                rkbuf->rkbuf_totlen -= RD_KAFKAP_REQHDR_SIZE;

                if (!rkbuf->rkbuf_totlen) {
                        /* Empty request (valid) */
                        *rkbufp = rkbuf;
                        mconn->rxbuf = NULL;
                        return 1;
                }

                /* Allocate space for the request payload */
                rd_buf_write_ensure(&rkbuf->rkbuf_buf,
                                    rkbuf->rkbuf_totlen,
                                    rkbuf->rkbuf_totlen);

        } else if (rd_buf_write_pos(&rkbuf->rkbuf_buf) -
                   RD_KAFKAP_REQHDR_SIZE == rkbuf->rkbuf_totlen) {
                /* The full request is now read into the buffer. */

                /* Set up response reader slice starting past the
                 * request header */
                rd_slice_init(&rkbuf->rkbuf_reader, &rkbuf->rkbuf_buf,
                              RD_KAFKAP_REQHDR_SIZE,
                              rd_buf_len(&rkbuf->rkbuf_buf) -
                              RD_KAFKAP_REQHDR_SIZE);

                /* For convenience, shave off the ClientId */
                rd_kafka_buf_skip_str(rkbuf);

                /* Return the buffer to the caller */
                *rkbufp = rkbuf;
                mconn->rxbuf = NULL;
                return 1;
        }

        return 0;


 err_parse:
        return -1;
}

rd_kafka_buf_t *rd_kafka_mock_buf_new_response (const rd_kafka_buf_t *request) {
        rd_kafka_buf_t *rkbuf = rd_kafka_buf_new(1, 100);

        /* Copy request header so the ApiVersion remains known */
        rkbuf->rkbuf_reqhdr = request->rkbuf_reqhdr;

        /* Size, updated later */
        rd_kafka_buf_write_i32(rkbuf, 0);

        /* CorrId */
        rd_kafka_buf_write_i32(rkbuf, request->rkbuf_reqhdr.CorrId);

        return rkbuf;
}





/**
 * @brief Parse protocol request.
 *
 * @returns 0 on success, -1 on parse error.
 */
static int
rd_kafka_mock_connection_parse_request (rd_kafka_mock_connection_t *mconn,
                                        rd_kafka_buf_t *rkbuf) {
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_t *rk = mcluster->rk;

        if (rkbuf->rkbuf_reqhdr.ApiKey < 0 ||
            rkbuf->rkbuf_reqhdr.ApiKey >= RD_KAFKAP__NUM ||
            !mcluster->api_handlers[rkbuf->rkbuf_reqhdr.ApiKey].cb) {
                rd_kafka_log(rk, LOG_ERR, "MOCK",
                             "Broker %"PRId32": unsupported %sRequestV%hd "
                             "from %s",
                             mconn->broker->id,
                             rd_kafka_ApiKey2str(rkbuf->rkbuf_reqhdr.ApiKey),
                             rkbuf->rkbuf_reqhdr.ApiVersion,
                             rd_sockaddr2str(&mconn->peer,
                                             RD_SOCKADDR2STR_F_PORT));
                return -1;
        }

        /* ApiVersionRequest handles future versions, for everything else
         * make sure the ApiVersion is supported. */
        if (rkbuf->rkbuf_reqhdr.ApiKey != RD_KAFKAP_ApiVersion &&
            !rd_kafka_mock_cluster_ApiVersion_check(
                    mcluster,
                    rkbuf->rkbuf_reqhdr.ApiKey,
                    rkbuf->rkbuf_reqhdr.ApiVersion)) {
                rd_kafka_log(rk, LOG_ERR, "MOCK",
                             "Broker %"PRId32": unsupported %sRequest "
                             "version %hd from %s",
                             mconn->broker->id,
                             rd_kafka_ApiKey2str(rkbuf->rkbuf_reqhdr.ApiKey),
                             rkbuf->rkbuf_reqhdr.ApiVersion,
                             rd_sockaddr2str(&mconn->peer,
                                             RD_SOCKADDR2STR_F_PORT));
                return -1;
        }

        rd_kafka_dbg(rk, MOCK, "MOCK",
                     "Broker %"PRId32": Received %sRequestV%hd from %s",
                     mconn->broker->id,
                     rd_kafka_ApiKey2str(rkbuf->rkbuf_reqhdr.ApiKey),
                     rkbuf->rkbuf_reqhdr.ApiVersion,
                     rd_sockaddr2str(&mconn->peer, RD_SOCKADDR2STR_F_PORT));

        return mcluster->api_handlers[rkbuf->rkbuf_reqhdr.ApiKey].cb(mconn,
                                                                     rkbuf);
}


/**
 * @brief Timer callback to set the POLLOUT flag for a connection after
 *        the delay has expired.
 */
static void rd_kafka_mock_connection_write_out_tmr_cb (rd_kafka_timers_t *rkts,
                                                       void *arg) {
        rd_kafka_mock_connection_t *mconn = arg;

        rd_kafka_mock_cluster_io_set_events(mconn->broker->cluster,
                                            mconn->transport->rktrans_s,
                                            POLLOUT);
}


/**
 * @brief Send as many bytes as possible from the output buffer.
 *
 * @returns 1 if all buffers were sent, 0 if more buffers need to be sent, or
 *          -1 on error.
 */
static ssize_t
rd_kafka_mock_connection_write_out (rd_kafka_mock_connection_t *mconn) {
        rd_kafka_buf_t *rkbuf;
        rd_ts_t now = rd_clock();
        rd_ts_t rtt = mconn->broker->rtt;

        while ((rkbuf = TAILQ_FIRST(&mconn->outbufs.rkbq_bufs))) {
                ssize_t r;
                char errstr[128];
                rd_ts_t ts_delay = 0;

                /* Connection delay/rtt is set. */
                if (rkbuf->rkbuf_ts_sent + rtt > now)
                        ts_delay = rkbuf->rkbuf_ts_sent + rtt;

                /* Response is being delayed */
                if (rkbuf->rkbuf_ts_retry && rkbuf->rkbuf_ts_retry > now)
                        ts_delay = rkbuf->rkbuf_ts_retry + rtt;

                if (ts_delay) {
                        /* Delay response */
                        rd_kafka_timer_start_oneshot(
                                &mconn->broker->cluster->timers,
                                &mconn->write_tmr,
                                rd_false,
                                ts_delay-now,
                                rd_kafka_mock_connection_write_out_tmr_cb,
                                mconn);
                        break;
                }

                if ((r = rd_kafka_transport_send(mconn->transport,
                                                 &rkbuf->rkbuf_reader,
                                                 errstr,
                                                 sizeof(errstr))) == -1)
                        return -1;

                if (rd_slice_remains(&rkbuf->rkbuf_reader) > 0)
                        return 0; /* Partial send, continue next time */

                /* Entire buffer sent, unlink and free */
                rd_kafka_bufq_deq(&mconn->outbufs, rkbuf);

                rd_kafka_buf_destroy(rkbuf);
        }

        rd_kafka_mock_cluster_io_clear_events(mconn->broker->cluster,
                                              mconn->transport->rktrans_s,
                                              POLLOUT);

        return 1;
}


/**
 * @brief Call connection_write_out() for all the broker's connections.
 *
 * Use to check if any responses should be sent when RTT has changed.
 */
static void
rd_kafka_mock_broker_connections_write_out (rd_kafka_mock_broker_t *mrkb) {
        rd_kafka_mock_connection_t *mconn, *tmp;

        /* Need a safe loop since connections may be removed on send error */
        TAILQ_FOREACH_SAFE(mconn, &mrkb->connections, link, tmp) {
                rd_kafka_mock_connection_write_out(mconn);
        }
}


/**
 * @brief Per-Connection IO handler
 */
static void rd_kafka_mock_connection_io (rd_kafka_mock_cluster_t *mcluster,
                                         rd_socket_t fd,
                                         int events, void *opaque) {
        rd_kafka_mock_connection_t *mconn = opaque;

        if (events & POLLIN) {
                rd_kafka_buf_t *rkbuf;
                int r;

                while (1) {
                        /* Read full request */
                        r = rd_kafka_mock_connection_read_request(mconn,
                                                                  &rkbuf);
                        if (r == 0)
                                break; /* Need more data */
                        else if (r == -1) {
                                rd_kafka_mock_connection_close(mconn,
                                                               "Read error");
                                return;
                        }

                        /* Parse and handle request */
                        r = rd_kafka_mock_connection_parse_request(mconn,
                                                                   rkbuf);
                        rd_kafka_buf_destroy(rkbuf);
                        if (r == -1) {
                                rd_kafka_mock_connection_close(mconn,
                                                               "Parse error");
                                return;
                        }
                }
        }

        if (events & (POLLERR|POLLHUP)) {
                rd_kafka_mock_connection_close(mconn, "Disconnected");
                return;
        }

        if (events & POLLOUT) {
                if (rd_kafka_mock_connection_write_out(mconn) == -1) {
                        rd_kafka_mock_connection_close(mconn, "Write error");
                        return;
                }
        }
}


/**
 * @brief Set connection as blocking, POLLIN will not be served.
 */
void rd_kafka_mock_connection_set_blocking (rd_kafka_mock_connection_t *mconn,
                                            rd_bool_t blocking) {
        rd_kafka_mock_cluster_io_set_event(mconn->broker->cluster,
                                           mconn->transport->rktrans_s,
                                           !blocking, POLLIN);
}


static rd_kafka_mock_connection_t *
rd_kafka_mock_connection_new (rd_kafka_mock_broker_t *mrkb, rd_socket_t fd,
                              const struct sockaddr_in *peer) {
        rd_kafka_mock_connection_t *mconn;
        rd_kafka_transport_t *rktrans;
        char errstr[128];

        if (!mrkb->up) {
                rd_close(fd);
                return NULL;
        }

        rktrans = rd_kafka_transport_new(mrkb->cluster->dummy_rkb, fd,
                                         errstr, sizeof(errstr));
        if (!rktrans) {
                rd_kafka_log(mrkb->cluster->rk, LOG_ERR, "MOCK",
                             "Failed to create transport for new "
                             "mock connection: %s", errstr);
                rd_close(fd);
                return NULL;
        }

        rd_kafka_transport_post_connect_setup(rktrans);

        mconn = rd_calloc(1, sizeof(*mconn));
        mconn->broker = mrkb;
        mconn->transport = rktrans;
        mconn->peer = *peer;
        rd_kafka_bufq_init(&mconn->outbufs);

        TAILQ_INSERT_TAIL(&mrkb->connections, mconn, link);

        rd_kafka_mock_cluster_io_add(mrkb->cluster,
                                     mconn->transport->rktrans_s,
                                     POLLIN,
                                     rd_kafka_mock_connection_io,
                                     mconn);

        rd_kafka_dbg(mrkb->cluster->rk, MOCK, "MOCK",
                     "Broker %"PRId32": New connection from %s",
                     mrkb->id,
                     rd_sockaddr2str(&mconn->peer, RD_SOCKADDR2STR_F_PORT));

        return mconn;
}



static void rd_kafka_mock_cluster_op_io (rd_kafka_mock_cluster_t *mcluster,
                                         rd_socket_t fd,
                                         int events, void *opaque) {
        /* Read wake-up fd data and throw away, just used for wake-ups*/
        char buf[1024];
        while (rd_read(fd, buf, sizeof(buf)) > 0)
                ; /* Read all buffered signalling bytes */
}


static int rd_kafka_mock_cluster_io_poll (rd_kafka_mock_cluster_t *mcluster,
                                          int timeout_ms) {
        int r;
        int i;

        r = rd_socket_poll(mcluster->fds, mcluster->fd_cnt, timeout_ms);
        if (r == RD_SOCKET_ERROR) {
                rd_kafka_log(mcluster->rk, LOG_CRIT, "MOCK",
                             "Mock cluster failed to poll %d fds: %d: %s",
                             mcluster->fd_cnt, r,
                             rd_socket_strerror(rd_socket_errno));
                return -1;
        }

        /* Serve ops, if any */
        rd_kafka_q_serve(mcluster->ops, RD_POLL_NOWAIT, 0,
                         RD_KAFKA_Q_CB_CALLBACK, NULL, NULL);

        /* Handle IO events, if any, and if not terminating */
        for (i = 0 ; mcluster->run  && r > 0 && i < mcluster->fd_cnt ; i++) {
                if (!mcluster->fds[i].revents)
                        continue;

                /* Call IO handler */
                mcluster->handlers[i].cb(mcluster, mcluster->fds[i].fd,
                                         mcluster->fds[i].revents,
                                         mcluster->handlers[i].opaque);
                r--;
        }

        return 0;
}


static int rd_kafka_mock_cluster_thread_main (void *arg) {
        rd_kafka_mock_cluster_t *mcluster = arg;

        rd_kafka_set_thread_name("mock");
        rd_kafka_set_thread_sysname("rdk:mock");
        rd_kafka_interceptors_on_thread_start(mcluster->rk,
                                              RD_KAFKA_THREAD_BACKGROUND);
        rd_atomic32_add(&rd_kafka_thread_cnt_curr, 1);

        /* Op wakeup fd */
        rd_kafka_mock_cluster_io_add(mcluster, mcluster->wakeup_fds[0],
                                     POLLIN,
                                     rd_kafka_mock_cluster_op_io, NULL);

        mcluster->run = rd_true;

        while (mcluster->run) {
                int sleeptime =
                        (int)((rd_kafka_timers_next(
                                       &mcluster->timers,
                                       1000*1000/*1s*/,
                                       1/*lock*/) + 999) / 1000);

                if (rd_kafka_mock_cluster_io_poll(mcluster, sleeptime) == -1)
                        break;

                rd_kafka_timers_run(&mcluster->timers, RD_POLL_NOWAIT);
        }

        rd_kafka_mock_cluster_io_del(mcluster, mcluster->wakeup_fds[0]);


        rd_kafka_interceptors_on_thread_exit(mcluster->rk,
                                             RD_KAFKA_THREAD_BACKGROUND);
        rd_atomic32_sub(&rd_kafka_thread_cnt_curr, 1);

        rd_kafka_mock_cluster_destroy0(mcluster);

        return 0;
}



static void rd_kafka_mock_broker_listen_io (rd_kafka_mock_cluster_t *mcluster,
                                            rd_socket_t fd,
                                            int events, void *opaque) {
        rd_kafka_mock_broker_t *mrkb = opaque;

        if (events & (POLLERR|POLLHUP))
                rd_assert(!*"Mock broker listen socket error");

        if (events & POLLIN) {
                rd_socket_t new_s;
                struct sockaddr_in peer;
                socklen_t peer_size = sizeof(peer);

                new_s = accept(mrkb->listen_s, (struct sockaddr *)&peer,
                               &peer_size);
                if (new_s == RD_SOCKET_ERROR) {
                        rd_kafka_log(mcluster->rk, LOG_ERR, "MOCK",
                                     "Failed to accept mock broker socket: %s",
                                     rd_socket_strerror(rd_socket_errno));
                        return;
                }

                rd_kafka_mock_connection_new(mrkb, new_s, &peer);
        }
}


/**
 * @brief Close all connections to broker.
 */
static void rd_kafka_mock_broker_close_all (rd_kafka_mock_broker_t *mrkb,
                                            const char *reason) {
        rd_kafka_mock_connection_t *mconn;

        while ((mconn = TAILQ_FIRST(&mrkb->connections)))
                rd_kafka_mock_connection_close(mconn, reason);
}

/**
 * @brief Destroy error stack, must be unlinked.
 */
static void
rd_kafka_mock_error_stack_destroy (rd_kafka_mock_error_stack_t *errstack) {
        if (errstack->errs)
                rd_free(errstack->errs);
        rd_free(errstack);
}


static void rd_kafka_mock_broker_destroy (rd_kafka_mock_broker_t *mrkb) {
        rd_kafka_mock_error_stack_t *errstack;

        rd_kafka_mock_broker_close_all(mrkb, "Destroying broker");

        rd_kafka_mock_cluster_io_del(mrkb->cluster, mrkb->listen_s);
        rd_close(mrkb->listen_s);

        while ((errstack = TAILQ_FIRST(&mrkb->errstacks))) {
                TAILQ_REMOVE(&mrkb->errstacks, errstack, link);
                rd_kafka_mock_error_stack_destroy(errstack);
        }

        TAILQ_REMOVE(&mrkb->cluster->brokers, mrkb, link);
        mrkb->cluster->broker_cnt--;

        rd_free(mrkb);
}


static rd_kafka_mock_broker_t *
rd_kafka_mock_broker_new (rd_kafka_mock_cluster_t *mcluster,
                          int32_t broker_id) {
        rd_kafka_mock_broker_t *mrkb;
        rd_socket_t listen_s;
        struct sockaddr_in sin = {
                .sin_family = AF_INET,
                .sin_addr = {
                        .s_addr = htonl(INADDR_LOOPBACK)
                }
        };
        socklen_t sin_len = sizeof(sin);

        /*
         * Create and bind socket to any loopback port
         */
        listen_s = rd_kafka_socket_cb_linux(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                                            NULL);
        if (listen_s == RD_SOCKET_ERROR) {
                rd_kafka_log(mcluster->rk, LOG_CRIT, "MOCK",
                             "Unable to create mock broker listen socket: %s",
                             rd_socket_strerror(rd_socket_errno));
                return NULL;
        }

        if (bind(listen_s, (struct sockaddr *)&sin, sizeof(sin)) ==
            RD_SOCKET_ERROR) {
                rd_kafka_log(mcluster->rk, LOG_CRIT, "MOCK",
                             "Failed to bind mock broker socket to %s: %s",
                             rd_socket_strerror(rd_socket_errno),
                             rd_sockaddr2str(&sin, RD_SOCKADDR2STR_F_PORT));
                rd_close(listen_s);
                return NULL;
        }

        if (getsockname(listen_s, (struct sockaddr *)&sin, &sin_len) ==
            RD_SOCKET_ERROR) {
                rd_kafka_log(mcluster->rk, LOG_CRIT, "MOCK",
                             "Failed to get mock broker socket name: %s",
                             rd_socket_strerror(rd_socket_errno));
                rd_close(listen_s);
                return NULL;
        }
        rd_assert(sin.sin_family == AF_INET);

        if (listen(listen_s, 5) == RD_SOCKET_ERROR) {
                rd_kafka_log(mcluster->rk, LOG_CRIT, "MOCK",
                             "Failed to listen on mock broker socket: %s",
                             rd_socket_strerror(rd_socket_errno));
                rd_close(listen_s);
                return NULL;
        }


        /*
         * Create mock broker object
         */
        mrkb = rd_calloc(1, sizeof(*mrkb));

        mrkb->id = broker_id;
        mrkb->cluster = mcluster;
        mrkb->up = rd_true;
        mrkb->listen_s = listen_s;
        mrkb->port = ntohs(sin.sin_port);
        rd_snprintf(mrkb->advertised_listener,
                    sizeof(mrkb->advertised_listener),
                    "%s", rd_sockaddr2str(&sin, 0));

        TAILQ_INIT(&mrkb->connections);
        TAILQ_INIT(&mrkb->errstacks);

        TAILQ_INSERT_TAIL(&mcluster->brokers, mrkb, link);
        mcluster->broker_cnt++;

        rd_kafka_mock_cluster_io_add(mcluster, listen_s, POLLIN,
                                     rd_kafka_mock_broker_listen_io, mrkb);

        return mrkb;
}


/**
 * @returns the coordtype_t for a coord type string, or -1 on error.
 */
static rd_kafka_coordtype_t rd_kafka_mock_coord_str2type (const char *str) {
        if (!strcmp(str, "transaction"))
                return RD_KAFKA_COORD_TXN;
        else if (!strcmp(str, "group"))
                return RD_KAFKA_COORD_GROUP;
        else
                return (rd_kafka_coordtype_t)-1;
}


/**
 * @brief Unlink and destroy coordinator.
 */
static void rd_kafka_mock_coord_destroy (rd_kafka_mock_cluster_t *mcluster,
                                         rd_kafka_mock_coord_t *mcoord) {
        TAILQ_REMOVE(&mcluster->coords, mcoord, link);
        rd_free(mcoord->key);
        rd_free(mcoord);
}

/**
 * @brief Find coordinator by type and key.
 */
static rd_kafka_mock_coord_t *
rd_kafka_mock_coord_find (rd_kafka_mock_cluster_t *mcluster,
                          rd_kafka_coordtype_t type, const char *key) {
        rd_kafka_mock_coord_t *mcoord;

        TAILQ_FOREACH(mcoord, &mcluster->coords, link) {
                if (mcoord->type == type && !strcmp(mcoord->key, key))
                        return mcoord;
        }

        return NULL;
}


/**
 * @returns the coordinator for KeyType,Key (e.g., GROUP,mygroup).
 */
rd_kafka_mock_broker_t *
rd_kafka_mock_cluster_get_coord (rd_kafka_mock_cluster_t *mcluster,
                                 rd_kafka_coordtype_t KeyType,
                                 const rd_kafkap_str_t *Key) {
        rd_kafka_mock_broker_t *mrkb;
        rd_kafka_mock_coord_t *mcoord;
        char *key;
        rd_crc32_t hash;
        int idx;

        /* Try the explicit coord list first */
        RD_KAFKAP_STR_DUPA(&key, Key);
        if ((mcoord = rd_kafka_mock_coord_find(mcluster, KeyType, key)))
                return rd_kafka_mock_broker_find(mcluster, mcoord->broker_id);

        /* Else hash the key to select an available broker. */
        hash = rd_crc32(Key->str, RD_KAFKAP_STR_LEN(Key));
        idx = (int)(hash % mcluster->broker_cnt);

        /* Use the broker index in the list */
        TAILQ_FOREACH(mrkb, &mcluster->brokers, link)
                if (idx-- == 0)
                        return mrkb;

        RD_NOTREACHED();
        return NULL;
}


/**
 * @brief Explicitly set coordinator for \p key_type ("transaction", "group")
 *        and \p key.
 */
static rd_kafka_mock_coord_t *
rd_kafka_mock_coord_set (rd_kafka_mock_cluster_t *mcluster,
                         const char *key_type, const char *key,
                         int32_t broker_id) {
        rd_kafka_mock_coord_t *mcoord;
        rd_kafka_coordtype_t type;

        if ((int)(type = rd_kafka_mock_coord_str2type(key_type)) == -1)
                return NULL;

        if ((mcoord = rd_kafka_mock_coord_find(mcluster, type, key)))
                rd_kafka_mock_coord_destroy(mcluster, mcoord);

        mcoord = rd_calloc(1, sizeof(*mcoord));
        mcoord->type = type;
        mcoord->key = rd_strdup(key);
        mcoord->broker_id = broker_id;

        TAILQ_INSERT_TAIL(&mcluster->coords, mcoord, link);

        return mcoord;
}


/**
 * @brief Remove and return the next error, or RD_KAFKA_RESP_ERR_NO_ERROR
 *        if no error.
 */
static rd_kafka_resp_err_t
rd_kafka_mock_error_stack_next (rd_kafka_mock_error_stack_t *errstack) {
        rd_kafka_resp_err_t err;

        if (likely(errstack->cnt == 0))
                return RD_KAFKA_RESP_ERR_NO_ERROR;

        err = errstack->errs[0];
        errstack->cnt--;
        if (errstack->cnt > 0)
                memmove(errstack->errs, &errstack->errs[1],
                        sizeof(*errstack->errs) * errstack->cnt);

        return err;
}


/**
 * @brief Find an error stack based on \p ApiKey
 */
static rd_kafka_mock_error_stack_t *
rd_kafka_mock_error_stack_find (const rd_kafka_mock_error_stack_head_t *shead,
                                int16_t ApiKey) {
        const rd_kafka_mock_error_stack_t *errstack;

        TAILQ_FOREACH(errstack, shead, link)
                if (errstack->ApiKey == ApiKey)
                        return (rd_kafka_mock_error_stack_t *)errstack;

        return NULL;
}



/**
 * @brief Find or create an error stack based on \p ApiKey
 */
static rd_kafka_mock_error_stack_t *
rd_kafka_mock_error_stack_get (rd_kafka_mock_error_stack_head_t *shead,
                               int16_t ApiKey) {
        rd_kafka_mock_error_stack_t *errstack;

        if ((errstack = rd_kafka_mock_error_stack_find(shead, ApiKey)))
                return errstack;

        errstack = rd_calloc(1, sizeof(*errstack));

        errstack->ApiKey = ApiKey;
        TAILQ_INSERT_TAIL(shead, errstack, link);

        return errstack;
}



/**
 * @brief Removes and returns the next request error for request type \p ApiKey.
 */
rd_kafka_resp_err_t
rd_kafka_mock_next_request_error (rd_kafka_mock_connection_t *mconn,
                                  int16_t ApiKey) {
        rd_kafka_mock_cluster_t *mcluster = mconn->broker->cluster;
        rd_kafka_mock_error_stack_t *errstack;
        rd_kafka_resp_err_t err;

        mtx_lock(&mcluster->lock);

        errstack = rd_kafka_mock_error_stack_find(&mconn->broker->errstacks,
                                                  ApiKey);
        if (likely(!errstack)) {
                errstack = rd_kafka_mock_error_stack_find(&mcluster->errstacks,
                                                          ApiKey);
                if (likely(!errstack)) {
                        mtx_unlock(&mcluster->lock);
                        return RD_KAFKA_RESP_ERR_NO_ERROR;
                }
        }

        err = rd_kafka_mock_error_stack_next(errstack);
        mtx_unlock(&mcluster->lock);

        return err;
}


void rd_kafka_mock_clear_request_errors (rd_kafka_mock_cluster_t *mcluster,
                                         int16_t ApiKey) {
        rd_kafka_mock_error_stack_t *errstack;

        mtx_lock(&mcluster->lock);

        errstack = rd_kafka_mock_error_stack_find(&mcluster->errstacks, ApiKey);
        if (errstack)
                errstack->cnt = 0;

        mtx_unlock(&mcluster->lock);
}


void
rd_kafka_mock_push_request_errors_array (rd_kafka_mock_cluster_t *mcluster,
                                         int16_t ApiKey,
                                         size_t cnt,
                                         const rd_kafka_resp_err_t *errors) {
        rd_kafka_mock_error_stack_t *errstack;
        size_t totcnt;

        mtx_lock(&mcluster->lock);

        errstack = rd_kafka_mock_error_stack_get(&mcluster->errstacks, ApiKey);

        totcnt = errstack->cnt + cnt;

        if (totcnt > errstack->size) {
                errstack->size = totcnt + 4;
                errstack->errs = rd_realloc(errstack->errs,
                                            errstack->size *
                                            sizeof(*errstack->errs));
        }

        while (cnt > 0)
                errstack->errs[errstack->cnt++] = errors[--cnt];

        mtx_unlock(&mcluster->lock);
}

void rd_kafka_mock_push_request_errors (rd_kafka_mock_cluster_t *mcluster,
                                        int16_t ApiKey, size_t cnt, ...) {
        va_list ap;
        rd_kafka_resp_err_t *errors = rd_alloca(sizeof(*errors) * cnt);
        size_t i;

        va_start(ap, cnt);
        for (i = 0 ; i < cnt ; i++)
                errors[i] = va_arg(ap, rd_kafka_resp_err_t);

        rd_kafka_mock_push_request_errors_array(mcluster, ApiKey, cnt, errors);
}


rd_kafka_resp_err_t
rd_kafka_mock_broker_push_request_errors (rd_kafka_mock_cluster_t *mcluster,
                                          int32_t broker_id,
                                          int16_t ApiKey, size_t cnt, ...) {
        rd_kafka_mock_broker_t *mrkb;
        va_list ap;
        rd_kafka_mock_error_stack_t *errstack;
        size_t totcnt;

        mtx_lock(&mcluster->lock);

        if (!(mrkb = rd_kafka_mock_broker_find(mcluster, broker_id))) {
                mtx_unlock(&mcluster->lock);
                return RD_KAFKA_RESP_ERR__UNKNOWN_BROKER;
        }

        errstack = rd_kafka_mock_error_stack_get(&mrkb->errstacks, ApiKey);

        totcnt = errstack->cnt + cnt;

        if (totcnt > errstack->size) {
                errstack->size = totcnt + 4;
                errstack->errs = rd_realloc(errstack->errs,
                                            errstack->size *
                                            sizeof(*errstack->errs));
        }

        va_start(ap, cnt);
        while (cnt-- > 0)
                errstack->errs[errstack->cnt++] =
                        va_arg(ap, rd_kafka_resp_err_t);
        va_end(ap);

        mtx_unlock(&mcluster->lock);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


void rd_kafka_mock_topic_set_error (rd_kafka_mock_cluster_t *mcluster,
                                    const char *topic,
                                    rd_kafka_resp_err_t err) {
        rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_MOCK);

        rko->rko_u.mock.name = rd_strdup(topic);
        rko->rko_u.mock.cmd = RD_KAFKA_MOCK_CMD_TOPIC_SET_ERROR;
        rko->rko_u.mock.err = err;

        rko = rd_kafka_op_req(mcluster->ops, rko, RD_POLL_INFINITE);
        if (rko)
                rd_kafka_op_destroy(rko);
}


rd_kafka_resp_err_t
rd_kafka_mock_topic_create (rd_kafka_mock_cluster_t *mcluster,
                            const char *topic, int partition_cnt,
                            int replication_factor) {
        rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_MOCK);

        rko->rko_u.mock.name = rd_strdup(topic);
        rko->rko_u.mock.lo = partition_cnt;
        rko->rko_u.mock.hi = replication_factor;
        rko->rko_u.mock.cmd = RD_KAFKA_MOCK_CMD_TOPIC_CREATE;

        return rd_kafka_op_err_destroy(
                rd_kafka_op_req(mcluster->ops, rko, RD_POLL_INFINITE));
}

rd_kafka_resp_err_t
rd_kafka_mock_partition_set_leader (rd_kafka_mock_cluster_t *mcluster,
                                    const char *topic, int32_t partition,
                                    int32_t broker_id) {
        rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_MOCK);

        rko->rko_u.mock.name = rd_strdup(topic);
        rko->rko_u.mock.cmd = RD_KAFKA_MOCK_CMD_PART_SET_LEADER;
        rko->rko_u.mock.partition = partition;
        rko->rko_u.mock.broker_id = broker_id;

        return rd_kafka_op_err_destroy(
                rd_kafka_op_req(mcluster->ops, rko, RD_POLL_INFINITE));
}

rd_kafka_resp_err_t
rd_kafka_mock_partition_set_follower (rd_kafka_mock_cluster_t *mcluster,
                                      const char *topic, int32_t partition,
                                      int32_t broker_id) {
        rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_MOCK);

        rko->rko_u.mock.name = rd_strdup(topic);
        rko->rko_u.mock.cmd = RD_KAFKA_MOCK_CMD_PART_SET_FOLLOWER;
        rko->rko_u.mock.partition = partition;
        rko->rko_u.mock.broker_id = broker_id;

        return rd_kafka_op_err_destroy(
                rd_kafka_op_req(mcluster->ops, rko, RD_POLL_INFINITE));
}

rd_kafka_resp_err_t
rd_kafka_mock_partition_set_follower_wmarks (rd_kafka_mock_cluster_t *mcluster,
                                             const char *topic,
                                             int32_t partition,
                                             int64_t lo, int64_t hi) {
        rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_MOCK);

        rko->rko_u.mock.name = rd_strdup(topic);
        rko->rko_u.mock.cmd = RD_KAFKA_MOCK_CMD_PART_SET_FOLLOWER_WMARKS;
        rko->rko_u.mock.partition = partition;
        rko->rko_u.mock.lo = lo;
        rko->rko_u.mock.hi = hi;

        return rd_kafka_op_err_destroy(
                rd_kafka_op_req(mcluster->ops, rko, RD_POLL_INFINITE));
}

rd_kafka_resp_err_t
rd_kafka_mock_broker_set_down (rd_kafka_mock_cluster_t *mcluster,
                               int32_t broker_id) {
        rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_MOCK);

        rko->rko_u.mock.broker_id = broker_id;
        rko->rko_u.mock.lo = rd_false;
        rko->rko_u.mock.cmd = RD_KAFKA_MOCK_CMD_BROKER_SET_UPDOWN;

        return rd_kafka_op_err_destroy(
                rd_kafka_op_req(mcluster->ops, rko, RD_POLL_INFINITE));
}

rd_kafka_resp_err_t
rd_kafka_mock_broker_set_up (rd_kafka_mock_cluster_t *mcluster,
                             int32_t broker_id) {
        rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_MOCK);

        rko->rko_u.mock.broker_id = broker_id;
        rko->rko_u.mock.lo = rd_true;
        rko->rko_u.mock.cmd = RD_KAFKA_MOCK_CMD_BROKER_SET_UPDOWN;

        return rd_kafka_op_err_destroy(
                rd_kafka_op_req(mcluster->ops, rko, RD_POLL_INFINITE));
}

rd_kafka_resp_err_t
rd_kafka_mock_broker_set_rtt (rd_kafka_mock_cluster_t *mcluster,
                              int32_t broker_id, int rtt_ms) {
        rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_MOCK);

        rko->rko_u.mock.broker_id = broker_id;
        rko->rko_u.mock.lo = rtt_ms;
        rko->rko_u.mock.cmd = RD_KAFKA_MOCK_CMD_BROKER_SET_RTT;

        return rd_kafka_op_err_destroy(
                rd_kafka_op_req(mcluster->ops, rko, RD_POLL_INFINITE));
}

rd_kafka_resp_err_t
rd_kafka_mock_broker_set_rack (rd_kafka_mock_cluster_t *mcluster,
                               int32_t broker_id, const char *rack) {
        rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_MOCK);

        rko->rko_u.mock.broker_id = broker_id;
        rko->rko_u.mock.name = rd_strdup(rack);
        rko->rko_u.mock.cmd = RD_KAFKA_MOCK_CMD_BROKER_SET_RACK;

        return rd_kafka_op_err_destroy(
                rd_kafka_op_req(mcluster->ops, rko, RD_POLL_INFINITE));
}

rd_kafka_resp_err_t
rd_kafka_mock_coordinator_set (rd_kafka_mock_cluster_t *mcluster,
                               const char *key_type, const char *key,
                               int32_t broker_id) {
        rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_MOCK);

        rko->rko_u.mock.name = rd_strdup(key_type);
        rko->rko_u.mock.str = rd_strdup(key);
        rko->rko_u.mock.broker_id = broker_id;
        rko->rko_u.mock.cmd = RD_KAFKA_MOCK_CMD_COORD_SET;

        return rd_kafka_op_err_destroy(
                rd_kafka_op_req(mcluster->ops, rko, RD_POLL_INFINITE));
}

rd_kafka_resp_err_t
rd_kafka_mock_set_apiversion (rd_kafka_mock_cluster_t *mcluster,
                              int16_t ApiKey,
                              int16_t MinVersion, int16_t MaxVersion) {
        rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_MOCK);

        rko->rko_u.mock.partition = ApiKey;
        rko->rko_u.mock.lo = MinVersion;
        rko->rko_u.mock.hi = MaxVersion;
        rko->rko_u.mock.cmd = RD_KAFKA_MOCK_CMD_APIVERSION_SET;

        return rd_kafka_op_err_destroy(
                rd_kafka_op_req(mcluster->ops, rko, RD_POLL_INFINITE));
}






/**
 * @brief Handle command op
 *
 * @locality mcluster thread
 */
static rd_kafka_resp_err_t
rd_kafka_mock_cluster_cmd (rd_kafka_mock_cluster_t *mcluster,
                           rd_kafka_op_t *rko) {
        rd_kafka_mock_topic_t *mtopic;
        rd_kafka_mock_partition_t *mpart;
        rd_kafka_mock_broker_t *mrkb;

        switch (rko->rko_u.mock.cmd)
        {
        case RD_KAFKA_MOCK_CMD_TOPIC_CREATE:
                if (rd_kafka_mock_topic_find(mcluster, rko->rko_u.mock.name))
                        return RD_KAFKA_RESP_ERR_TOPIC_ALREADY_EXISTS;

                if (!rd_kafka_mock_topic_new(mcluster, rko->rko_u.mock.name,
                                             /* partition_cnt */
                                             (int)rko->rko_u.mock.lo,
                                             /* replication_factor */
                                             (int)rko->rko_u.mock.hi))
                        return RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION;
                break;

        case RD_KAFKA_MOCK_CMD_TOPIC_SET_ERROR:
                mtopic = rd_kafka_mock_topic_get(mcluster,
                                                 rko->rko_u.mock.name, -1);
                mtopic->err = rko->rko_u.mock.err;
                break;

        case RD_KAFKA_MOCK_CMD_PART_SET_LEADER:
                mpart = rd_kafka_mock_partition_get(mcluster,
                                                    rko->rko_u.mock.name,
                                                    rko->rko_u.mock.partition);
                if (!mpart)
                        return RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;

                if (rko->rko_u.mock.broker_id != -1) {
                        mrkb = rd_kafka_mock_broker_find(
                                mcluster, rko->rko_u.mock.broker_id);
                        if (!mrkb)
                                return RD_KAFKA_RESP_ERR_BROKER_NOT_AVAILABLE;
                } else {
                        mrkb = NULL;
                }

                rd_kafka_dbg(mcluster->rk, MOCK, "MOCK",
                             "Set %s [%"PRId32"] leader to %"PRId32,
                             rko->rko_u.mock.name, rko->rko_u.mock.partition,
                             rko->rko_u.mock.broker_id);

                rd_kafka_mock_partition_set_leader0(mpart, mrkb);
                break;

        case RD_KAFKA_MOCK_CMD_PART_SET_FOLLOWER:
                mpart = rd_kafka_mock_partition_get(mcluster,
                                                    rko->rko_u.mock.name,
                                                    rko->rko_u.mock.partition);
                if (!mpart)
                        return RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;

                rd_kafka_dbg(mcluster->rk, MOCK, "MOCK",
                             "Set %s [%"PRId32"] preferred follower "
                             "to %"PRId32,
                             rko->rko_u.mock.name, rko->rko_u.mock.partition,
                             rko->rko_u.mock.broker_id);

                mpart->follower_id = rko->rko_u.mock.broker_id;
                break;

        case RD_KAFKA_MOCK_CMD_PART_SET_FOLLOWER_WMARKS:
                mpart = rd_kafka_mock_partition_get(mcluster,
                                                    rko->rko_u.mock.name,
                                                    rko->rko_u.mock.partition);
                if (!mpart)
                        return RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART;

                rd_kafka_dbg(mcluster->rk, MOCK, "MOCK",
                             "Set %s [%"PRId32"] follower "
                             "watermark offsets to %"PRId64"..%"PRId64,
                             rko->rko_u.mock.name, rko->rko_u.mock.partition,
                             rko->rko_u.mock.lo, rko->rko_u.mock.hi);

                if (rko->rko_u.mock.lo == -1) {
                        mpart->follower_start_offset = mpart->start_offset;
                        mpart->update_follower_start_offset = rd_true;
                } else {
                        mpart->follower_start_offset = rko->rko_u.mock.lo;
                        mpart->update_follower_start_offset = rd_false;
                }

                if (rko->rko_u.mock.hi == -1) {
                        mpart->follower_end_offset = mpart->end_offset;
                        mpart->update_follower_end_offset = rd_true;
                } else {
                        mpart->follower_end_offset = rko->rko_u.mock.hi;
                        mpart->update_follower_end_offset = rd_false;
                }
                break;

        case RD_KAFKA_MOCK_CMD_BROKER_SET_UPDOWN:
                mrkb = rd_kafka_mock_broker_find(mcluster,
                                                 rko->rko_u.mock.broker_id);
                if (!mrkb)
                        return RD_KAFKA_RESP_ERR_BROKER_NOT_AVAILABLE;

                mrkb->up = (rd_bool_t)rko->rko_u.mock.lo;

                if (!mrkb->up)
                        rd_kafka_mock_broker_close_all(mrkb, "Broker down");
                break;

        case RD_KAFKA_MOCK_CMD_BROKER_SET_RTT:
                mrkb = rd_kafka_mock_broker_find(mcluster,
                                                 rko->rko_u.mock.broker_id);
                if (!mrkb)
                        return RD_KAFKA_RESP_ERR_BROKER_NOT_AVAILABLE;

                mrkb->rtt = (rd_ts_t)rko->rko_u.mock.lo * 1000;

                /* Check if there is anything to send now that the RTT
                 * has changed or if a timer is to be started. */
                rd_kafka_mock_broker_connections_write_out(mrkb);
                break;

        case RD_KAFKA_MOCK_CMD_BROKER_SET_RACK:
                mrkb = rd_kafka_mock_broker_find(mcluster,
                                                 rko->rko_u.mock.broker_id);
                if (!mrkb)
                        return RD_KAFKA_RESP_ERR_BROKER_NOT_AVAILABLE;

                if (mrkb->rack)
                        rd_free(mrkb->rack);

                if (rko->rko_u.mock.name)
                        mrkb->rack = rd_strdup(rko->rko_u.mock.name);
                else
                        mrkb->rack = NULL;
                break;

        case RD_KAFKA_MOCK_CMD_COORD_SET:
                if (!rd_kafka_mock_coord_set(mcluster,
                                             rko->rko_u.mock.name,
                                             rko->rko_u.mock.str,
                                             rko->rko_u.mock.broker_id))
                        return RD_KAFKA_RESP_ERR__INVALID_ARG;
                break;

        case RD_KAFKA_MOCK_CMD_APIVERSION_SET:
                if (rko->rko_u.mock.partition < 0 ||
                    rko->rko_u.mock.partition >= RD_KAFKAP__NUM)
                        return RD_KAFKA_RESP_ERR__INVALID_ARG;

                mcluster->api_handlers[(int)rko->rko_u.mock.partition].
                        MinVersion = (int16_t)rko->rko_u.mock.lo;
                mcluster->api_handlers[(int)rko->rko_u.mock.partition].
                        MaxVersion = (int16_t)rko->rko_u.mock.hi;
                break;

        default:
                rd_assert(!*"unknown mock cmd");
                break;
        }

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


static rd_kafka_op_res_t
rd_kafka_mock_cluster_op_serve (rd_kafka_t *rk, rd_kafka_q_t *rkq,
                                rd_kafka_op_t *rko,
                                rd_kafka_q_cb_type_t cb_type, void *opaque) {
        rd_kafka_mock_cluster_t *mcluster = opaque;
        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;

        switch ((int)rko->rko_type)
        {
        case RD_KAFKA_OP_TERMINATE:
                mcluster->run = rd_false;
                break;

        case RD_KAFKA_OP_MOCK:
                err = rd_kafka_mock_cluster_cmd(mcluster, rko);
                break;

        default:
                rd_assert(!"*unhandled op");
                break;
        }

        rd_kafka_op_reply(rko, err);

        return RD_KAFKA_OP_RES_HANDLED;
}


/**
 * @brief Destroy cluster (internal)
 */
static void
rd_kafka_mock_cluster_destroy0 (rd_kafka_mock_cluster_t *mcluster) {
        rd_kafka_mock_topic_t *mtopic;
        rd_kafka_mock_broker_t *mrkb;
        rd_kafka_mock_cgrp_t *mcgrp;
        rd_kafka_mock_coord_t *mcoord;
        rd_kafka_mock_error_stack_t *errstack;
        thrd_t dummy_rkb_thread;
        int ret;

        while ((mtopic = TAILQ_FIRST(&mcluster->topics)))
                rd_kafka_mock_topic_destroy(mtopic);

        while ((mrkb = TAILQ_FIRST(&mcluster->brokers)))
                rd_kafka_mock_broker_destroy(mrkb);

        while ((mcgrp = TAILQ_FIRST(&mcluster->cgrps)))
                rd_kafka_mock_cgrp_destroy(mcgrp);

        while ((mcoord = TAILQ_FIRST(&mcluster->coords)))
                rd_kafka_mock_coord_destroy(mcluster, mcoord);

        while ((errstack = TAILQ_FIRST(&mcluster->errstacks))) {
                TAILQ_REMOVE(&mcluster->errstacks, errstack, link);
                rd_kafka_mock_error_stack_destroy(errstack);
        }

        /*
         * Destroy dummy broker
         */
        rd_kafka_q_enq(mcluster->dummy_rkb->rkb_ops,
                       rd_kafka_op_new(RD_KAFKA_OP_TERMINATE));

        dummy_rkb_thread = mcluster->dummy_rkb->rkb_thread;

        rd_kafka_broker_destroy(mcluster->dummy_rkb);

        if (thrd_join(dummy_rkb_thread, &ret) != thrd_success)
                rd_assert(!*"failed to join mock dummy broker thread");


        rd_kafka_q_destroy_owner(mcluster->ops);

        rd_kafka_timers_destroy(&mcluster->timers);

        if (mcluster->fd_size > 0) {
                rd_free(mcluster->fds);
                rd_free(mcluster->handlers);
        }

        mtx_destroy(&mcluster->lock);

        rd_free(mcluster->bootstraps);

        rd_close(mcluster->wakeup_fds[0]);
        rd_close(mcluster->wakeup_fds[1]);
}



void rd_kafka_mock_cluster_destroy (rd_kafka_mock_cluster_t *mcluster) {
        int res;
        rd_kafka_op_t *rko;

        rd_kafka_dbg(mcluster->rk, MOCK, "MOCK", "Destroying cluster");

        rd_assert(rd_atomic32_get(&mcluster->rk->rk_mock.cluster_cnt) > 0);
        rd_atomic32_sub(&mcluster->rk->rk_mock.cluster_cnt, 1);

        rko = rd_kafka_op_req2(mcluster->ops, RD_KAFKA_OP_TERMINATE);

        if (rko)
                rd_kafka_op_destroy(rko);

        if (thrd_join(mcluster->thread, &res) != thrd_success)
                rd_assert(!*"failed to join mock thread");

        rd_free(mcluster);
}



rd_kafka_mock_cluster_t *rd_kafka_mock_cluster_new (rd_kafka_t *rk,
                                                    int broker_cnt) {
        rd_kafka_mock_cluster_t *mcluster;
        rd_kafka_mock_broker_t *mrkb;
        int i, r;
        size_t bootstraps_len = 0;
        size_t of;

        mcluster = rd_calloc(1, sizeof(*mcluster));
        mcluster->rk = rk;

        mcluster->dummy_rkb = rd_kafka_broker_add(rk, RD_KAFKA_INTERNAL,
                                                  RD_KAFKA_PROTO_PLAINTEXT,
                                                  "mock", 0,
                                                  RD_KAFKA_NODEID_UA);
        rd_snprintf(mcluster->id, sizeof(mcluster->id),
                    "mockCluster%lx", (intptr_t)rk ^ (intptr_t)mcluster);

        TAILQ_INIT(&mcluster->brokers);

        for (i = 1 ; i <= broker_cnt ; i++) {
                if (!(mrkb = rd_kafka_mock_broker_new(mcluster, i))) {
                        rd_kafka_mock_cluster_destroy(mcluster);
                        return NULL;
                }

                /* advertised listener + ":port" + "," */
                bootstraps_len += strlen(mrkb->advertised_listener) + 6 + 1;
        }

        mtx_init(&mcluster->lock, mtx_plain);

        TAILQ_INIT(&mcluster->topics);
        mcluster->defaults.partition_cnt = 4;
        mcluster->defaults.replication_factor = RD_MIN(3, broker_cnt);

        TAILQ_INIT(&mcluster->cgrps);

        TAILQ_INIT(&mcluster->coords);

        TAILQ_INIT(&mcluster->errstacks);

        memcpy(mcluster->api_handlers, rd_kafka_mock_api_handlers,
               sizeof(mcluster->api_handlers));

        /* Use an op queue for controlling the cluster in
         * a thread-safe manner without locking. */
        mcluster->ops = rd_kafka_q_new(rk);
        mcluster->ops->rkq_serve = rd_kafka_mock_cluster_op_serve;
        mcluster->ops->rkq_opaque = mcluster;

        rd_kafka_timers_init(&mcluster->timers, rk, mcluster->ops);

        if ((r = rd_pipe_nonblocking(mcluster->wakeup_fds)) == -1) {
                rd_kafka_log(rk, LOG_ERR, "MOCK",
                             "Failed to setup mock cluster wake-up fds: %s",
                             rd_socket_strerror(r));
        } else {
                const char onebyte = 1;
                rd_kafka_q_io_event_enable(mcluster->ops,
                                           mcluster->wakeup_fds[1],
                                           &onebyte, sizeof(onebyte));
        }


        if (thrd_create(&mcluster->thread,
                        rd_kafka_mock_cluster_thread_main, mcluster) !=
            thrd_success) {
                rd_kafka_log(rk, LOG_CRIT, "MOCK",
                             "Failed to create mock cluster thread: %s",
                             rd_strerror(errno));
                rd_kafka_mock_cluster_destroy(mcluster);
                return NULL;
        }


        /* Construct bootstrap.servers list */
        mcluster->bootstraps = rd_malloc(bootstraps_len + 1);
        of = 0;
        TAILQ_FOREACH(mrkb, &mcluster->brokers, link) {
                r = rd_snprintf(&mcluster->bootstraps[of],
                                bootstraps_len - of,
                                "%s%s:%d",
                                of > 0 ? "," : "",
                                mrkb->advertised_listener, mrkb->port);
                of += r;
                rd_assert(of < bootstraps_len);
        }
        mcluster->bootstraps[of] = '\0';

        rd_kafka_dbg(rk, MOCK, "MOCK", "Mock cluster %s bootstrap.servers=%s",
                     mcluster->id, mcluster->bootstraps);

        rd_atomic32_add(&rk->rk_mock.cluster_cnt, 1);

        return mcluster;
}


rd_kafka_t *
rd_kafka_mock_cluster_handle (const rd_kafka_mock_cluster_t *mcluster) {
        return (rd_kafka_t *)mcluster->rk;
}

rd_kafka_mock_cluster_t *
rd_kafka_handle_mock_cluster (const rd_kafka_t *rk) {
        return (rd_kafka_mock_cluster_t *)rk->rk_mock.cluster;
}


const char *
rd_kafka_mock_cluster_bootstraps (const rd_kafka_mock_cluster_t *mcluster) {
        return mcluster->bootstraps;
}
