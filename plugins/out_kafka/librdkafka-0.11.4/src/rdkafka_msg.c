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
#include "rdkafka_interceptor.h"
#include "rdkafka_header.h"
#include "rdcrc32.h"
#include "rdmurmur2.h"
#include "rdrand.h"
#include "rdtime.h"
#include "rdsysqueue.h"
#include "rdunittest.h"

#include <stdarg.h>

void rd_kafka_msg_destroy (rd_kafka_t *rk, rd_kafka_msg_t *rkm) {

	if (rkm->rkm_flags & RD_KAFKA_MSG_F_ACCOUNT) {
		rd_dassert(rk || rkm->rkm_rkmessage.rkt);
		rd_kafka_curr_msgs_sub(
			rk ? rk :
			rd_kafka_topic_a2i(rkm->rkm_rkmessage.rkt)->rkt_rk,
			1, rkm->rkm_len);
	}

        if (rkm->rkm_headers)
                rd_kafka_headers_destroy(rkm->rkm_headers);

	if (likely(rkm->rkm_rkmessage.rkt != NULL))
		rd_kafka_topic_destroy0(
                        rd_kafka_topic_a2s(rkm->rkm_rkmessage.rkt));

	if (rkm->rkm_flags & RD_KAFKA_MSG_F_FREE && rkm->rkm_payload)
		rd_free(rkm->rkm_payload);

	if (rkm->rkm_flags & RD_KAFKA_MSG_F_FREE_RKM)
		rd_free(rkm);
}



/**
 * @brief Create a new Producer message, copying the payload as
 *        indicated by msgflags.
 *
 * @returns the new message
 */
static
rd_kafka_msg_t *rd_kafka_msg_new00 (rd_kafka_itopic_t *rkt,
				    int32_t partition,
				    int msgflags,
				    char *payload, size_t len,
				    const void *key, size_t keylen,
				    void *msg_opaque) {
	rd_kafka_msg_t *rkm;
	size_t mlen = sizeof(*rkm);
	char *p;

	/* If we are to make a copy of the payload, allocate space for it too */
	if (msgflags & RD_KAFKA_MSG_F_COPY) {
		msgflags &= ~RD_KAFKA_MSG_F_FREE;
		mlen += len;
	}

	mlen += keylen;

	/* Note: using rd_malloc here, not rd_calloc, so make sure all fields
	 *       are properly set up. */
	rkm                 = rd_malloc(mlen);
	rkm->rkm_err        = 0;
	rkm->rkm_flags      = (RD_KAFKA_MSG_F_PRODUCER |
                               RD_KAFKA_MSG_F_FREE_RKM | msgflags);
	rkm->rkm_len        = len;
	rkm->rkm_opaque     = msg_opaque;
	rkm->rkm_rkmessage.rkt = rd_kafka_topic_keep_a(rkt);

	rkm->rkm_partition  = partition;
        rkm->rkm_offset     = RD_KAFKA_OFFSET_INVALID;
	rkm->rkm_timestamp  = 0;
	rkm->rkm_tstype     = RD_KAFKA_TIMESTAMP_NOT_AVAILABLE;
        rkm->rkm_headers    = NULL;

	p = (char *)(rkm+1);

	if (payload && msgflags & RD_KAFKA_MSG_F_COPY) {
		/* Copy payload to space following the ..msg_t */
		rkm->rkm_payload = p;
		memcpy(rkm->rkm_payload, payload, len);
		p += len;

	} else {
		/* Just point to the provided payload. */
		rkm->rkm_payload = payload;
	}

	if (key) {
		rkm->rkm_key     = p;
		rkm->rkm_key_len = keylen;
		memcpy(rkm->rkm_key, key, keylen);
	} else {
		rkm->rkm_key = NULL;
		rkm->rkm_key_len = 0;
	}


        return rkm;
}




/**
 * @brief Create a new Producer message.
 *
 * @remark Must only be used by producer code.
 *
 * Returns 0 on success or -1 on error.
 * Both errno and 'errp' are set appropriately.
 */
static rd_kafka_msg_t *rd_kafka_msg_new0 (rd_kafka_itopic_t *rkt,
                                          int32_t force_partition,
                                          int msgflags,
                                          char *payload, size_t len,
                                          const void *key, size_t keylen,
                                          void *msg_opaque,
                                          rd_kafka_resp_err_t *errp,
                                          int *errnop,
                                          rd_kafka_headers_t *hdrs,
                                          int64_t timestamp,
                                          rd_ts_t now) {
	rd_kafka_msg_t *rkm;
        size_t hdrs_size = 0;

	if (unlikely(!payload))
		len = 0;
	if (!key)
		keylen = 0;
        if (hdrs)
                hdrs_size = rd_kafka_headers_serialized_size(hdrs);

	if (unlikely(len + keylen + hdrs_size >
		     (size_t)rkt->rkt_rk->rk_conf.max_msg_size ||
		     keylen > INT32_MAX)) {
		*errp = RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE;
		if (errnop)
			*errnop = EMSGSIZE;
		return NULL;
	}

        if (msgflags & RD_KAFKA_MSG_F_BLOCK)
                *errp = rd_kafka_curr_msgs_add(
                        rkt->rkt_rk, 1, len, 1/*block*/,
                        (msgflags & RD_KAFKA_MSG_F_RKT_RDLOCKED) ?
                        &rkt->rkt_lock : NULL);
        else
                *errp = rd_kafka_curr_msgs_add(rkt->rkt_rk, 1, len, 0, NULL);

        if (unlikely(*errp)) {
		if (errnop)
			*errnop = ENOBUFS;
		return NULL;
	}


	rkm = rd_kafka_msg_new00(rkt, force_partition,
				 msgflags|RD_KAFKA_MSG_F_ACCOUNT /* curr_msgs_add() */,
				 payload, len, key, keylen, msg_opaque);

        memset(&rkm->rkm_u.producer, 0, sizeof(rkm->rkm_u.producer));

        if (timestamp)
                rkm->rkm_timestamp  = timestamp;
        else
                rkm->rkm_timestamp = rd_uclock()/1000;
        rkm->rkm_tstype     = RD_KAFKA_TIMESTAMP_CREATE_TIME;

        if (hdrs) {
                rd_dassert(!rkm->rkm_headers);
                rkm->rkm_headers = hdrs;
        }

        rkm->rkm_ts_enq = now;

	if (rkt->rkt_conf.message_timeout_ms == 0) {
		rkm->rkm_ts_timeout = INT64_MAX;
	} else {
		rkm->rkm_ts_timeout = now +
			rkt->rkt_conf.message_timeout_ms * 1000;
	}

        /* Call interceptor chain for on_send */
        rd_kafka_interceptors_on_send(rkt->rkt_rk, &rkm->rkm_rkmessage);

        return rkm;
}


/**
 * @brief Produce: creates a new message, runs the partitioner and enqueues
 *        into on the selected partition.
 *
 * @returns 0 on success or -1 on error.
 *
 * If the function returns -1 and RD_KAFKA_MSG_F_FREE was specified, then
 * the memory associated with the payload is still the caller's
 * responsibility.
 *
 * @locks none
 */
int rd_kafka_msg_new (rd_kafka_itopic_t *rkt, int32_t force_partition,
		      int msgflags,
		      char *payload, size_t len,
		      const void *key, size_t keylen,
		      void *msg_opaque) {
	rd_kafka_msg_t *rkm;
	rd_kafka_resp_err_t err;
	int errnox;

        /* Create message */
        rkm = rd_kafka_msg_new0(rkt, force_partition, msgflags,
                                payload, len, key, keylen, msg_opaque,
                                &err, &errnox, NULL, 0, rd_clock());
        if (unlikely(!rkm)) {
                /* errno is already set by msg_new() */
		rd_kafka_set_last_error(err, errnox);
                return -1;
        }


        /* Partition the message */
	err = rd_kafka_msg_partitioner(rkt, rkm, 1);
	if (likely(!err)) {
		rd_kafka_set_last_error(0, 0);
		return 0;
	}

        /* Interceptor: unroll failing messages by triggering on_ack.. */
        rkm->rkm_err = err;
        rd_kafka_interceptors_on_acknowledgement(rkt->rkt_rk,
                                                 &rkm->rkm_rkmessage);

	/* Handle partitioner failures: it only fails when the application
	 * attempts to force a destination partition that does not exist
	 * in the cluster.  Note we must clear the RD_KAFKA_MSG_F_FREE
	 * flag since our contract says we don't free the payload on
	 * failure. */

	rkm->rkm_flags &= ~RD_KAFKA_MSG_F_FREE;
	rd_kafka_msg_destroy(rkt->rkt_rk, rkm);

	/* Translate error codes to errnos. */
	if (err == RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION)
		rd_kafka_set_last_error(err, ESRCH);
	else if (err == RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC)
		rd_kafka_set_last_error(err, ENOENT);
	else
		rd_kafka_set_last_error(err, EINVAL); /* NOTREACHED */

	return -1;
}


rd_kafka_resp_err_t rd_kafka_producev (rd_kafka_t *rk, ...) {
        va_list ap;
        rd_kafka_msg_t s_rkm = {
                /* Message defaults */
                .rkm_partition = RD_KAFKA_PARTITION_UA,
                .rkm_timestamp = 0, /* current time */
        };
        rd_kafka_msg_t *rkm = &s_rkm;
        rd_kafka_vtype_t vtype;
        rd_kafka_topic_t *app_rkt;
        shptr_rd_kafka_itopic_t *s_rkt = NULL;
        rd_kafka_itopic_t *rkt;
        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;
        rd_kafka_headers_t *hdrs = NULL;
        rd_kafka_headers_t *app_hdrs = NULL; /* App-provided headers list */

        va_start(ap, rk);
        while (!err &&
               (vtype = va_arg(ap, rd_kafka_vtype_t)) != RD_KAFKA_VTYPE_END) {
                switch (vtype)
                {
                case RD_KAFKA_VTYPE_TOPIC:
                        s_rkt = rd_kafka_topic_new0(rk,
                                                    va_arg(ap, const char *),
                                                    NULL, NULL, 1);
                        break;

                case RD_KAFKA_VTYPE_RKT:
                        app_rkt = va_arg(ap, rd_kafka_topic_t *);
                        s_rkt = rd_kafka_topic_keep(
                                rd_kafka_topic_a2i(app_rkt));
                        break;

                case RD_KAFKA_VTYPE_PARTITION:
                        rkm->rkm_partition = va_arg(ap, int32_t);
                        break;

                case RD_KAFKA_VTYPE_VALUE:
                        rkm->rkm_payload = va_arg(ap, void *);
                        rkm->rkm_len = va_arg(ap, size_t);
                        break;

                case RD_KAFKA_VTYPE_KEY:
                        rkm->rkm_key = va_arg(ap, void *);
                        rkm->rkm_key_len = va_arg(ap, size_t);
                        break;

                case RD_KAFKA_VTYPE_OPAQUE:
                        rkm->rkm_opaque = va_arg(ap, void *);
                        break;

                case RD_KAFKA_VTYPE_MSGFLAGS:
                        rkm->rkm_flags = va_arg(ap, int);
                        break;

                case RD_KAFKA_VTYPE_TIMESTAMP:
                        rkm->rkm_timestamp = va_arg(ap, int64_t);
                        break;

                case RD_KAFKA_VTYPE_HEADER:
                {
                        const char *name;
                        const void *value;
                        ssize_t size;

                        if (unlikely(app_hdrs != NULL)) {
                                err = RD_KAFKA_RESP_ERR__CONFLICT;
                                break;
                        }

                        if (unlikely(!hdrs))
                                hdrs = rd_kafka_headers_new(8);

                        name = va_arg(ap, const char *);
                        value = va_arg(ap, const void *);
                        size = va_arg(ap, ssize_t);

                        err = rd_kafka_header_add(hdrs, name, -1, value, size);
                }
                break;

                case RD_KAFKA_VTYPE_HEADERS:
                        if (unlikely(hdrs != NULL)) {
                                err = RD_KAFKA_RESP_ERR__CONFLICT;
                                break;
                        }
                        app_hdrs = va_arg(ap, rd_kafka_headers_t *);
                        break;

                default:
                        err = RD_KAFKA_RESP_ERR__INVALID_ARG;
                        break;
                }
        }

        va_end(ap);

        if (unlikely(!s_rkt))
                return RD_KAFKA_RESP_ERR__INVALID_ARG;

        rkt = rd_kafka_topic_s2i(s_rkt);

        if (likely(!err))
                rkm = rd_kafka_msg_new0(rkt,
                                        rkm->rkm_partition,
                                        rkm->rkm_flags,
                                        rkm->rkm_payload, rkm->rkm_len,
                                        rkm->rkm_key, rkm->rkm_key_len,
                                        rkm->rkm_opaque,
                                        &err, NULL,
                                        app_hdrs ? app_hdrs : hdrs,
                                        rkm->rkm_timestamp,
                                        rd_clock());

        if (unlikely(err)) {
                rd_kafka_topic_destroy0(s_rkt);
                if (hdrs)
                        rd_kafka_headers_destroy(hdrs);
                return err;
        }

        /* Partition the message */
        err = rd_kafka_msg_partitioner(rkt, rkm, 1);
        if (unlikely(err)) {
                /* Handle partitioner failures: it only fails when
                 * the application attempts to force a destination
                 * partition that does not exist in the cluster. */

                /* Interceptors: Unroll on_send by on_ack.. */
                rkm->rkm_err = err;
                rd_kafka_interceptors_on_acknowledgement(rk,
                                                         &rkm->rkm_rkmessage);

                /* Note we must clear the RD_KAFKA_MSG_F_FREE
                 * flag since our contract says we don't free the payload on
                 * failure. */
                rkm->rkm_flags &= ~RD_KAFKA_MSG_F_FREE;

                /* Deassociate application owned headers from message
                 * since headers remain in application ownership
                 * when producev() fails */
                if (app_hdrs && app_hdrs == rkm->rkm_headers)
                        rkm->rkm_headers = NULL;

                rd_kafka_msg_destroy(rk, rkm);
        }

        rd_kafka_topic_destroy0(s_rkt);

        return err;
}

/**
 * Produce a batch of messages.
 * Returns the number of messages succesfully queued for producing.
 * Each message's .err will be set accordingly.
 */
int rd_kafka_produce_batch (rd_kafka_topic_t *app_rkt, int32_t partition,
                            int msgflags,
                            rd_kafka_message_t *rkmessages, int message_cnt) {
        rd_kafka_msgq_t tmpq = RD_KAFKA_MSGQ_INITIALIZER(tmpq);
        int i;
	int64_t utc_now = rd_uclock() / 1000;
        rd_ts_t now = rd_clock();
        int good = 0;
        int multiple_partitions = (partition == RD_KAFKA_PARTITION_UA ||
                                   (msgflags & RD_KAFKA_MSG_F_PARTITION));
        rd_kafka_resp_err_t all_err = 0;
        rd_kafka_itopic_t *rkt = rd_kafka_topic_a2i(app_rkt);
        rd_kafka_toppar_t *rktp = NULL;
        shptr_rd_kafka_toppar_t *s_rktp = NULL;

        /* For multiple partitions; hold lock for entire run,
         * for one partition: only acquire for now. */
        rd_kafka_topic_rdlock(rkt);
        if (!multiple_partitions) {
                s_rktp = rd_kafka_toppar_get_avail(rkt, partition,
                                                   1/*ua on miss*/, &all_err);
                rktp = rd_kafka_toppar_s2i(s_rktp);
                rd_kafka_topic_rdunlock(rkt);
        } else {
                /* Indicate to lower-level msg_new..() that rkt is locked
                 * so that they may unlock it momentarily if blocking. */
                msgflags |= RD_KAFKA_MSG_F_RKT_RDLOCKED;
        }

        for (i = 0 ; i < message_cnt ; i++) {
                rd_kafka_msg_t *rkm;

                /* Propagate error for all messages. */
                if (unlikely(all_err)) {
                        rkmessages[i].err = all_err;
                        continue;
                }

                /* Create message */
                rkm = rd_kafka_msg_new0(rkt,
                                        (msgflags & RD_KAFKA_MSG_F_PARTITION) ?
                                        rkmessages[i].partition : partition,
                                        msgflags,
                                        rkmessages[i].payload,
                                        rkmessages[i].len,
                                        rkmessages[i].key,
                                        rkmessages[i].key_len,
                                        rkmessages[i]._private,
                                        &rkmessages[i].err, NULL,
					NULL, utc_now, now);
                if (unlikely(!rkm)) {
			if (rkmessages[i].err == RD_KAFKA_RESP_ERR__QUEUE_FULL)
				all_err = rkmessages[i].err;
                        continue;
		}

                /* Three cases here:
                 *  partition==UA:            run the partitioner (slow)
                 *  RD_KAFKA_MSG_F_PARTITION: produce message to specified
                 *                            partition
                 *  fixed partition:          simply concatenate the queue
                 *                            to partit */
                if (multiple_partitions) {
                        if (rkm->rkm_partition == RD_KAFKA_PARTITION_UA) {
                                /* Partition the message */
                                rkmessages[i].err =
                                        rd_kafka_msg_partitioner(
                                                rkt, rkm, 0/*already locked*/);
                        } else {
                                if (s_rktp == NULL ||
                                    rkm->rkm_partition !=
                                    rd_kafka_toppar_s2i(s_rktp)->
                                    rktp_partition) {
                                        if (s_rktp != NULL)
                                                rd_kafka_toppar_destroy(s_rktp);
                                        s_rktp = rd_kafka_toppar_get_avail(
                                                rkt, rkm->rkm_partition,
                                                1/*ua on miss*/, &all_err);
                                }
                                rktp = rd_kafka_toppar_s2i(s_rktp);
                                rd_kafka_toppar_enq_msg(rktp, rkm);
                        }

                        if (unlikely(rkmessages[i].err)) {
                                /* Interceptors: Unroll on_send by on_ack.. */
                                rd_kafka_interceptors_on_acknowledgement(
                                        rkt->rkt_rk, &rkmessages[i]);

                                rd_kafka_msg_destroy(rkt->rkt_rk, rkm);
                                continue;
                        }


                } else {
                        /* Single destination partition. */
                        rd_kafka_toppar_enq_msg(rktp, rkm);
                }

                rkmessages[i].err = RD_KAFKA_RESP_ERR_NO_ERROR;
                good++;
        }

        if (multiple_partitions)
                rd_kafka_topic_rdunlock(rkt);
        if (s_rktp != NULL)
                rd_kafka_toppar_destroy(s_rktp);

        return good;
}

/**
 * Scan 'rkmq' for messages that have timed out and remove them from
 * 'rkmq' and add to 'timedout'.
 *
 * Returns the number of messages timed out.
 */
int rd_kafka_msgq_age_scan (rd_kafka_msgq_t *rkmq,
			    rd_kafka_msgq_t *timedout,
			    rd_ts_t now) {
	rd_kafka_msg_t *rkm, *tmp;
	int cnt = timedout->rkmq_msg_cnt;

	/* Assume messages are added in time sequencial order */
	TAILQ_FOREACH_SAFE(rkm, &rkmq->rkmq_msgs, rkm_link, tmp) {
                /* FIXME: this is no longer true */
		if (likely(rkm->rkm_ts_timeout > now))
			break;

		rd_kafka_msgq_deq(rkmq, rkm, 1);
		rd_kafka_msgq_enq(timedout, rkm);
	}

	return timedout->rkmq_msg_cnt - cnt;
}


static RD_INLINE int
rd_kafka_msgq_enq_sorted0 (rd_kafka_msgq_t *rkmq,
                           rd_kafka_msg_t *rkm,
                           int (*order_cmp) (const void *, const void *)) {
        TAILQ_INSERT_SORTED(&rkmq->rkmq_msgs, rkm, rd_kafka_msg_t *,
                            rkm_link, order_cmp);
        rkmq->rkmq_msg_bytes += rkm->rkm_len+rkm->rkm_key_len;
        return ++rkmq->rkmq_msg_cnt;
}

int rd_kafka_msgq_enq_sorted (const rd_kafka_itopic_t *rkt,
                              rd_kafka_msgq_t *rkmq,
                              rd_kafka_msg_t *rkm) {
        rd_dassert(rkm->rkm_u.producer.msgseq != 0);
        return rd_kafka_msgq_enq_sorted0(rkmq, rkm,
                                         rkt->rkt_conf.msg_order_cmp);
}

/**
 * @brief Find the insert position (i.e., the previous element)
 *        for message \p rkm.
 *
 * @returns the insert position element, or NULL if \p rkm should be
 *          added at head of queue.
 */
rd_kafka_msg_t *rd_kafka_msgq_find_pos (const rd_kafka_msgq_t *rkmq,
                                        const rd_kafka_msg_t *rkm,
                                        int (*cmp) (const void *,
                                                    const void *)) {
        const rd_kafka_msg_t *curr, *last = NULL;

        TAILQ_FOREACH(curr, &rkmq->rkmq_msgs, rkm_link) {
                if (cmp(rkm, curr) < 0)
                        return (rd_kafka_msg_t *)last;
                last = curr;
        }

        return (rd_kafka_msg_t *)last;
}



int32_t rd_kafka_msg_partitioner_random (const rd_kafka_topic_t *rkt,
					 const void *key, size_t keylen,
					 int32_t partition_cnt,
					 void *rkt_opaque,
					 void *msg_opaque) {
	int32_t p = rd_jitter(0, partition_cnt-1);
	if (unlikely(!rd_kafka_topic_partition_available(rkt, p)))
		return rd_jitter(0, partition_cnt-1);
	else
		return p;
}

int32_t rd_kafka_msg_partitioner_consistent (const rd_kafka_topic_t *rkt,
                                             const void *key, size_t keylen,
                                             int32_t partition_cnt,
                                             void *rkt_opaque,
                                             void *msg_opaque) {
    return rd_crc32(key, keylen) % partition_cnt;
}

int32_t rd_kafka_msg_partitioner_consistent_random (const rd_kafka_topic_t *rkt,
                                             const void *key, size_t keylen,
                                             int32_t partition_cnt,
                                             void *rkt_opaque,
                                             void *msg_opaque) {
    if (keylen == 0)
      return rd_kafka_msg_partitioner_random(rkt,
                                             key,
                                             keylen,
                                             partition_cnt,
                                             rkt_opaque,
                                             msg_opaque);
    else
      return rd_kafka_msg_partitioner_consistent(rkt,
                                                 key,
                                                 keylen,
                                                 partition_cnt,
                                                 rkt_opaque,
                                                 msg_opaque);
}

int32_t
rd_kafka_msg_partitioner_murmur2 (const rd_kafka_topic_t *rkt,
                                  const void *key, size_t keylen,
                                  int32_t partition_cnt,
                                  void *rkt_opaque,
                                  void *msg_opaque) {
        return rd_murmur2(key, keylen) % partition_cnt;
}

int32_t rd_kafka_msg_partitioner_murmur2_random (const rd_kafka_topic_t *rkt,
                                                 const void *key, size_t keylen,
                                                 int32_t partition_cnt,
                                                 void *rkt_opaque,
                                                 void *msg_opaque) {
        if (!key)
                return rd_kafka_msg_partitioner_random(rkt,
                                                       key,
                                                       keylen,
                                                       partition_cnt,
                                                       rkt_opaque,
                                                       msg_opaque);
        else
                return rd_murmur2(key, keylen) % partition_cnt;
}


/**
 * Assigns a message to a topic partition using a partitioner.
 * Returns RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION or .._UNKNOWN_TOPIC if
 * partitioning failed, or 0 on success.
 */
int rd_kafka_msg_partitioner (rd_kafka_itopic_t *rkt, rd_kafka_msg_t *rkm,
			      int do_lock) {
	int32_t partition;
	rd_kafka_toppar_t *rktp_new;
        shptr_rd_kafka_toppar_t *s_rktp_new;
	rd_kafka_resp_err_t err;

	if (do_lock)
		rd_kafka_topic_rdlock(rkt);

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
                err = RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC;
		if (do_lock)
			rd_kafka_topic_rdunlock(rkt);
                return err;

        case RD_KAFKA_TOPIC_S_EXISTS:
                /* Topic exists in cluster. */

                /* Topic exists but has no partitions.
                 * This is usually an transient state following the
                 * auto-creation of a topic. */
                if (unlikely(rkt->rkt_partition_cnt == 0)) {
                        partition = RD_KAFKA_PARTITION_UA;
                        break;
                }

                /* Partition not assigned, run partitioner. */
                if (rkm->rkm_partition == RD_KAFKA_PARTITION_UA) {
                        rd_kafka_topic_t *app_rkt;
                        /* Provide a temporary app_rkt instance to protect
                         * from the case where the application decided to
                         * destroy its topic object prior to delivery completion
                         * (issue #502). */
                        app_rkt = rd_kafka_topic_keep_a(rkt);
                        partition = rkt->rkt_conf.
                                partitioner(app_rkt,
                                            rkm->rkm_key,
					    rkm->rkm_key_len,
                                            rkt->rkt_partition_cnt,
                                            rkt->rkt_conf.opaque,
                                            rkm->rkm_opaque);
                        rd_kafka_topic_destroy0(
                                rd_kafka_topic_a2s(app_rkt));
                } else
                        partition = rkm->rkm_partition;

                /* Check that partition exists. */
                if (partition >= rkt->rkt_partition_cnt) {
                        err = RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;
                        if (do_lock)
                                rd_kafka_topic_rdunlock(rkt);
                        return err;
                }
                break;

        default:
                rd_kafka_assert(rkt->rkt_rk, !*"NOTREACHED");
                break;
        }

	/* Get new partition */
	s_rktp_new = rd_kafka_toppar_get(rkt, partition, 0);

	if (unlikely(!s_rktp_new)) {
		/* Unknown topic or partition */
		if (rkt->rkt_state == RD_KAFKA_TOPIC_S_NOTEXISTS)
			err = RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC;
		else
			err = RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;

		if (do_lock)
			rd_kafka_topic_rdunlock(rkt);

		return  err;
	}

        rktp_new = rd_kafka_toppar_s2i(s_rktp_new);
        rd_atomic64_add(&rktp_new->rktp_c.msgs, 1);

        /* Update message partition */
        if (rkm->rkm_partition == RD_KAFKA_PARTITION_UA)
                rkm->rkm_partition = partition;

	/* Partition is available: enqueue msg on partition's queue */
	rd_kafka_toppar_enq_msg(rktp_new, rkm);
	if (do_lock)
		rd_kafka_topic_rdunlock(rkt);
	rd_kafka_toppar_destroy(s_rktp_new); /* from _get() */
	return 0;
}




/**
 * @name Public message type (rd_kafka_message_t)
 */
void rd_kafka_message_destroy (rd_kafka_message_t *rkmessage) {
        rd_kafka_op_t *rko;

        if (likely((rko = (rd_kafka_op_t *)rkmessage->_private) != NULL))
                rd_kafka_op_destroy(rko);
        else {
                rd_kafka_msg_t *rkm = rd_kafka_message2msg(rkmessage);
                rd_kafka_msg_destroy(NULL, rkm);
        }
}


rd_kafka_message_t *rd_kafka_message_new (void) {
        rd_kafka_msg_t *rkm = rd_calloc(1, sizeof(*rkm));
        return (rd_kafka_message_t *)rkm;
}


/**
 * @brief Set up a rkmessage from an rko for passing to the application.
 * @remark Will trigger on_consume() interceptors if any.
 */
static rd_kafka_message_t *
rd_kafka_message_setup (rd_kafka_op_t *rko, rd_kafka_message_t *rkmessage) {
        rd_kafka_itopic_t *rkt;
        rd_kafka_toppar_t *rktp = NULL;

        if (rko->rko_type == RD_KAFKA_OP_DR) {
                rkt = rd_kafka_topic_s2i(rko->rko_u.dr.s_rkt);
        } else {
                if (rko->rko_rktp) {
                        rktp = rd_kafka_toppar_s2i(rko->rko_rktp);
                        rkt = rktp->rktp_rkt;
                } else
                        rkt = NULL;

                rkmessage->_private = rko;
        }


        if (!rkmessage->rkt && rkt)
                rkmessage->rkt = rd_kafka_topic_keep_a(rkt);

        if (rktp)
                rkmessage->partition = rktp->rktp_partition;

        if (!rkmessage->err)
                rkmessage->err = rko->rko_err;

        /* Call on_consume interceptors */
        switch (rko->rko_type)
        {
        case RD_KAFKA_OP_FETCH:
                if (!rkmessage->err && rkt)
                        rd_kafka_interceptors_on_consume(rkt->rkt_rk,
                                                         rkmessage);
                break;

        default:
                break;
        }

        return rkmessage;
}



/**
 * @brief Get rkmessage from rkm (for EVENT_DR)
 * @remark Must only be called just prior to passing a dr to the application.
 */
rd_kafka_message_t *rd_kafka_message_get_from_rkm (rd_kafka_op_t *rko,
                                                   rd_kafka_msg_t *rkm) {
        return rd_kafka_message_setup(rko, &rkm->rkm_rkmessage);
}

/**
 * @brief Convert rko to rkmessage
 * @remark Must only be called just prior to passing a consumed message
 *         or event to the application.
 * @remark Will trigger on_consume() interceptors, if any.
 * @returns a rkmessage (bound to the rko).
 */
rd_kafka_message_t *rd_kafka_message_get (rd_kafka_op_t *rko) {
        rd_kafka_message_t *rkmessage;

        if (!rko)
                return rd_kafka_message_new(); /* empty */

        switch (rko->rko_type)
        {
        case RD_KAFKA_OP_FETCH:
                /* Use embedded rkmessage */
                rkmessage = &rko->rko_u.fetch.rkm.rkm_rkmessage;
                break;

        case RD_KAFKA_OP_ERR:
        case RD_KAFKA_OP_CONSUMER_ERR:
                rkmessage = &rko->rko_u.err.rkm.rkm_rkmessage;
                rkmessage->payload = rko->rko_u.err.errstr;
                rkmessage->offset  = rko->rko_u.err.offset;
                break;

        default:
                rd_kafka_assert(NULL, !*"unhandled optype");
                RD_NOTREACHED();
                return NULL;
        }

        return rd_kafka_message_setup(rko, rkmessage);
}


int64_t rd_kafka_message_timestamp (const rd_kafka_message_t *rkmessage,
                                    rd_kafka_timestamp_type_t *tstype) {
        rd_kafka_msg_t *rkm;

        if (rkmessage->err) {
                if (tstype)
                        *tstype = RD_KAFKA_TIMESTAMP_NOT_AVAILABLE;
                return -1;
        }

        rkm = rd_kafka_message2msg((rd_kafka_message_t *)rkmessage);

        if (tstype)
                *tstype = rkm->rkm_tstype;

        return rkm->rkm_timestamp;
}


int64_t rd_kafka_message_latency (const rd_kafka_message_t *rkmessage) {
        rd_kafka_msg_t *rkm;

        rkm = rd_kafka_message2msg((rd_kafka_message_t *)rkmessage);

        if (unlikely(!rkm->rkm_ts_enq))
                return -1;

        return rd_clock() - rkm->rkm_ts_enq;
}



/**
 * @brief Parse serialized message headers and populate
 *        rkm->rkm_headers (which must be NULL).
 */
static rd_kafka_resp_err_t rd_kafka_msg_headers_parse (rd_kafka_msg_t *rkm) {
        rd_kafka_buf_t *rkbuf;
        int64_t HeaderCount;
        const int log_decode_errors = 0;
        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR__BAD_MSG;
        int i;
        rd_kafka_headers_t *hdrs = NULL;

        rd_dassert(!rkm->rkm_headers);

        if (RD_KAFKAP_BYTES_LEN(&rkm->rkm_u.consumer.binhdrs) == 0)
                return RD_KAFKA_RESP_ERR__NOENT;

        rkbuf = rd_kafka_buf_new_shadow(rkm->rkm_u.consumer.binhdrs.data,
                                        RD_KAFKAP_BYTES_LEN(&rkm->rkm_u.
                                                            consumer.binhdrs),
                                        NULL);

        rd_kafka_buf_read_varint(rkbuf, &HeaderCount);

        if (HeaderCount <= 0) {
                rd_kafka_buf_destroy(rkbuf);
                return RD_KAFKA_RESP_ERR__NOENT;
        } else if (unlikely(HeaderCount > 100000)) {
                rd_kafka_buf_destroy(rkbuf);
                return RD_KAFKA_RESP_ERR__BAD_MSG;
        }

        hdrs = rd_kafka_headers_new((size_t)HeaderCount);

        for (i = 0 ; (int64_t)i < HeaderCount ; i++) {
                int64_t KeyLen, ValueLen;
                const char *Key, *Value;

                rd_kafka_buf_read_varint(rkbuf, &KeyLen);
                rd_kafka_buf_read_ptr(rkbuf, &Key, (size_t)KeyLen);

                rd_kafka_buf_read_varint(rkbuf, &ValueLen);
                if (unlikely(ValueLen == -1))
                        Value = NULL;
                else
                        rd_kafka_buf_read_ptr(rkbuf, &Value, (size_t)ValueLen);

                rd_kafka_header_add(hdrs, Key, (ssize_t)KeyLen,
                                    Value, (ssize_t)ValueLen);
        }

        rkm->rkm_headers = hdrs;

        rd_kafka_buf_destroy(rkbuf);
        return RD_KAFKA_RESP_ERR_NO_ERROR;

 err_parse:
        err = rkbuf->rkbuf_err;
        rd_kafka_buf_destroy(rkbuf);
        if (hdrs)
                rd_kafka_headers_destroy(hdrs);
        return err;
}




rd_kafka_resp_err_t
rd_kafka_message_headers (const rd_kafka_message_t *rkmessage,
                          rd_kafka_headers_t **hdrsp) {
        rd_kafka_msg_t *rkm;
        rd_kafka_resp_err_t err;

        rkm = rd_kafka_message2msg((rd_kafka_message_t *)rkmessage);

        if (rkm->rkm_headers) {
                *hdrsp = rkm->rkm_headers;
                return RD_KAFKA_RESP_ERR_NO_ERROR;
        }

        /* Producer (rkm_headers will be set if there were any headers) */
        if (rkm->rkm_flags & RD_KAFKA_MSG_F_PRODUCER)
                return RD_KAFKA_RESP_ERR__NOENT;

        /* Consumer */

        /* No previously parsed headers, check if the underlying
         * protocol message had headers and if so, parse them. */
        if (unlikely(!RD_KAFKAP_BYTES_LEN(&rkm->rkm_u.consumer.binhdrs)))
                return RD_KAFKA_RESP_ERR__NOENT;

        err = rd_kafka_msg_headers_parse(rkm);
        if (unlikely(err))
                return err;

        *hdrsp = rkm->rkm_headers;
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


rd_kafka_resp_err_t
rd_kafka_message_detach_headers (rd_kafka_message_t *rkmessage,
                                 rd_kafka_headers_t **hdrsp) {
        rd_kafka_msg_t *rkm;
        rd_kafka_resp_err_t err;

        err = rd_kafka_message_headers(rkmessage, hdrsp);
        if (err)
                return err;

        rkm = rd_kafka_message2msg((rd_kafka_message_t *)rkmessage);
        rkm->rkm_headers = NULL;

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


void rd_kafka_message_set_headers (rd_kafka_message_t *rkmessage,
                                   rd_kafka_headers_t *hdrs) {
        rd_kafka_msg_t *rkm;

        rkm = rd_kafka_message2msg((rd_kafka_message_t *)rkmessage);

        if (rkm->rkm_headers) {
                assert(rkm->rkm_headers != hdrs);
                rd_kafka_headers_destroy(rkm->rkm_headers);
        }

        rkm->rkm_headers = hdrs;
}



void rd_kafka_msgq_dump (FILE *fp, const char *what, rd_kafka_msgq_t *rkmq) {
        rd_kafka_msg_t *rkm;

        fprintf(fp, "%s msgq_dump (%d messages, %"PRIusz" bytes):\n", what,
                rd_kafka_msgq_len(rkmq), rd_kafka_msgq_size(rkmq));
        TAILQ_FOREACH(rkm, &rkmq->rkmq_msgs, rkm_link) {
                fprintf(fp, " [%"PRId32"]@%"PRId64
                        ": rkm msgseq %"PRIu64": \"%.*s\"\n",
                        rkm->rkm_partition, rkm->rkm_offset,
                        rkm->rkm_u.producer.msgseq,
                        (int)rkm->rkm_len, (const char *)rkm->rkm_payload);
        }
}

/**
 * @name Unit tests
 */

/**
 * @brief Unittest: message allocator
 */
static rd_kafka_msg_t *ut_rd_kafka_msg_new (void) {
        rd_kafka_msg_t *rkm;

        rkm = rd_calloc(1, sizeof(*rkm));
        rkm->rkm_flags      = RD_KAFKA_MSG_F_FREE_RKM;
        rkm->rkm_offset     = RD_KAFKA_OFFSET_INVALID;
        rkm->rkm_tstype     = RD_KAFKA_TIMESTAMP_NOT_AVAILABLE;

        return rkm;
}



/**
 * @brief Unittest: destroy all messages in queue
 */
static void ut_rd_kafka_msgq_purge (rd_kafka_msgq_t *rkmq) {
        rd_kafka_msg_t *rkm, *tmp;

        TAILQ_FOREACH_SAFE(rkm, &rkmq->rkmq_msgs, rkm_link, tmp)
                rd_kafka_msg_destroy(NULL, rkm);


        rd_kafka_msgq_init(rkmq);
}



static int ut_verify_msgq_order (const char *what,
                                 const rd_kafka_msgq_t *rkmq,
                                 int first, int last) {
        const rd_kafka_msg_t *rkm;
        uint64_t expected = first;
        int incr = first < last ? +1 : -1;
        int fails = 0;
        int cnt = 0;

        TAILQ_FOREACH(rkm, &rkmq->rkmq_msgs, rkm_link) {
                if (rkm->rkm_u.producer.msgseq != expected) {
                        RD_UT_SAY("%s: expected msgseq %"PRIu64
                                  " not %"PRIu64" at index #%d",
                                  what, expected,
                                  rkm->rkm_u.producer.msgseq, cnt);
                        fails++;
                }
                cnt++;
                expected += incr;
        }

        RD_UT_ASSERT(!fails, "See %d previous failure(s)", fails);
        return fails;
}

/**
 * @brief Verify ordering comparator for message queues.
 */
static int unittest_msgq_order (const char *what, int fifo,
                          int (*cmp) (const void *, const void *)) {
        rd_kafka_msgq_t rkmq = RD_KAFKA_MSGQ_INITIALIZER(rkmq);
        rd_kafka_msg_t *rkm;
        rd_kafka_msgq_t sendq;
        int i;

        RD_UT_SAY("%s: testing in %s mode", what, fifo? "FIFO" : "LIFO");

        for (i = 1 ; i <= 6 ; i++) {
                rkm = ut_rd_kafka_msg_new();
                rkm->rkm_u.producer.msgseq = i;
                rd_kafka_msgq_enq_sorted0(&rkmq, rkm, cmp);
        }

        if (fifo) {
                if (ut_verify_msgq_order("added", &rkmq, 1, 6))
                        return 1;
        } else {
                if (ut_verify_msgq_order("added", &rkmq, 6, 1))
                        return 1;
        }

        /* Move 3 messages to "send" queue which we then re-insert
         * in the original queue (i.e., "retry"). */
        rd_kafka_msgq_init(&sendq);
        while (rd_kafka_msgq_len(&sendq) < 3)
                rd_kafka_msgq_enq(&sendq, rd_kafka_msgq_pop(&rkmq));

        if (fifo) {
                if (ut_verify_msgq_order("send removed", &rkmq, 4, 6))
                        return 1;

                if (ut_verify_msgq_order("sendq", &sendq, 1, 3))
                        return 1;
        } else {
                if (ut_verify_msgq_order("send removed", &rkmq, 3, 1))
                        return 1;

                if (ut_verify_msgq_order("sendq", &sendq, 6, 4))
                        return 1;
        }

        /* Retry the messages, which moves them back to sendq
         * maintaining the original order */
        rd_kafka_retry_msgq(&rkmq, &sendq, 1, 1, 0, cmp);

        RD_UT_ASSERT(rd_kafka_msgq_len(&sendq) == 0,
                     "sendq FIFO should be empty, not contain %d messages",
                     rd_kafka_msgq_len(&sendq));

        if (fifo) {
                if (ut_verify_msgq_order("readded", &rkmq, 1, 6))
                        return 1;
        } else {
                if (ut_verify_msgq_order("readded", &rkmq, 6, 1))
                        return 1;
        }

        /* Move 4 first messages to to "send" queue, then
         * retry them with max_retries=1 which should now fail for
         * the 3 first messages that were already retried. */
        rd_kafka_msgq_init(&sendq);
        while (rd_kafka_msgq_len(&sendq) < 4)
                rd_kafka_msgq_enq(&sendq, rd_kafka_msgq_pop(&rkmq));

        if (fifo) {
                if (ut_verify_msgq_order("send removed #2", &rkmq, 5, 6))
                        return 1;

                if (ut_verify_msgq_order("sendq #2", &sendq, 1, 4))
                        return 1;
        } else {
                if (ut_verify_msgq_order("send removed #2", &rkmq, 2, 1))
                        return 1;

                if (ut_verify_msgq_order("sendq #2", &sendq, 6, 3))
                        return 1;
        }

        /* Retry the messages, which should now keep the 3 first messages
         * on sendq (no more retries) and just number 4 moved back. */
        rd_kafka_retry_msgq(&rkmq, &sendq, 1, 1, 0, cmp);

        if (fifo) {
                if (ut_verify_msgq_order("readded #2", &rkmq, 4, 6))
                        return 1;

                if (ut_verify_msgq_order("no more retries", &sendq, 1, 3))
                        return 1;

        } else {
                if (ut_verify_msgq_order("readded #2", &rkmq, 3, 1))
                        return 1;

                if (ut_verify_msgq_order("no more retries", &sendq, 6, 4))
                        return 1;
        }

        ut_rd_kafka_msgq_purge(&sendq);
        ut_rd_kafka_msgq_purge(&rkmq);

        return 0;

}


int unittest_msg (void) {
        int fails = 0;

        fails += unittest_msgq_order("FIFO", 1, rd_kafka_msg_cmp_msgseq);
        fails += unittest_msgq_order("LIFO", 0, rd_kafka_msg_cmp_msgseq_lifo);

        return fails;
}
