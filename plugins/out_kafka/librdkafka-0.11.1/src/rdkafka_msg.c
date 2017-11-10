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
#include "rdcrc32.h"
#include "rdrand.h"
#include "rdtime.h"

#include "rdsysqueue.h"

#include <stdarg.h>

void rd_kafka_msg_destroy (rd_kafka_t *rk, rd_kafka_msg_t *rkm) {

	if (rkm->rkm_flags & RD_KAFKA_MSG_F_ACCOUNT) {
		rd_dassert(rk || rkm->rkm_rkmessage.rkt);
		rd_kafka_curr_msgs_sub(
			rk ? rk :
			rd_kafka_topic_a2i(rkm->rkm_rkmessage.rkt)->rkt_rk,
			1, rkm->rkm_len);
	}

	if (likely(rkm->rkm_rkmessage.rkt != NULL))
		rd_kafka_topic_destroy0(
                        rd_kafka_topic_a2s(rkm->rkm_rkmessage.rkt));

	if (rkm->rkm_flags & RD_KAFKA_MSG_F_FREE && rkm->rkm_payload)
		rd_free(rkm->rkm_payload);

	if (rkm->rkm_flags & RD_KAFKA_MSG_F_FREE_RKM)
		rd_free(rkm);
}




/**
 * @brief Create a new message, copying the payload as indicated by msgflags.
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
	rkm->rkm_flags      = RD_KAFKA_MSG_F_FREE_RKM | msgflags;
	rkm->rkm_len        = len;
	rkm->rkm_opaque     = msg_opaque;
	rkm->rkm_rkmessage.rkt = rd_kafka_topic_keep_a(rkt);

	rkm->rkm_partition  = partition;
        rkm->rkm_offset     = 0;
	rkm->rkm_timestamp  = 0;
	rkm->rkm_tstype     = RD_KAFKA_TIMESTAMP_NOT_AVAILABLE;

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
 * @brief Create a new message.
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
                                          int64_t timestamp,
                                          rd_ts_t now) {
	rd_kafka_msg_t *rkm;

	if (unlikely(!payload))
		len = 0;
	if (!key)
		keylen = 0;

	if (unlikely(len + keylen >
		     (size_t)rkt->rkt_rk->rk_conf.max_msg_size ||
		     keylen > INT32_MAX)) {
		*errp = RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE;
		if (errnop)
			*errnop = EMSGSIZE;
		return NULL;
	}

	*errp = rd_kafka_curr_msgs_add(rkt->rkt_rk, 1, len,
				       msgflags & RD_KAFKA_MSG_F_BLOCK);
	if (unlikely(*errp)) {
		if (errnop)
			*errnop = ENOBUFS;
		return NULL;
	}


	rkm = rd_kafka_msg_new00(rkt, force_partition,
				 msgflags|RD_KAFKA_MSG_F_ACCOUNT /* curr_msgs_add() */,
				 payload, len, key, keylen, msg_opaque);

        if (timestamp)
                rkm->rkm_timestamp  = timestamp;
        else
                rkm->rkm_timestamp = rd_uclock()/1000;
        rkm->rkm_tstype     = RD_KAFKA_TIMESTAMP_CREATE_TIME;

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
                                &err, &errnox, 0, rd_clock());
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

        va_start(ap, rk);
        while ((vtype = va_arg(ap, rd_kafka_vtype_t)) != RD_KAFKA_VTYPE_END) {
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
                                        rkm->rkm_timestamp, rd_clock());

        if (unlikely(err))
                return err;

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
        rd_kafka_resp_err_t all_err = 0;
        rd_kafka_itopic_t *rkt = rd_kafka_topic_a2i(app_rkt);

        /* For partitioner; hold lock for entire run,
         * for one partition: only acquire when needed at the end. */
	if (partition == RD_KAFKA_PARTITION_UA)
		rd_kafka_topic_rdlock(rkt);

        for (i = 0 ; i < message_cnt ; i++) {
                rd_kafka_msg_t *rkm;

                /* Propagate error for all messages. */
                if (unlikely(all_err)) {
                        rkmessages[i].err = all_err;
                        continue;
                }

                /* Create message */
                rkm = rd_kafka_msg_new0(rkt,
                                        partition , msgflags,
                                        rkmessages[i].payload,
                                        rkmessages[i].len,
                                        rkmessages[i].key,
                                        rkmessages[i].key_len,
                                        rkmessages[i]._private,
                                        &rkmessages[i].err,
					NULL, utc_now, now);
                if (unlikely(!rkm)) {
			if (rkmessages[i].err == RD_KAFKA_RESP_ERR__QUEUE_FULL)
				all_err = rkmessages[i].err;
                        continue;
		}

                /* Two cases here:
                 *  partition==UA:     run the partitioner (slow)
                 *  fixed partition:   simply concatenate the queue to partit */
                if (partition == RD_KAFKA_PARTITION_UA) {
                        /* Partition the message */
                        rkmessages[i].err =
                                rd_kafka_msg_partitioner(rkt, rkm,
                                                         0/*already locked*/);

                        if (unlikely(rkmessages[i].err)) {
                                /* Interceptors: Unroll on_send by on_ack.. */
                                rd_kafka_interceptors_on_acknowledgement(
                                        rkt->rkt_rk, &rkmessages[i]);

                                rd_kafka_msg_destroy(rkt->rkt_rk, rkm);
                                continue;
                        }


                } else {
                        /* Single destination partition, enqueue message
                         * on temporary queue for later queue concat. */
                        rd_kafka_msgq_enq(&tmpq, rkm);
                }

                rkmessages[i].err = RD_KAFKA_RESP_ERR_NO_ERROR;
                good++;
        }



	/* Specific partition */
        if (partition != RD_KAFKA_PARTITION_UA) {
                shptr_rd_kafka_toppar_t *s_rktp;

		rd_kafka_topic_rdlock(rkt);

                s_rktp = rd_kafka_toppar_get_avail(rkt, partition,
                                                   1/*ua on miss*/, &all_err);
                /* Concatenate tmpq onto partition queue. */
                if (likely(s_rktp != NULL)) {
                        rd_kafka_toppar_t *rktp = rd_kafka_toppar_s2i(s_rktp);
                        rd_atomic64_add(&rktp->rktp_c.msgs, good);
                        rd_kafka_toppar_concat_msgq(rktp, &tmpq);
                        rd_kafka_toppar_destroy(s_rktp);
                }
        }

	rd_kafka_topic_rdunlock(rkt);

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
	int cnt = rd_atomic32_get(&timedout->rkmq_msg_cnt);

	/* Assume messages are added in time sequencial order */
	TAILQ_FOREACH_SAFE(rkm, &rkmq->rkmq_msgs, rkm_link, tmp) {
		if (likely(rkm->rkm_ts_timeout > now))
			break;

		rd_kafka_msgq_deq(rkmq, rkm, 1);
		rd_kafka_msgq_enq(timedout, rkm);
	}

	return rd_atomic32_get(&timedout->rkmq_msg_cnt) - cnt;
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

