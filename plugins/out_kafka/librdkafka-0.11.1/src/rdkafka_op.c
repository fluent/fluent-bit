/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2015, Magnus Edenhill
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

#include <stdarg.h>

#include "rdkafka_int.h"
#include "rdkafka_op.h"
#include "rdkafka_topic.h"
#include "rdkafka_partition.h"
#include "rdkafka_offset.h"

/* Current number of rd_kafka_op_t */
rd_atomic32_t rd_kafka_op_cnt;


const char *rd_kafka_op2str (rd_kafka_op_type_t type) {
        int skiplen = 6;
        static const char *names[] = {
                [RD_KAFKA_OP_NONE] = "REPLY:NONE",
                [RD_KAFKA_OP_FETCH] = "REPLY:FETCH",
                [RD_KAFKA_OP_ERR] = "REPLY:ERR",
                [RD_KAFKA_OP_CONSUMER_ERR] = "REPLY:CONSUMER_ERR",
                [RD_KAFKA_OP_DR] = "REPLY:DR",
                [RD_KAFKA_OP_STATS] = "REPLY:STATS",
                [RD_KAFKA_OP_OFFSET_COMMIT] = "REPLY:OFFSET_COMMIT",
                [RD_KAFKA_OP_NODE_UPDATE] = "REPLY:NODE_UPDATE",
                [RD_KAFKA_OP_XMIT_BUF] = "REPLY:XMIT_BUF",
                [RD_KAFKA_OP_RECV_BUF] = "REPLY:RECV_BUF",
                [RD_KAFKA_OP_XMIT_RETRY] = "REPLY:XMIT_RETRY",
                [RD_KAFKA_OP_FETCH_START] = "REPLY:FETCH_START",
                [RD_KAFKA_OP_FETCH_STOP] = "REPLY:FETCH_STOP",
                [RD_KAFKA_OP_SEEK] = "REPLY:SEEK",
                [RD_KAFKA_OP_PAUSE] = "REPLY:PAUSE",
                [RD_KAFKA_OP_OFFSET_FETCH] = "REPLY:OFFSET_FETCH",
                [RD_KAFKA_OP_PARTITION_JOIN] = "REPLY:PARTITION_JOIN",
                [RD_KAFKA_OP_PARTITION_LEAVE] = "REPLY:PARTITION_LEAVE",
                [RD_KAFKA_OP_REBALANCE] = "REPLY:REBALANCE",
                [RD_KAFKA_OP_TERMINATE] = "REPLY:TERMINATE",
                [RD_KAFKA_OP_COORD_QUERY] = "REPLY:COORD_QUERY",
                [RD_KAFKA_OP_SUBSCRIBE] = "REPLY:SUBSCRIBE",
                [RD_KAFKA_OP_ASSIGN] = "REPLY:ASSIGN",
                [RD_KAFKA_OP_GET_SUBSCRIPTION] = "REPLY:GET_SUBSCRIPTION",
                [RD_KAFKA_OP_GET_ASSIGNMENT] = "REPLY:GET_ASSIGNMENT",
                [RD_KAFKA_OP_THROTTLE] = "REPLY:THROTTLE",
                [RD_KAFKA_OP_NAME] = "REPLY:NAME",
                [RD_KAFKA_OP_OFFSET_RESET] = "REPLY:OFFSET_RESET",
                [RD_KAFKA_OP_METADATA] = "REPLY:METADATA",
                [RD_KAFKA_OP_LOG] = "REPLY:LOG",
                [RD_KAFKA_OP_WAKEUP] = "REPLY:WAKEUP",
        };

        if (type & RD_KAFKA_OP_REPLY)
                skiplen = 0;

        return names[type & ~RD_KAFKA_OP_FLAGMASK]+skiplen;
}


void rd_kafka_op_print (FILE *fp, const char *prefix, rd_kafka_op_t *rko) {
	fprintf(fp,
		"%s((rd_kafka_op_t*)%p)\n"
		"%s Type: %s (0x%x), Version: %"PRId32"\n",
		prefix, rko,
		prefix, rd_kafka_op2str(rko->rko_type), rko->rko_type,
		rko->rko_version);
	if (rko->rko_err)
		fprintf(fp, "%s Error: %s\n",
			prefix, rd_kafka_err2str(rko->rko_err));
	if (rko->rko_replyq.q)
		fprintf(fp, "%s Replyq %p v%d (%s)\n",
			prefix, rko->rko_replyq.q, rko->rko_replyq.version,
#if ENABLE_DEVEL
			rko->rko_replyq._id
#else
			""
#endif
			);
	if (rko->rko_rktp) {
		rd_kafka_toppar_t *rktp = rd_kafka_toppar_s2i(rko->rko_rktp);
		fprintf(fp, "%s ((rd_kafka_toppar_t*)%p) "
			"%s [%"PRId32"] v%d (shptr %p)\n",
			prefix, rktp, rktp->rktp_rkt->rkt_topic->str,
			rktp->rktp_partition,
			rd_atomic32_get(&rktp->rktp_version), rko->rko_rktp);
	}

	switch (rko->rko_type & ~RD_KAFKA_OP_FLAGMASK)
	{
	case RD_KAFKA_OP_FETCH:
		fprintf(fp,  "%s Offset: %"PRId64"\n",
			prefix, rko->rko_u.fetch.rkm.rkm_offset);
		break;
	case RD_KAFKA_OP_CONSUMER_ERR:
		fprintf(fp,  "%s Offset: %"PRId64"\n",
			prefix, rko->rko_u.err.offset);
		/* FALLTHRU */
	case RD_KAFKA_OP_ERR:
		fprintf(fp, "%s Reason: %s\n", prefix, rko->rko_u.err.errstr);
		break;
	case RD_KAFKA_OP_DR:
		fprintf(fp, "%s %"PRId32" messages on %s\n", prefix,
			rd_atomic32_get(&rko->rko_u.dr.msgq.rkmq_msg_cnt),
			rko->rko_u.dr.s_rkt ?
			rd_kafka_topic_s2i(rko->rko_u.dr.s_rkt)->
			rkt_topic->str : "(n/a)");
		break;
	case RD_KAFKA_OP_OFFSET_COMMIT:
		fprintf(fp, "%s Callback: %p (opaque %p)\n",
			prefix, rko->rko_u.offset_commit.cb,
			rko->rko_u.offset_commit.opaque);
		fprintf(fp, "%s %d partitions\n",
			prefix,
			rko->rko_u.offset_commit.partitions ?
			rko->rko_u.offset_commit.partitions->cnt : 0);
		break;

        case RD_KAFKA_OP_LOG:
                fprintf(fp, "%s Log: %%%d %s: %s\n",
                        prefix, rko->rko_u.log.level,
                        rko->rko_u.log.fac,
                        rko->rko_u.log.str);
                break;

	default:
		break;
	}
}


rd_kafka_op_t *rd_kafka_op_new0 (const char *source, rd_kafka_op_type_t type) {
	rd_kafka_op_t *rko;
        static const size_t op2size[RD_KAFKA_OP__END] = {
                [RD_KAFKA_OP_FETCH] = sizeof(rko->rko_u.fetch),
                [RD_KAFKA_OP_ERR] = sizeof(rko->rko_u.err),
                [RD_KAFKA_OP_CONSUMER_ERR] = sizeof(rko->rko_u.err),
                [RD_KAFKA_OP_DR] = sizeof(rko->rko_u.dr),
                [RD_KAFKA_OP_STATS] = sizeof(rko->rko_u.stats),
                [RD_KAFKA_OP_OFFSET_COMMIT] = sizeof(rko->rko_u.offset_commit),
                [RD_KAFKA_OP_NODE_UPDATE] = sizeof(rko->rko_u.node),
                [RD_KAFKA_OP_XMIT_BUF] = sizeof(rko->rko_u.xbuf),
                [RD_KAFKA_OP_RECV_BUF] = sizeof(rko->rko_u.xbuf),
                [RD_KAFKA_OP_XMIT_RETRY] = sizeof(rko->rko_u.xbuf),
                [RD_KAFKA_OP_FETCH_START] = sizeof(rko->rko_u.fetch_start),
                [RD_KAFKA_OP_FETCH_STOP] = 0,
                [RD_KAFKA_OP_SEEK] = sizeof(rko->rko_u.fetch_start),
                [RD_KAFKA_OP_PAUSE] = sizeof(rko->rko_u.pause),
                [RD_KAFKA_OP_OFFSET_FETCH] = sizeof(rko->rko_u.offset_fetch),
                [RD_KAFKA_OP_PARTITION_JOIN] = 0,
                [RD_KAFKA_OP_PARTITION_LEAVE] = 0,
                [RD_KAFKA_OP_REBALANCE] = sizeof(rko->rko_u.rebalance),
                [RD_KAFKA_OP_TERMINATE] = 0,
                [RD_KAFKA_OP_COORD_QUERY] = 0,
                [RD_KAFKA_OP_SUBSCRIBE] = sizeof(rko->rko_u.subscribe),
                [RD_KAFKA_OP_ASSIGN] = sizeof(rko->rko_u.assign),
                [RD_KAFKA_OP_GET_SUBSCRIPTION] = sizeof(rko->rko_u.subscribe),
                [RD_KAFKA_OP_GET_ASSIGNMENT] = sizeof(rko->rko_u.assign),
                [RD_KAFKA_OP_THROTTLE] = sizeof(rko->rko_u.throttle),
                [RD_KAFKA_OP_NAME] = sizeof(rko->rko_u.name),
                [RD_KAFKA_OP_OFFSET_RESET] = sizeof(rko->rko_u.offset_reset),
                [RD_KAFKA_OP_METADATA] = sizeof(rko->rko_u.metadata),
                [RD_KAFKA_OP_LOG] = sizeof(rko->rko_u.log),
                [RD_KAFKA_OP_WAKEUP] = 0,
	};
	size_t tsize = op2size[type & ~RD_KAFKA_OP_FLAGMASK];

	rko = rd_calloc(1, sizeof(*rko)-sizeof(rko->rko_u)+tsize);
	rko->rko_type = type;

#if ENABLE_DEVEL
        rko->rko_source = source;
        rd_atomic32_add(&rd_kafka_op_cnt, 1);
#endif
	return rko;
}


void rd_kafka_op_destroy (rd_kafka_op_t *rko) {

	switch (rko->rko_type & ~RD_KAFKA_OP_FLAGMASK)
	{
	case RD_KAFKA_OP_FETCH:
		rd_kafka_msg_destroy(NULL, &rko->rko_u.fetch.rkm);
		/* Decrease refcount on rkbuf to eventually rd_free shared buf*/
		if (rko->rko_u.fetch.rkbuf)
			rd_kafka_buf_handle_op(rko, RD_KAFKA_RESP_ERR__DESTROY);

		break;

	case RD_KAFKA_OP_OFFSET_FETCH:
		if (rko->rko_u.offset_fetch.partitions &&
		    rko->rko_u.offset_fetch.do_free)
			rd_kafka_topic_partition_list_destroy(
				rko->rko_u.offset_fetch.partitions);
		break;

	case RD_KAFKA_OP_OFFSET_COMMIT:
		RD_IF_FREE(rko->rko_u.offset_commit.partitions,
			   rd_kafka_topic_partition_list_destroy);
                RD_IF_FREE(rko->rko_u.offset_commit.reason, rd_free);
		break;

	case RD_KAFKA_OP_SUBSCRIBE:
	case RD_KAFKA_OP_GET_SUBSCRIPTION:
		RD_IF_FREE(rko->rko_u.subscribe.topics,
			   rd_kafka_topic_partition_list_destroy);
		break;

	case RD_KAFKA_OP_ASSIGN:
	case RD_KAFKA_OP_GET_ASSIGNMENT:
		RD_IF_FREE(rko->rko_u.assign.partitions,
			   rd_kafka_topic_partition_list_destroy);
		break;

	case RD_KAFKA_OP_REBALANCE:
		RD_IF_FREE(rko->rko_u.rebalance.partitions,
			   rd_kafka_topic_partition_list_destroy);
		break;

	case RD_KAFKA_OP_NAME:
		RD_IF_FREE(rko->rko_u.name.str, rd_free);
		break;

	case RD_KAFKA_OP_ERR:
	case RD_KAFKA_OP_CONSUMER_ERR:
		RD_IF_FREE(rko->rko_u.err.errstr, rd_free);
		rd_kafka_msg_destroy(NULL, &rko->rko_u.err.rkm);
		break;

		break;

	case RD_KAFKA_OP_THROTTLE:
		RD_IF_FREE(rko->rko_u.throttle.nodename, rd_free);
		break;

	case RD_KAFKA_OP_STATS:
		RD_IF_FREE(rko->rko_u.stats.json, rd_free);
		break;

	case RD_KAFKA_OP_XMIT_RETRY:
	case RD_KAFKA_OP_XMIT_BUF:
	case RD_KAFKA_OP_RECV_BUF:
		if (rko->rko_u.xbuf.rkbuf)
			rd_kafka_buf_handle_op(rko, RD_KAFKA_RESP_ERR__DESTROY);

		RD_IF_FREE(rko->rko_u.xbuf.rkbuf, rd_kafka_buf_destroy);
		break;

	case RD_KAFKA_OP_DR:
		rd_kafka_msgq_purge(rko->rko_rk, &rko->rko_u.dr.msgq);
		if (rko->rko_u.dr.do_purge2)
			rd_kafka_msgq_purge(rko->rko_rk, &rko->rko_u.dr.msgq2);

		if (rko->rko_u.dr.s_rkt)
			rd_kafka_topic_destroy0(rko->rko_u.dr.s_rkt);
		break;

	case RD_KAFKA_OP_OFFSET_RESET:
		RD_IF_FREE(rko->rko_u.offset_reset.reason, rd_free);
		break;

        case RD_KAFKA_OP_METADATA:
                RD_IF_FREE(rko->rko_u.metadata.md, rd_kafka_metadata_destroy);
                break;

        case RD_KAFKA_OP_LOG:
                rd_free(rko->rko_u.log.str);
                break;

	default:
		break;
	}

        if (rko->rko_type & RD_KAFKA_OP_CB && rko->rko_op_cb) {
                rd_kafka_op_res_t res;
                /* Let callback clean up */
                rko->rko_err = RD_KAFKA_RESP_ERR__DESTROY;
                res = rko->rko_op_cb(rko->rko_rk, NULL, rko);
                assert(res != RD_KAFKA_OP_RES_YIELD);
        }

	RD_IF_FREE(rko->rko_rktp, rd_kafka_toppar_destroy);

	rd_kafka_replyq_destroy(&rko->rko_replyq);

#if ENABLE_DEVEL
        if (rd_atomic32_sub(&rd_kafka_op_cnt, 1) < 0)
                rd_kafka_assert(NULL, !*"rd_kafka_op_cnt < 0");
#endif

	rd_free(rko);
}











/**
 * Propagate an error event to the application on a specific queue.
 * \p optype should be RD_KAFKA_OP_ERR for generic errors and
 * RD_KAFKA_OP_CONSUMER_ERR for consumer errors.
 */
void rd_kafka_q_op_err (rd_kafka_q_t *rkq, rd_kafka_op_type_t optype,
                        rd_kafka_resp_err_t err, int32_t version,
			rd_kafka_toppar_t *rktp, int64_t offset,
                        const char *fmt, ...) {
	va_list ap;
	char buf[2048];
	rd_kafka_op_t *rko;

	va_start(ap, fmt);
	rd_vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	rko = rd_kafka_op_new(optype);
	rko->rko_version = version;
	rko->rko_err = err;
	rko->rko_u.err.offset = offset;
	rko->rko_u.err.errstr = rd_strdup(buf);
	if (rktp)
		rko->rko_rktp = rd_kafka_toppar_keep(rktp);

	rd_kafka_q_enq(rkq, rko);
}



/**
 * Creates a reply opp based on 'rko_orig'.
 * If 'rko_orig' has rko_op_cb set the reply op will be OR:ed with
 * RD_KAFKA_OP_CB, else the reply type will be the original rko_type OR:ed
 * with RD_KAFKA_OP_REPLY.
 */
rd_kafka_op_t *rd_kafka_op_new_reply (rd_kafka_op_t *rko_orig,
				      rd_kafka_resp_err_t err) {
        rd_kafka_op_t *rko;

        rko = rd_kafka_op_new(rko_orig->rko_type |
			      (rko_orig->rko_op_cb ?
			       RD_KAFKA_OP_CB : RD_KAFKA_OP_REPLY));
	rd_kafka_op_get_reply_version(rko, rko_orig);
	rko->rko_op_cb   = rko_orig->rko_op_cb;
	rko->rko_err     = err;
	if (rko_orig->rko_rktp)
		rko->rko_rktp = rd_kafka_toppar_keep(
			rd_kafka_toppar_s2i(rko_orig->rko_rktp));

        return rko;
}


/**
 * @brief Create new callback op for type \p type
 */
rd_kafka_op_t *rd_kafka_op_new_cb (rd_kafka_t *rk,
                                   rd_kafka_op_type_t type,
                                   rd_kafka_op_cb_t *cb) {
        rd_kafka_op_t *rko;
        rko = rd_kafka_op_new(type | RD_KAFKA_OP_CB);
        rko->rko_op_cb = cb;
        rko->rko_rk = rk;
        return rko;
}



/**
 * @brief Reply to 'rko' re-using the same rko.
 * If there is no replyq the rko is destroyed.
 *
 * @returns 1 if op was enqueued, else 0 and rko is destroyed.
 */
int rd_kafka_op_reply (rd_kafka_op_t *rko, rd_kafka_resp_err_t err) {

        if (!rko->rko_replyq.q) {
		rd_kafka_op_destroy(rko);
                return 0;
	}

	rko->rko_type |= (rko->rko_op_cb ? RD_KAFKA_OP_CB : RD_KAFKA_OP_REPLY);
        rko->rko_err   = err;

	return rd_kafka_replyq_enq(&rko->rko_replyq, rko, 0);
}


/**
 * @brief Send request to queue, wait for response.
 *
 * @returns response on success or NULL if destq is disabled.
 */
rd_kafka_op_t *rd_kafka_op_req0 (rd_kafka_q_t *destq,
                                 rd_kafka_q_t *recvq,
                                 rd_kafka_op_t *rko,
                                 int timeout_ms) {
        rd_kafka_op_t *reply;

        /* Indicate to destination where to send reply. */
        rd_kafka_op_set_replyq(rko, recvq, NULL);

        /* Enqueue op */
        if (!rd_kafka_q_enq(destq, rko))
                return NULL;

        /* Wait for reply */
        reply = rd_kafka_q_pop(recvq, timeout_ms, 0);

        /* May be NULL for timeout */
        return reply;
}

/**
 * Send request to queue, wait for response.
 * Creates a temporary reply queue.
 */
rd_kafka_op_t *rd_kafka_op_req (rd_kafka_q_t *destq,
                                rd_kafka_op_t *rko,
                                int timeout_ms) {
        rd_kafka_q_t *recvq;
        rd_kafka_op_t *reply;

        recvq = rd_kafka_q_new(destq->rkq_rk);

        reply = rd_kafka_op_req0(destq, recvq, rko, timeout_ms);

        rd_kafka_q_destroy(recvq);

        return reply;
}


/**
 * Send simple type-only request to queue, wait for response.
 */
rd_kafka_op_t *rd_kafka_op_req2 (rd_kafka_q_t *destq, rd_kafka_op_type_t type) {
        rd_kafka_op_t *rko;

        rko = rd_kafka_op_new(type);
        return rd_kafka_op_req(destq, rko, RD_POLL_INFINITE);
}

/**
 * Destroys the rko and returns its error.
 */
rd_kafka_resp_err_t rd_kafka_op_err_destroy (rd_kafka_op_t *rko) {
        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR__TIMED_OUT;

	if (rko) {
		err = rko->rko_err;
		rd_kafka_op_destroy(rko);
	}
        return err;
}


/**
 * Call op callback
 */
rd_kafka_op_res_t rd_kafka_op_call (rd_kafka_t *rk, rd_kafka_q_t *rkq,
                                    rd_kafka_op_t *rko) {
        rd_kafka_op_res_t res;
        res = rko->rko_op_cb(rk, rkq, rko);
        if (unlikely(res == RD_KAFKA_OP_RES_YIELD || rd_kafka_yield_thread))
                return RD_KAFKA_OP_RES_YIELD;
        rko->rko_op_cb = NULL;
        return res;
}


/**
 * @brief Creates a new RD_KAFKA_OP_FETCH op and sets up the
 *        embedded message according to the parameters.
 *
 * @param rkmp will be set to the embedded rkm in the rko (for convenience)
 * @param offset may be updated later if relative offset.
 */
rd_kafka_op_t *
rd_kafka_op_new_fetch_msg (rd_kafka_msg_t **rkmp,
                           rd_kafka_toppar_t *rktp,
                           int32_t version,
                           rd_kafka_buf_t *rkbuf,
                           int64_t offset,
                           size_t key_len, const void *key,
                           size_t val_len, const void *val) {
        rd_kafka_msg_t *rkm;
        rd_kafka_op_t *rko;

        rko = rd_kafka_op_new(RD_KAFKA_OP_FETCH);
        rko->rko_rktp    = rd_kafka_toppar_keep(rktp);
        rko->rko_version = version;
        rkm   = &rko->rko_u.fetch.rkm;
        *rkmp = rkm;

        /* Since all the ops share the same payload buffer
         * a refcnt is used on the rkbuf that makes sure all
         * consume_cb() will have been
         * called for each of these ops before the rkbuf
         * and its memory backing buffers are freed. */
        rko->rko_u.fetch.rkbuf = rkbuf;
        rd_kafka_buf_keep(rkbuf);

        rkm->rkm_offset    = offset;

        rkm->rkm_key       = (void *)key;
        rkm->rkm_key_len   = key_len;

        rkm->rkm_payload   = (void *)val;
        rkm->rkm_len       = val_len;
        rko->rko_len       = (int32_t)rkm->rkm_len;

        rkm->rkm_partition = rktp->rktp_partition;

        return rko;
}


/**
 * Enqueue ERR__THROTTLE op, if desired.
 */
void rd_kafka_op_throttle_time (rd_kafka_broker_t *rkb,
				rd_kafka_q_t *rkq,
				int throttle_time) {
	rd_kafka_op_t *rko;

	rd_avg_add(&rkb->rkb_avg_throttle, throttle_time);

	/* We send throttle events when:
	 *  - throttle_time > 0
	 *  - throttle_time == 0 and last throttle_time > 0
	 */
	if (!rkb->rkb_rk->rk_conf.throttle_cb ||
	    (!throttle_time && !rd_atomic32_get(&rkb->rkb_rk->rk_last_throttle)))
		return;

	rd_atomic32_set(&rkb->rkb_rk->rk_last_throttle, throttle_time);

	rko = rd_kafka_op_new(RD_KAFKA_OP_THROTTLE);
        rd_kafka_op_set_prio(rko, RD_KAFKA_PRIO_HIGH);
	rko->rko_u.throttle.nodename = rd_strdup(rkb->rkb_nodename);
	rko->rko_u.throttle.nodeid   = rkb->rkb_nodeid;
	rko->rko_u.throttle.throttle_time = throttle_time;
	rd_kafka_q_enq(rkq, rko);
}


/**
 * @brief Handle standard op types.
 */
rd_kafka_op_res_t
rd_kafka_op_handle_std (rd_kafka_t *rk, rd_kafka_q_t *rkq,
                        rd_kafka_op_t *rko, int cb_type) {
        if (cb_type == RD_KAFKA_Q_CB_FORCE_RETURN)
                return RD_KAFKA_OP_RES_PASS;
        else if (cb_type != RD_KAFKA_Q_CB_EVENT &&
                 rko->rko_type & RD_KAFKA_OP_CB)
                return rd_kafka_op_call(rk, rkq, rko);
        else if (rko->rko_type == RD_KAFKA_OP_RECV_BUF) /* Handle Response */
                rd_kafka_buf_handle_op(rko, rko->rko_err);
        else if (rko->rko_type == RD_KAFKA_OP_WAKEUP)
                ;/* do nothing, wake up is a fact anyway */
        else if (cb_type != RD_KAFKA_Q_CB_RETURN &&
                 rko->rko_type & RD_KAFKA_OP_REPLY &&
                 rko->rko_err == RD_KAFKA_RESP_ERR__DESTROY)
                return RD_KAFKA_OP_RES_HANDLED; /* dest queue was
                                                 * probably disabled. */
        else
                return RD_KAFKA_OP_RES_PASS;

        return RD_KAFKA_OP_RES_HANDLED;
}


/**
 * @brief Attempt to handle op using its queue's serve callback,
 *        or the passed callback, or op_handle_std(), else do nothing.
 *
 * @param rkq is \p rko's queue (which it was unlinked from) with rkq_lock
 *            being held. Callback may re-enqueue the op on this queue
 *            and return YIELD.
 *
 * @returns HANDLED if op was handled (and destroyed), PASS if not,
 *          or YIELD if op was handled (maybe destroyed or re-enqueued)
 *          and caller must propagate yield upwards (cancel and return).
 */
rd_kafka_op_res_t
rd_kafka_op_handle (rd_kafka_t *rk, rd_kafka_q_t *rkq, rd_kafka_op_t *rko,
                    rd_kafka_q_cb_type_t cb_type, void *opaque,
                    rd_kafka_q_serve_cb_t *callback) {
        rd_kafka_op_res_t res;

        res = rd_kafka_op_handle_std(rk, rkq, rko, cb_type);
        if (res == RD_KAFKA_OP_RES_HANDLED) {
                rd_kafka_op_destroy(rko);
                return res;
        } else if (unlikely(res == RD_KAFKA_OP_RES_YIELD))
                return res;

        if (rko->rko_serve) {
                callback = rko->rko_serve;
                opaque   = rko->rko_serve_opaque;
                rko->rko_serve        = NULL;
                rko->rko_serve_opaque = NULL;
        }

        if (callback)
                res = callback(rk, rkq, rko, cb_type, opaque);

        return res;
}


/**
 * @brief Store offset for fetched message.
 */
void rd_kafka_op_offset_store (rd_kafka_t *rk, rd_kafka_op_t *rko,
			       const rd_kafka_message_t *rkmessage) {
	rd_kafka_toppar_t *rktp;

	if (unlikely(rko->rko_type != RD_KAFKA_OP_FETCH || rko->rko_err))
		return;

	rktp = rd_kafka_toppar_s2i(rko->rko_rktp);

	if (unlikely(!rk))
		rk = rktp->rktp_rkt->rkt_rk;

	rd_kafka_toppar_lock(rktp);
	rktp->rktp_app_offset = rkmessage->offset+1;
	if (rk->rk_conf.enable_auto_offset_store)
		rd_kafka_offset_store0(rktp, rkmessage->offset+1, 0/*no lock*/);
	rd_kafka_toppar_unlock(rktp);
}
