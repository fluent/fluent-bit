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



#ifndef _MSC_VER
#define _GNU_SOURCE
/*
 * AIX defines this and the value needs to be set correctly. For Solaris,
 * src/rd.h defines _POSIX_SOURCE to be 200809L, which corresponds to XPG7,
 * which itself is not compatible with _XOPEN_SOURCE on that platform.
 */
#if !defined(_AIX) && !defined(__sun)
#define _XOPEN_SOURCE
#endif
#include <signal.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#include "rd.h"
#include "rdkafka_int.h"
#include "rdkafka_msg.h"
#include "rdkafka_msgset.h"
#include "rdkafka_topic.h"
#include "rdkafka_partition.h"
#include "rdkafka_broker.h"
#include "rdkafka_offset.h"
#include "rdkafka_transport.h"
#include "rdkafka_proto.h"
#include "rdkafka_buf.h"
#include "rdkafka_request.h"
#include "rdkafka_sasl.h"
#include "rdkafka_interceptor.h"
#include "rdtime.h"
#include "rdcrc32.h"
#include "rdrand.h"
#include "rdkafka_lz4.h"
#if WITH_SSL
#include <openssl/err.h>
#endif
#include "rdendian.h"


const char *rd_kafka_broker_state_names[] = {
	"INIT",
	"DOWN",
	"CONNECT",
	"AUTH",
	"UP",
        "UPDATE",
	"APIVERSION_QUERY",
	"AUTH_HANDSHAKE"
};

const char *rd_kafka_secproto_names[] = {
	[RD_KAFKA_PROTO_PLAINTEXT] = "plaintext",
	[RD_KAFKA_PROTO_SSL] = "ssl",
	[RD_KAFKA_PROTO_SASL_PLAINTEXT] = "sasl_plaintext",
	[RD_KAFKA_PROTO_SASL_SSL] = "sasl_ssl",
	NULL
};







#define rd_kafka_broker_terminating(rkb) \
        (rd_refcnt_get(&(rkb)->rkb_refcnt) <= 1)


/**
 * Construct broker nodename.
 */
static void rd_kafka_mk_nodename (char *dest, size_t dsize,
                                  const char *name, uint16_t port) {
        rd_snprintf(dest, dsize, "%s:%hu", name, port);
}

/**
 * Construct descriptive broker name
 */
static void rd_kafka_mk_brokername (char *dest, size_t dsize,
				    rd_kafka_secproto_t proto,
				    const char *nodename, int32_t nodeid,
				    rd_kafka_confsource_t source) {

	/* Prepend protocol name to brokername, unless it is a
	 * standard plaintext broker in which case we omit the protocol part. */
	if (proto != RD_KAFKA_PROTO_PLAINTEXT) {
		int r = rd_snprintf(dest, dsize, "%s://",
				    rd_kafka_secproto_names[proto]);
		if (r >= (int)dsize) /* Skip proto name if it wont fit.. */
			r = 0;

		dest += r;
		dsize -= r;
	}

	if (nodeid == RD_KAFKA_NODEID_UA)
		rd_snprintf(dest, dsize, "%s/%s",
			    nodename,
			    source == RD_KAFKA_INTERNAL ?
			    "internal":"bootstrap");
	else
		rd_snprintf(dest, dsize, "%s/%"PRId32, nodename, nodeid);
}


/**
 * @brief Enable protocol feature(s) for the current broker.
 *
 * Locality: broker thread
 */
static void rd_kafka_broker_feature_enable (rd_kafka_broker_t *rkb,
					    int features) {
	if (features & rkb->rkb_features)
		return;

	rkb->rkb_features |= features;
	rd_rkb_dbg(rkb, BROKER | RD_KAFKA_DBG_PROTOCOL | RD_KAFKA_DBG_FEATURE,
		   "FEATURE",
		   "Updated enabled protocol features +%s to %s",
		   rd_kafka_features2str(features),
		   rd_kafka_features2str(rkb->rkb_features));
}


/**
 * @brief Disable protocol feature(s) for the current broker.
 *
 * Locality: broker thread
 */
static void rd_kafka_broker_feature_disable (rd_kafka_broker_t *rkb,
						       int features) {
	if (!(features & rkb->rkb_features))
		return;

	rkb->rkb_features &= ~features;
	rd_rkb_dbg(rkb, BROKER | RD_KAFKA_DBG_PROTOCOL | RD_KAFKA_DBG_FEATURE,
		   "FEATURE",
		   "Updated enabled protocol features -%s to %s",
		   rd_kafka_features2str(features),
		   rd_kafka_features2str(rkb->rkb_features));
}


/**
 * @brief Set protocol feature(s) for the current broker.
 *
 * @remark This replaces the previous feature set.
 *
 * @locality broker thread
 * @locks rd_kafka_broker_lock()
 */
static void rd_kafka_broker_features_set (rd_kafka_broker_t *rkb, int features) {
	if (rkb->rkb_features == features)
		return;

	rkb->rkb_features = features;
	rd_rkb_dbg(rkb, BROKER, "FEATURE",
		   "Updated enabled protocol features to %s",
		   rd_kafka_features2str(rkb->rkb_features));
}


/**
 * @brief Check and return supported ApiVersion for \p ApiKey.
 *
 * @returns the highest supported ApiVersion in the specified range (inclusive)
 *          or -1 if the ApiKey is not supported or no matching ApiVersion.
 *          The current feature set is also returned in \p featuresp
 * @locks none
 * @locality any
 */
int16_t rd_kafka_broker_ApiVersion_supported (rd_kafka_broker_t *rkb,
                                              int16_t ApiKey,
                                              int16_t minver, int16_t maxver,
                                              int *featuresp) {
        struct rd_kafka_ApiVersion skel = { .ApiKey = ApiKey };
        struct rd_kafka_ApiVersion ret = RD_ZERO_INIT, *retp;

        rd_kafka_broker_lock(rkb);
        retp = bsearch(&skel, rkb->rkb_ApiVersions, rkb->rkb_ApiVersions_cnt,
                       sizeof(*rkb->rkb_ApiVersions),
                       rd_kafka_ApiVersion_key_cmp);
        if (retp)
                ret = *retp;
        if (featuresp)
                *featuresp = rkb->rkb_features;
        rd_kafka_broker_unlock(rkb);

        if (!retp)
                return -1;

        if (ret.MaxVer < maxver) {
                if (ret.MaxVer < minver)
                        return -1;
                else
                        return ret.MaxVer;
        } else if (ret.MinVer > maxver)
                return -1;
        else
                return maxver;
}


/**
 * @brief Set broker state.
 *
 *        \c rkb->rkb_state is the previous state, while
 *        \p state is the new state.
 *
 * @locks rd_kafka_broker_lock() MUST be held.
 * @locality broker thread
 */
void rd_kafka_broker_set_state (rd_kafka_broker_t *rkb, int state) {
	if ((int)rkb->rkb_state == state)
		return;

	rd_kafka_dbg(rkb->rkb_rk, BROKER, "STATE",
		     "%s: Broker changed state %s -> %s",
		     rkb->rkb_name,
		     rd_kafka_broker_state_names[rkb->rkb_state],
		     rd_kafka_broker_state_names[state]);

	if (rkb->rkb_source == RD_KAFKA_INTERNAL) {
		/* no-op */
	} else if (state == RD_KAFKA_BROKER_STATE_DOWN &&
		   !rkb->rkb_down_reported &&
		   rkb->rkb_state != RD_KAFKA_BROKER_STATE_APIVERSION_QUERY) {
		/* Propagate ALL_BROKERS_DOWN event if all brokers are
		 * now down, unless we're terminating.
		 * Dont do this if we're querying for ApiVersion since it
		 * is bound to fail once on older brokers. */
		if (rd_atomic32_add(&rkb->rkb_rk->rk_broker_down_cnt, 1) ==
		    rd_atomic32_get(&rkb->rkb_rk->rk_broker_cnt) &&
		    !rd_atomic32_get(&rkb->rkb_rk->rk_terminate))
			rd_kafka_op_err(rkb->rkb_rk,
					RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN,
					"%i/%i brokers are down",
					rd_atomic32_get(&rkb->rkb_rk->
                                                        rk_broker_down_cnt),
					rd_atomic32_get(&rkb->rkb_rk->
                                                        rk_broker_cnt));
		rkb->rkb_down_reported = 1;

        } else if (state >= RD_KAFKA_BROKER_STATE_UP &&
		   rkb->rkb_down_reported) {
		rd_atomic32_sub(&rkb->rkb_rk->rk_broker_down_cnt, 1);
		rkb->rkb_down_reported = 0;
	}

	rkb->rkb_state = state;
        rkb->rkb_ts_state = rd_clock();

	rd_kafka_brokers_broadcast_state_change(rkb->rkb_rk);
}


/**
 * @brief Locks broker, acquires the states, unlocks, and returns
 *        the state.
 * @locks !broker_lock
 * @locality any
 */
int rd_kafka_broker_get_state (rd_kafka_broker_t *rkb) {
        int state;
        rd_kafka_broker_lock(rkb);
        state = rkb->rkb_state;
        rd_kafka_broker_unlock(rkb);
        return state;
}


/**
 * Failure propagation to application.
 * Will tear down connection to broker and trigger a reconnect.
 *
 * If 'fmt' is NULL nothing will be logged or propagated to the application.
 *
 * \p level is the log level, <=LOG_INFO will be logged while =LOG_DEBUG will
 * be debug-logged.
 * 
 * Locality: Broker thread
 */
void rd_kafka_broker_fail (rd_kafka_broker_t *rkb,
                           int level, rd_kafka_resp_err_t err,
			   const char *fmt, ...) {
	va_list ap;
	int errno_save = errno;
	rd_kafka_bufq_t tmpq_waitresp, tmpq;
        int old_state;

	rd_kafka_assert(rkb->rkb_rk, thrd_is_current(rkb->rkb_thread));

	rd_kafka_dbg(rkb->rkb_rk, BROKER | RD_KAFKA_DBG_PROTOCOL, "BROKERFAIL",
		     "%s: failed: err: %s: (errno: %s)",
		     rkb->rkb_name, rd_kafka_err2str(err),
		     rd_strerror(errno_save));

	rkb->rkb_err.err = errno_save;

	if (rkb->rkb_transport) {
		rd_kafka_transport_close(rkb->rkb_transport);
		rkb->rkb_transport = NULL;
	}

	rkb->rkb_req_timeouts = 0;

	if (rkb->rkb_recv_buf) {
		rd_kafka_buf_destroy(rkb->rkb_recv_buf);
		rkb->rkb_recv_buf = NULL;
	}

        /* Reset max blocking time back to the default to avoid busy-looping
         * on reconnect if blocking=0 (#1397).
         * But honour the lower on-termination blocking time. */
        if (rd_kafka_terminating(rkb->rkb_rk))
                rkb->rkb_blocking_max_ms = 1;
        else
                rkb->rkb_blocking_max_ms =
                        rkb->rkb_rk->rk_conf.socket_blocking_max_ms;

	rd_kafka_broker_lock(rkb);

	/* The caller may omit the format if it thinks this is a recurring
	 * failure, in which case the following things are omitted:
	 *  - log message
	 *  - application OP_ERR
	 *  - metadata request
	 *
	 * Dont log anything if this was the termination signal, or if the
	 * socket disconnected while trying ApiVersionRequest.
	 */
	if (fmt &&
	    !(errno_save == EINTR &&
	      rd_atomic32_get(&rkb->rkb_rk->rk_terminate)) &&
	    !(err == RD_KAFKA_RESP_ERR__TRANSPORT &&
	      rkb->rkb_state == RD_KAFKA_BROKER_STATE_APIVERSION_QUERY)) {
		int of;

		/* Insert broker name in log message if it fits. */
		of = rd_snprintf(rkb->rkb_err.msg, sizeof(rkb->rkb_err.msg),
			      "%s: ", rkb->rkb_name);
		if (of >= (int)sizeof(rkb->rkb_err.msg))
			of = 0;
		va_start(ap, fmt);
		rd_vsnprintf(rkb->rkb_err.msg+of,
			  sizeof(rkb->rkb_err.msg)-of, fmt, ap);
		va_end(ap);

                if (level >= LOG_DEBUG)
                        rd_kafka_dbg(rkb->rkb_rk, BROKER, "FAIL",
                                     "%s", rkb->rkb_err.msg);
                else {
                        /* Don't log if an error callback is registered */
                        if (!rkb->rkb_rk->rk_conf.error_cb)
                                rd_kafka_log(rkb->rkb_rk, level, "FAIL",
                                             "%s", rkb->rkb_err.msg);
                        /* Send ERR op back to application for processing. */
                        rd_kafka_op_err(rkb->rkb_rk, err,
                                        "%s", rkb->rkb_err.msg);
                }
	}

	/* If we're currently asking for ApiVersion and the connection
	 * went down it probably means the broker does not support that request
	 * and tore down the connection. In this case we disable that feature flag. */
	if (rkb->rkb_state == RD_KAFKA_BROKER_STATE_APIVERSION_QUERY)
		rd_kafka_broker_feature_disable(rkb, RD_KAFKA_FEATURE_APIVERSION);

	/* Set broker state */
        old_state = rkb->rkb_state;
	rd_kafka_broker_set_state(rkb, RD_KAFKA_BROKER_STATE_DOWN);

	/* Unlock broker since a requeue will try to lock it. */
	rd_kafka_broker_unlock(rkb);

	/*
	 * Purge all buffers
	 * (put bufs on a temporary queue since bufs may be requeued,
	 *  make sure outstanding requests are re-enqueued before
	 *  bufs on outbufs queue.)
	 */
	rd_kafka_bufq_init(&tmpq_waitresp);
	rd_kafka_bufq_init(&tmpq);
	rd_kafka_bufq_concat(&tmpq_waitresp, &rkb->rkb_waitresps);
	rd_kafka_bufq_concat(&tmpq, &rkb->rkb_outbufs);
        rd_atomic32_init(&rkb->rkb_blocking_request_cnt, 0);

	/* Purge the buffers (might get re-enqueued in case of retries) */
	rd_kafka_bufq_purge(rkb, &tmpq_waitresp, err);

	/* Put the outbufs back on queue */
	rd_kafka_bufq_concat(&rkb->rkb_outbufs, &tmpq);

	/* Update bufq for connection reset:
	 *  - Purge connection-setup requests from outbufs since they will be
	 *    reissued on the next connect.
	 *  - Reset any partially sent buffer's offset.
	 */
	rd_kafka_bufq_connection_reset(rkb, &rkb->rkb_outbufs);

	/* Extra debugging for tracking termination-hang issues:
	 * show what is keeping this broker from decommissioning. */
	if (rd_kafka_terminating(rkb->rkb_rk) &&
	    !rd_kafka_broker_terminating(rkb)) {
		rd_rkb_dbg(rkb, BROKER | RD_KAFKA_DBG_PROTOCOL, "BRKTERM",
			   "terminating: broker still has %d refcnt(s), "
			   "%"PRId32" buffer(s), %d partition(s)",
			   rd_refcnt_get(&rkb->rkb_refcnt),
			   rd_kafka_bufq_cnt(&rkb->rkb_outbufs),
			   rkb->rkb_toppar_cnt);
		rd_kafka_bufq_dump(rkb, "BRKOUTBUFS", &rkb->rkb_outbufs);
#if ENABLE_SHAREDPTR_DEBUG
		if (rd_refcnt_get(&rkb->rkb_refcnt) > 1) {
			rd_rkb_dbg(rkb, BROKER, "BRKTERM",
				   "Dumping shared pointers: "
				   "this broker is %p", rkb);
			rd_shared_ptrs_dump();
		}
#endif
	}


        /* Query for topic leaders to quickly pick up on failover. */
        if (fmt && err != RD_KAFKA_RESP_ERR__DESTROY &&
            old_state >= RD_KAFKA_BROKER_STATE_UP)
                rd_kafka_metadata_refresh_known_topics(rkb->rkb_rk, NULL,
                                                       1/*force*/,
                                                       "broker down");
}





/**
 * Scan bufq for buffer timeouts, trigger buffer callback on timeout.
 *
 * If \p partial_cntp is non-NULL any partially sent buffers will increase
 * the provided counter by 1.
 *
 * @returns the number of timed out buffers.
 *
 * @locality broker thread
 */
static int rd_kafka_broker_bufq_timeout_scan (rd_kafka_broker_t *rkb,
					      int is_waitresp_q,
					      rd_kafka_bufq_t *rkbq,
					      int *partial_cntp,
					      rd_kafka_resp_err_t err,
					      rd_ts_t now) {
	rd_kafka_buf_t *rkbuf, *tmp;
	int cnt = 0;

	TAILQ_FOREACH_SAFE(rkbuf, &rkbq->rkbq_bufs, rkbuf_link, tmp) {

		if (likely(now && rkbuf->rkbuf_ts_timeout > now))
			continue;

                if (partial_cntp && rd_slice_offset(&rkbuf->rkbuf_reader) > 0)
                        (*partial_cntp)++;

		/* Convert rkbuf_ts_sent to elapsed time since request */
		if (rkbuf->rkbuf_ts_sent)
			rkbuf->rkbuf_ts_sent = now - rkbuf->rkbuf_ts_sent;
		else
			rkbuf->rkbuf_ts_sent = now - rkbuf->rkbuf_ts_enq;

		rd_kafka_bufq_deq(rkbq, rkbuf);

		if (is_waitresp_q && rkbuf->rkbuf_flags & RD_KAFKA_OP_F_BLOCKING
		    && rd_atomic32_sub(&rkb->rkb_blocking_request_cnt, 1) == 0)
			rd_kafka_brokers_broadcast_state_change(rkb->rkb_rk);

                rd_kafka_buf_callback(rkb->rkb_rk, rkb, err, NULL, rkbuf);
		cnt++;
	}

	return cnt;
}


/**
 * Scan the wait-response and outbuf queues for message timeouts.
 *
 * Locality: Broker thread
 */
static void rd_kafka_broker_timeout_scan (rd_kafka_broker_t *rkb, rd_ts_t now) {
	int req_cnt, retry_cnt, q_cnt;

	rd_kafka_assert(rkb->rkb_rk, thrd_is_current(rkb->rkb_thread));

	/* Outstanding requests waiting for response */
	req_cnt = rd_kafka_broker_bufq_timeout_scan(
		rkb, 1, &rkb->rkb_waitresps, NULL,
		RD_KAFKA_RESP_ERR__TIMED_OUT, now);
	/* Requests in retry queue */
	retry_cnt = rd_kafka_broker_bufq_timeout_scan(
		rkb, 0, &rkb->rkb_retrybufs, NULL,
		RD_KAFKA_RESP_ERR__TIMED_OUT_QUEUE, now);
	/* Requests in local queue not sent yet. */
	q_cnt = rd_kafka_broker_bufq_timeout_scan(
		rkb, 0, &rkb->rkb_outbufs, &req_cnt,
		RD_KAFKA_RESP_ERR__TIMED_OUT_QUEUE, now);

	if (req_cnt + retry_cnt + q_cnt > 0) {
		rd_rkb_dbg(rkb, MSG|RD_KAFKA_DBG_BROKER,
			   "REQTMOUT", "Timed out %i+%i+%i requests",
			   req_cnt, retry_cnt, q_cnt);

                /* Fail the broker if socket.max.fails is configured and
                 * now exceeded. */
                rkb->rkb_req_timeouts   += req_cnt + q_cnt;
                rd_atomic64_add(&rkb->rkb_c.req_timeouts, req_cnt + q_cnt);

		/* If this was an in-flight request that timed out, or
		 * the other queues has reached the socket.max.fails threshold,
		 * we need to take down the connection. */
                if (rkb->rkb_rk->rk_conf.socket_max_fails &&
                    rkb->rkb_req_timeouts >=
                    rkb->rkb_rk->rk_conf.socket_max_fails &&
                    rkb->rkb_state >= RD_KAFKA_BROKER_STATE_UP) {
                        char rttinfo[32];
                        /* Print average RTT (if avail) to help diagnose. */
                        rd_avg_calc(&rkb->rkb_avg_rtt, now);
                        if (rkb->rkb_avg_rtt.ra_v.avg)
                                rd_snprintf(rttinfo, sizeof(rttinfo),
                                            " (average rtt %.3fms)",
                                            (float)(rkb->rkb_avg_rtt.ra_v.avg/
                                                    1000.0f));
                        else
                                rttinfo[0] = 0;
                        errno = ETIMEDOUT;
                        rd_kafka_broker_fail(rkb, LOG_ERR,
                                             RD_KAFKA_RESP_ERR__TIMED_OUT,
                                             "%i request(s) timed out: "
                                             "disconnect%s",
                                             rkb->rkb_req_timeouts, rttinfo);
                }
        }
}



static ssize_t
rd_kafka_broker_send (rd_kafka_broker_t *rkb, rd_slice_t *slice) {
	ssize_t r;
	char errstr[128];

	rd_kafka_assert(rkb->rkb_rk, rkb->rkb_state >= RD_KAFKA_BROKER_STATE_UP);
	rd_kafka_assert(rkb->rkb_rk, rkb->rkb_transport);

        r = rd_kafka_transport_send(rkb->rkb_transport, slice,
                                    errstr, sizeof(errstr));

	if (r == -1) {
		rd_kafka_broker_fail(rkb, LOG_ERR, RD_KAFKA_RESP_ERR__TRANSPORT,
                                     "Send failed: %s", errstr);
		rd_atomic64_add(&rkb->rkb_c.tx_err, 1);
		return -1;
	}

	rd_atomic64_add(&rkb->rkb_c.tx_bytes, r);
	rd_atomic64_add(&rkb->rkb_c.tx, 1);
	return r;
}




static int rd_kafka_broker_resolve (rd_kafka_broker_t *rkb) {
	const char *errstr;
        int save_idx = 0;

	if (rkb->rkb_rsal &&
	    rkb->rkb_ts_rsal_last + (rkb->rkb_rk->rk_conf.broker_addr_ttl*1000)
	    < rd_clock()) {
		/* Address list has expired. */

                /* Save the address index to make sure we still round-robin
                 * if we get the same address list back */
                save_idx = rkb->rkb_rsal->rsal_curr;

		rd_sockaddr_list_destroy(rkb->rkb_rsal);
		rkb->rkb_rsal = NULL;
	}

	if (!rkb->rkb_rsal) {
		/* Resolve */
		rkb->rkb_rsal = rd_getaddrinfo(rkb->rkb_nodename,
					       RD_KAFKA_PORT_STR,
					       AI_ADDRCONFIG,
					       rkb->rkb_rk->rk_conf.
                                               broker_addr_family,
                                               SOCK_STREAM,
					       IPPROTO_TCP, &errstr);

		if (!rkb->rkb_rsal) {
                        rd_kafka_broker_fail(rkb, LOG_ERR,
                                             RD_KAFKA_RESP_ERR__RESOLVE,
                                             /* Avoid duplicate log messages */
                                             rkb->rkb_err.err == errno ?
                                             NULL :
                                             "Failed to resolve '%s': %s",
                                             rkb->rkb_nodename, errstr);
			return -1;
                } else {
                        rkb->rkb_ts_rsal_last = rd_clock();
                        /* Continue at previous round-robin position */
                        if (rkb->rkb_rsal->rsal_cnt > save_idx)
                                rkb->rkb_rsal->rsal_curr = save_idx;
                }
	}

	return 0;
}


static void rd_kafka_broker_buf_enq0 (rd_kafka_broker_t *rkb,
				      rd_kafka_buf_t *rkbuf, int at_head) {
        rd_ts_t now;

	rd_kafka_assert(rkb->rkb_rk, thrd_is_current(rkb->rkb_thread));

        now = rd_clock();
        rkbuf->rkbuf_ts_enq = now;

        /* Calculate request attempt timeout */
        rd_kafka_buf_calc_timeout(rkb->rkb_rk, rkbuf, now);

	if (unlikely(at_head)) {
		/* Insert message at head of queue */
		rd_kafka_buf_t *prev, *after = NULL;

		/* Put us behind any flash messages and partially sent buffers.
		 * We need to check if buf corrid is set rather than
		 * rkbuf_of since SSL_write may return 0 and expect the
		 * exact same arguments the next call. */
		TAILQ_FOREACH(prev, &rkb->rkb_outbufs.rkbq_bufs, rkbuf_link) {
			if (!(prev->rkbuf_flags & RD_KAFKA_OP_F_FLASH) &&
			    prev->rkbuf_corrid == 0)
				break;
			after = prev;
		}

		if (after)
			TAILQ_INSERT_AFTER(&rkb->rkb_outbufs.rkbq_bufs,
					   after, rkbuf, rkbuf_link);
		else
			TAILQ_INSERT_HEAD(&rkb->rkb_outbufs.rkbq_bufs,
					  rkbuf, rkbuf_link);
	} else {
		/* Insert message at tail of queue */
		TAILQ_INSERT_TAIL(&rkb->rkb_outbufs.rkbq_bufs,
				  rkbuf, rkbuf_link);
	}

	(void)rd_atomic32_add(&rkb->rkb_outbufs.rkbq_cnt, 1);
        (void)rd_atomic32_add(&rkb->rkb_outbufs.rkbq_msg_cnt,
                              rkbuf->rkbuf_msgq.rkmq_msg_cnt);
}


/**
 * Finalize a stuffed rkbuf for sending to broker.
 */
static void rd_kafka_buf_finalize (rd_kafka_t *rk, rd_kafka_buf_t *rkbuf) {
        size_t totsize;

        /* Calculate total request buffer length. */
        totsize = rd_buf_len(&rkbuf->rkbuf_buf) - 4;
        rd_assert(totsize <= (size_t)rk->rk_conf.max_msg_size);

        /* Set up a buffer reader for sending the buffer. */
        rd_slice_init_full(&rkbuf->rkbuf_reader, &rkbuf->rkbuf_buf);

        /**
         * Update request header fields
         */
        /* Total reuqest length */
        rd_kafka_buf_update_i32(rkbuf, 0, (int32_t)totsize);

        /* ApiVersion */
        rd_kafka_buf_update_i16(rkbuf, 4+2, rkbuf->rkbuf_reqhdr.ApiVersion);
}


void rd_kafka_broker_buf_enq1 (rd_kafka_broker_t *rkb,
                               rd_kafka_buf_t *rkbuf,
                               rd_kafka_resp_cb_t *resp_cb,
                               void *opaque) {


        rkbuf->rkbuf_cb     = resp_cb;
	rkbuf->rkbuf_opaque = opaque;

        rd_kafka_buf_finalize(rkb->rkb_rk, rkbuf);

	rd_kafka_broker_buf_enq0(rkb, rkbuf,
				 (rkbuf->rkbuf_flags & RD_KAFKA_OP_F_FLASH)?
				 1/*head*/: 0/*tail*/);
}


/**
 * Enqueue buffer on broker's xmit queue, but fail buffer immediately
 * if broker is not up.
 *
 * Locality: broker thread
 */
static int rd_kafka_broker_buf_enq2 (rd_kafka_broker_t *rkb,
				      rd_kafka_buf_t *rkbuf) {
        if (unlikely(rkb->rkb_source == RD_KAFKA_INTERNAL)) {
                /* Fail request immediately if this is the internal broker. */
                rd_kafka_buf_callback(rkb->rkb_rk, rkb,
				      RD_KAFKA_RESP_ERR__TRANSPORT,
                                      NULL, rkbuf);
                return -1;
        }

	rd_kafka_broker_buf_enq0(rkb, rkbuf,
				 (rkbuf->rkbuf_flags & RD_KAFKA_OP_F_FLASH)?
				 1/*head*/: 0/*tail*/);

	return 0;
}



/**
 * Enqueue buffer for tranmission.
 * Responses are enqueued on 'replyq' (RD_KAFKA_OP_RECV_BUF)
 *
 * Locality: any thread
 */
void rd_kafka_broker_buf_enq_replyq (rd_kafka_broker_t *rkb,
                                     rd_kafka_buf_t *rkbuf,
                                     rd_kafka_replyq_t replyq,
                                     rd_kafka_resp_cb_t *resp_cb,
                                     void *opaque) {

        assert(rkbuf->rkbuf_rkb == rkb);
        if (resp_cb) {
                rkbuf->rkbuf_replyq = replyq;
                rkbuf->rkbuf_cb     = resp_cb;
                rkbuf->rkbuf_opaque = opaque;
        } else {
		rd_dassert(!replyq.q);
	}

        rd_kafka_buf_finalize(rkb->rkb_rk, rkbuf);


	if (thrd_is_current(rkb->rkb_thread)) {
		rd_kafka_broker_buf_enq2(rkb, rkbuf);

	} else {
		rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_XMIT_BUF);
		rko->rko_u.xbuf.rkbuf = rkbuf;
		rd_kafka_q_enq(rkb->rkb_ops, rko);
	}
}




/**
 * @returns the current broker state change version.
 *          Pass this value to fugure rd_kafka_brokers_wait_state_change() calls
 *          to avoid the race condition where a state-change happens between
 *          an initial call to some API that fails and the sub-sequent
 *          .._wait_state_change() call.
 */
int rd_kafka_brokers_get_state_version (rd_kafka_t *rk) {
	int version;
	mtx_lock(&rk->rk_broker_state_change_lock);
	version = rk->rk_broker_state_change_version;
	mtx_unlock(&rk->rk_broker_state_change_lock);
	return version;
}

/**
 * @brief Wait at most \p timeout_ms for any state change for any broker.
 *        \p stored_version is the value previously returned by
 *        rd_kafka_brokers_get_state_version() prior to another API call
 *        that failed due to invalid state.
 *
 * Triggers:
 *   - broker state changes
 *   - broker transitioning from blocking to non-blocking
 *   - partition leader changes
 *   - group state changes
 *
 * @remark There is no guarantee that a state change actually took place.
 *
 * @returns 1 if a state change was signaled (maybe), else 0 (timeout)
 *
 * @locality any thread
 */
int rd_kafka_brokers_wait_state_change (rd_kafka_t *rk, int stored_version,
					int timeout_ms) {
	int r;
	mtx_lock(&rk->rk_broker_state_change_lock);
	if (stored_version != rk->rk_broker_state_change_version)
		r = 1;
	else
		r = cnd_timedwait_ms(&rk->rk_broker_state_change_cnd,
				     &rk->rk_broker_state_change_lock,
				     timeout_ms) == thrd_success;
	mtx_unlock(&rk->rk_broker_state_change_lock);
	return r;
}


/**
 * @brief Broadcast broker state change to listeners, if any.
 *
 * @locality any thread
 */
void rd_kafka_brokers_broadcast_state_change (rd_kafka_t *rk) {
	rd_kafka_dbg(rk, GENERIC, "BROADCAST",
		     "Broadcasting state change");
	mtx_lock(&rk->rk_broker_state_change_lock);
	rk->rk_broker_state_change_version++;
	cnd_broadcast(&rk->rk_broker_state_change_cnd);
	mtx_unlock(&rk->rk_broker_state_change_lock);
}


/**
 * Returns a random broker (with refcnt increased) in state 'state'.
 * Uses Reservoir sampling.
 *
 * 'filter' is an optional callback used to filter out undesired brokers.
 * The filter function should return 1 to filter out a broker, or 0 to keep it
 * in the list of eligible brokers to return.
 * rd_kafka_broker_lock() is held during the filter callback.
 *
 * Locks: rd_kafka_rdlock(rk) MUST be held.
 * Locality: any thread
 */
rd_kafka_broker_t *rd_kafka_broker_any (rd_kafka_t *rk, int state,
                                        int (*filter) (rd_kafka_broker_t *rkb,
                                                       void *opaque),
                                        void *opaque) {
	rd_kafka_broker_t *rkb, *good = NULL;
        int cnt = 0;

	TAILQ_FOREACH(rkb, &rk->rk_brokers, rkb_link) {
		rd_kafka_broker_lock(rkb);
		if ((int)rkb->rkb_state == state &&
                    (!filter || !filter(rkb, opaque))) {
                        if (cnt < 1 || rd_jitter(0, cnt) < 1) {
                                if (good)
                                        rd_kafka_broker_destroy(good);
                                rd_kafka_broker_keep(rkb);
                                good = rkb;
                        }
                        cnt += 1;
                }
		rd_kafka_broker_unlock(rkb);
	}

        return good;
}


/**
 * @brief Spend at most \p timeout_ms to acquire a usable (Up && non-blocking)
 *        broker.
 *
 * @returns A probably usable broker with increased refcount, or NULL on timeout
 * @locks rd_kafka_*lock() if !do_lock
 * @locality any
 */
rd_kafka_broker_t *rd_kafka_broker_any_usable (rd_kafka_t *rk,
                                                int timeout_ms,
                                                int do_lock) {
	const rd_ts_t ts_end = rd_timeout_init(timeout_ms);

	while (1) {
		rd_kafka_broker_t *rkb;
		int remains;
		int version = rd_kafka_brokers_get_state_version(rk);

                /* Try non-blocking (e.g., non-fetching) brokers first. */
                if (do_lock)
                        rd_kafka_rdlock(rk);
                rkb = rd_kafka_broker_any(rk, RD_KAFKA_BROKER_STATE_UP,
                                          rd_kafka_broker_filter_non_blocking,
                                          NULL);
                if (!rkb)
                        rkb = rd_kafka_broker_any(rk, RD_KAFKA_BROKER_STATE_UP,
                                                  NULL, NULL);
                if (do_lock)
                        rd_kafka_rdunlock(rk);

                if (rkb)
                        return rkb;

		remains = rd_timeout_remains(ts_end);
		if (rd_timeout_expired(remains))
			return NULL;

		rd_kafka_brokers_wait_state_change(rk, version, remains);
	}

	return NULL;
}



/**
 * Returns a broker in state `state`, preferring the one with
 * matching `broker_id`.
 * Uses Reservoir sampling.
 *
 * Locks: rd_kafka_rdlock(rk) MUST be held.
 * Locality: any thread
 */
rd_kafka_broker_t *rd_kafka_broker_prefer (rd_kafka_t *rk, int32_t broker_id,
					   int state) {
	rd_kafka_broker_t *rkb, *good = NULL;
        int cnt = 0;

	TAILQ_FOREACH(rkb, &rk->rk_brokers, rkb_link) {
		rd_kafka_broker_lock(rkb);
		if ((int)rkb->rkb_state == state) {
                        if (broker_id != -1 && rkb->rkb_nodeid == broker_id) {
                                if (good)
                                        rd_kafka_broker_destroy(good);
                                rd_kafka_broker_keep(rkb);
                                good = rkb;
                                rd_kafka_broker_unlock(rkb);
                                break;
                        }
                        if (cnt < 1 || rd_jitter(0, cnt) < 1) {
                                if (good)
                                        rd_kafka_broker_destroy(good);
                                rd_kafka_broker_keep(rkb);
                                good = rkb;
                        }
                        cnt += 1;
                }
		rd_kafka_broker_unlock(rkb);
	}

        return good;
}






/**
 * Find a waitresp (rkbuf awaiting response) by the correlation id.
 */
static rd_kafka_buf_t *rd_kafka_waitresp_find (rd_kafka_broker_t *rkb,
					       int32_t corrid) {
	rd_kafka_buf_t *rkbuf;
	rd_ts_t now = rd_clock();

	rd_kafka_assert(rkb->rkb_rk, thrd_is_current(rkb->rkb_thread));

	TAILQ_FOREACH(rkbuf, &rkb->rkb_waitresps.rkbq_bufs, rkbuf_link)
		if (rkbuf->rkbuf_corrid == corrid) {
			/* Convert ts_sent to RTT */
			rkbuf->rkbuf_ts_sent = now - rkbuf->rkbuf_ts_sent;
			rd_avg_add(&rkb->rkb_avg_rtt, rkbuf->rkbuf_ts_sent);

                        if (rkbuf->rkbuf_flags & RD_KAFKA_OP_F_BLOCKING &&
			    rd_atomic32_sub(&rkb->rkb_blocking_request_cnt,
					    1) == 1)
				rd_kafka_brokers_broadcast_state_change(
					rkb->rkb_rk);

			rd_kafka_bufq_deq(&rkb->rkb_waitresps, rkbuf);
			return rkbuf;
		}
	return NULL;
}




/**
 * Map a response message to a request.
 */
static int rd_kafka_req_response (rd_kafka_broker_t *rkb,
				  rd_kafka_buf_t *rkbuf) {
	rd_kafka_buf_t *req;

	rd_kafka_assert(rkb->rkb_rk, thrd_is_current(rkb->rkb_thread));


	/* Find corresponding request message by correlation id */
	if (unlikely(!(req =
		       rd_kafka_waitresp_find(rkb,
					      rkbuf->rkbuf_reshdr.CorrId)))) {
		/* unknown response. probably due to request timeout */
                rd_atomic64_add(&rkb->rkb_c.rx_corrid_err, 1);
		rd_rkb_dbg(rkb, BROKER, "RESPONSE",
			   "Response for unknown CorrId %"PRId32" (timed out?)",
			   rkbuf->rkbuf_reshdr.CorrId);
                rd_kafka_buf_destroy(rkbuf);
                return -1;
	}

	rd_rkb_dbg(rkb, PROTOCOL, "RECV",
		   "Received %sResponse (v%hd, %"PRIusz" bytes, CorrId %"PRId32
		   ", rtt %.2fms)",
		   rd_kafka_ApiKey2str(req->rkbuf_reqhdr.ApiKey),
                   req->rkbuf_reqhdr.ApiVersion,
		   rkbuf->rkbuf_totlen, rkbuf->rkbuf_reshdr.CorrId,
		   (float)req->rkbuf_ts_sent / 1000.0f);

        /* Set up response reader slice starting past the response header */
        rd_slice_init(&rkbuf->rkbuf_reader, &rkbuf->rkbuf_buf,
                      RD_KAFKAP_RESHDR_SIZE,
                      rd_buf_len(&rkbuf->rkbuf_buf) - RD_KAFKAP_RESHDR_SIZE);

        if (!rkbuf->rkbuf_rkb) {
                rkbuf->rkbuf_rkb = rkb;
                rd_kafka_broker_keep(rkbuf->rkbuf_rkb);
        } else
                rd_assert(rkbuf->rkbuf_rkb == rkb);

	/* Call callback. */
        rd_kafka_buf_callback(rkb->rkb_rk, rkb, 0, rkbuf, req);

	return 0;
}




int rd_kafka_recv (rd_kafka_broker_t *rkb) {
	rd_kafka_buf_t *rkbuf;
	ssize_t r;
        /* errstr is not set by buf_read errors, so default it here. */
        char errstr[512] = "Protocol parse failure";
        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR_NO_ERROR;
	const int log_decode_errors = LOG_ERR;


        /* It is impossible to estimate the correct size of the response
         * so we split the read up in two parts: first we read the protocol
         * length and correlation id (i.e., the Response header), and then
         * when we know the full length of the response we allocate a new
         * buffer and call receive again.
         * All this in an async fashion (e.g., partial reads).
         */
	if (!(rkbuf = rkb->rkb_recv_buf)) {
		/* No receive in progress: create new buffer */

                rkbuf = rd_kafka_buf_new(2, RD_KAFKAP_RESHDR_SIZE);

		rkb->rkb_recv_buf = rkbuf;

                /* Set up buffer reader for the response header. */
                rd_buf_write_ensure(&rkbuf->rkbuf_buf,
                                    RD_KAFKAP_RESHDR_SIZE,
                                    RD_KAFKAP_RESHDR_SIZE);
        }

        rd_dassert(rd_buf_write_remains(&rkbuf->rkbuf_buf) > 0);

        r = rd_kafka_transport_recv(rkb->rkb_transport, &rkbuf->rkbuf_buf,
                                    errstr, sizeof(errstr));
        if (unlikely(r <= 0)) {
                if (r == 0)
                        return 0; /* EAGAIN */
                err = RD_KAFKA_RESP_ERR__TRANSPORT;
                rd_atomic64_add(&rkb->rkb_c.rx_err, 1);
                goto err;
        }

	if (rkbuf->rkbuf_totlen == 0) {
		/* Packet length not known yet. */

                if (unlikely(rd_buf_write_pos(&rkbuf->rkbuf_buf) <
                             RD_KAFKAP_RESHDR_SIZE)) {
			/* Need response header for packet length and corrid.
			 * Wait for more data. */ 
			return 0;
		}

                rd_assert(!rkbuf->rkbuf_rkb);
                rkbuf->rkbuf_rkb = rkb; /* Protocol parsing code needs
                                         * the rkb for logging, but we dont
                                         * want to keep a reference to the
                                         * broker this early since that extra
                                         * refcount will mess with the broker's
                                         * refcount-based termination code. */

                /* Initialize reader */
                rd_slice_init(&rkbuf->rkbuf_reader, &rkbuf->rkbuf_buf, 0,
                              RD_KAFKAP_RESHDR_SIZE);

		/* Read protocol header */
		rd_kafka_buf_read_i32(rkbuf, &rkbuf->rkbuf_reshdr.Size);
		rd_kafka_buf_read_i32(rkbuf, &rkbuf->rkbuf_reshdr.CorrId);

                rkbuf->rkbuf_rkb = NULL; /* Reset */

		rkbuf->rkbuf_totlen = rkbuf->rkbuf_reshdr.Size;

		/* Make sure message size is within tolerable limits. */
		if (rkbuf->rkbuf_totlen < 4/*CorrId*/ ||
		    rkbuf->rkbuf_totlen >
		    (size_t)rkb->rkb_rk->rk_conf.recv_max_msg_size) {
                        rd_snprintf(errstr, sizeof(errstr),
                                    "Invalid response size %"PRId32" (0..%i): "
                                    "increase receive.message.max.bytes",
                                    rkbuf->rkbuf_reshdr.Size,
                                    rkb->rkb_rk->rk_conf.recv_max_msg_size);
                        err = RD_KAFKA_RESP_ERR__BAD_MSG;
			rd_atomic64_add(&rkb->rkb_c.rx_err, 1);
			goto err;
		}

		rkbuf->rkbuf_totlen -= 4; /*CorrId*/

		if (rkbuf->rkbuf_totlen > 0) {
			/* Allocate another buffer that fits all data (short of
			 * the common response header). We want all
			 * data to be in contigious memory. */

                        rd_buf_write_ensure_contig(&rkbuf->rkbuf_buf,
                                                   rkbuf->rkbuf_totlen);
		}
	}

        if (rd_buf_write_pos(&rkbuf->rkbuf_buf) - RD_KAFKAP_RESHDR_SIZE ==
            rkbuf->rkbuf_totlen) {
		/* Message is complete, pass it on to the original requester. */
		rkb->rkb_recv_buf = NULL;
                rd_atomic64_add(&rkb->rkb_c.rx, 1);
                rd_atomic64_add(&rkb->rkb_c.rx_bytes,
                                rd_buf_write_pos(&rkbuf->rkbuf_buf));
		rd_kafka_req_response(rkb, rkbuf);
	}

	return 1;

 err_parse:
        err = rkbuf->rkbuf_err;
 err:
	rd_kafka_broker_fail(rkb,
                             !rkb->rkb_rk->rk_conf.log_connection_close &&
                             !strcmp(errstr, "Disconnected") ?
                             LOG_DEBUG : LOG_ERR, err,
                             "Receive failed: %s", errstr);
	return -1;
}


/**
 * Linux version of socket_cb providing racefree CLOEXEC.
 */
int rd_kafka_socket_cb_linux (int domain, int type, int protocol,
                              void *opaque) {
#ifdef SOCK_CLOEXEC
        return socket(domain, type | SOCK_CLOEXEC, protocol);
#else
        return rd_kafka_socket_cb_generic(domain, type, protocol, opaque);
#endif
}

/**
 * Fallback version of socket_cb NOT providing racefree CLOEXEC,
 * but setting CLOEXEC after socket creation (if FD_CLOEXEC is defined).
 */
int rd_kafka_socket_cb_generic (int domain, int type, int protocol,
                                void *opaque) {
        int s;
        int on = 1;
        s = (int)socket(domain, type, protocol);
        if (s == -1)
                return -1;
#ifdef FD_CLOEXEC
        fcntl(s, F_SETFD, FD_CLOEXEC, &on);
#endif
        return s;
}


/**
 * Initiate asynchronous connection attempt to the next address
 * in the broker's address list.
 * While the connect is asynchronous and its IO served in the CONNECT state,
 * the initial name resolve is blocking.
 *
 * Returns -1 on error, else 0.
 */
static int rd_kafka_broker_connect (rd_kafka_broker_t *rkb) {
	const rd_sockaddr_inx_t *sinx;
	char errstr[512];

	rd_rkb_dbg(rkb, BROKER, "CONNECT",
		"broker in state %s connecting",
		rd_kafka_broker_state_names[rkb->rkb_state]);

	if (rd_kafka_broker_resolve(rkb) == -1)
		return -1;

	sinx = rd_sockaddr_list_next(rkb->rkb_rsal);

	rd_kafka_assert(rkb->rkb_rk, !rkb->rkb_transport);

	if (!(rkb->rkb_transport = rd_kafka_transport_connect(rkb, sinx,
		errstr, sizeof(errstr)))) {
		/* Avoid duplicate log messages */
		if (rkb->rkb_err.err == errno)
			rd_kafka_broker_fail(rkb, LOG_DEBUG,
                                             RD_KAFKA_RESP_ERR__FAIL, NULL);
		else
			rd_kafka_broker_fail(rkb, LOG_ERR,
                                             RD_KAFKA_RESP_ERR__TRANSPORT,
					     "%s", errstr);
		return -1;
	}

	rd_kafka_broker_lock(rkb);
	rd_kafka_broker_set_state(rkb, RD_KAFKA_BROKER_STATE_CONNECT);
	rd_kafka_broker_unlock(rkb);

	return 0;
}


/**
 * @brief Call when connection is ready to transition to fully functional
 *        UP state.
 *
 * @locality Broker thread
 */
void rd_kafka_broker_connect_up (rd_kafka_broker_t *rkb) {

	rkb->rkb_max_inflight = rkb->rkb_rk->rk_conf.max_inflight;
        rkb->rkb_err.err = 0;

	rd_kafka_broker_lock(rkb);
	rd_kafka_broker_set_state(rkb, RD_KAFKA_BROKER_STATE_UP);
	rd_kafka_broker_unlock(rkb);

        /* Request metadata (async):
         * try locally known topics first and if there are none try
         * getting just the broker list. */
        if (rd_kafka_metadata_refresh_known_topics(NULL, rkb, 0/*dont force*/,
                                                   "connected") ==
            RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC)
                rd_kafka_metadata_refresh_brokers(NULL, rkb, "connected");
}



static void rd_kafka_broker_connect_auth (rd_kafka_broker_t *rkb);


/**
 * @brief Parses and handles SaslMechanism response, transitions
 *        the broker state.
 *
 */
static void
rd_kafka_broker_handle_SaslHandshake (rd_kafka_t *rk,
				      rd_kafka_broker_t *rkb,
				      rd_kafka_resp_err_t err,
				      rd_kafka_buf_t *rkbuf,
				      rd_kafka_buf_t *request,
				      void *opaque) {
        const int log_decode_errors = LOG_ERR;
	int32_t MechCnt;
	int16_t ErrorCode;
	int i = 0;
	char *mechs = "(n/a)";
	size_t msz, mof = 0;

	if (err == RD_KAFKA_RESP_ERR__DESTROY)
		return;

        if (err)
                goto err;

	rd_kafka_buf_read_i16(rkbuf, &ErrorCode);
        rd_kafka_buf_read_i32(rkbuf, &MechCnt);

	/* Build a CSV string of supported mechanisms. */
	msz = RD_MIN(511, MechCnt * 32);
	mechs = rd_alloca(msz);
	*mechs = '\0';

	for (i = 0 ; i < MechCnt ; i++) {
		rd_kafkap_str_t mech;
		rd_kafka_buf_read_str(rkbuf, &mech);

		mof += rd_snprintf(mechs+mof, msz-mof, "%s%.*s",
				   i ? ",":"", RD_KAFKAP_STR_PR(&mech));

		if (mof >= msz)
			break;
        }

	rd_rkb_dbg(rkb,
		   PROTOCOL | RD_KAFKA_DBG_SECURITY | RD_KAFKA_DBG_BROKER,
		   "SASLMECHS", "Broker supported SASL mechanisms: %s",
		   mechs);

	if (ErrorCode) {
		err = ErrorCode;
		goto err;
	}

	/* Circle back to connect_auth() to start proper AUTH state. */
	rd_kafka_broker_connect_auth(rkb);
	return;

 err_parse:
        err = rkbuf->rkbuf_err;
 err:
	rd_kafka_broker_fail(rkb, LOG_ERR,
			     RD_KAFKA_RESP_ERR__AUTHENTICATION,
			     "SASL %s mechanism handshake failed: %s: "
			     "broker's supported mechanisms: %s",
                             rkb->rkb_rk->rk_conf.sasl.mechanisms,
			     rd_kafka_err2str(err), mechs);
}


/**
 * @brief Transition state to:
 *        - AUTH_HANDSHAKE (if SASL is configured and handshakes supported)
 *        - AUTH (if SASL is configured but no handshake is required or
 *                not supported, or has already taken place.)
 *        - UP (if SASL is not configured)
 */
static void rd_kafka_broker_connect_auth (rd_kafka_broker_t *rkb) {

	if ((rkb->rkb_proto == RD_KAFKA_PROTO_SASL_PLAINTEXT ||
	     rkb->rkb_proto == RD_KAFKA_PROTO_SASL_SSL)) {

		rd_rkb_dbg(rkb, SECURITY | RD_KAFKA_DBG_BROKER, "AUTH",
			   "Auth in state %s (handshake %ssupported)",
			   rd_kafka_broker_state_names[rkb->rkb_state],
			   (rkb->rkb_features&RD_KAFKA_FEATURE_SASL_HANDSHAKE)
			   ? "" : "not ");

		/* Broker >= 0.10.0: send request to select mechanism */
		if (rkb->rkb_state != RD_KAFKA_BROKER_STATE_AUTH_HANDSHAKE &&
		    (rkb->rkb_features & RD_KAFKA_FEATURE_SASL_HANDSHAKE)) {

			rd_kafka_broker_lock(rkb);
			rd_kafka_broker_set_state(
				rkb, RD_KAFKA_BROKER_STATE_AUTH_HANDSHAKE);
			rd_kafka_broker_unlock(rkb);

			rd_kafka_SaslHandshakeRequest(
				rkb, rkb->rkb_rk->rk_conf.sasl.mechanisms,
				RD_KAFKA_NO_REPLYQ,
				rd_kafka_broker_handle_SaslHandshake,
				NULL, 1 /* flash */);

		} else {
			/* Either Handshake succeeded (protocol selected)
			 * or Handshakes were not supported.
			 * In both cases continue with authentication. */
			char sasl_errstr[512];

			rd_kafka_broker_lock(rkb);
			rd_kafka_broker_set_state(rkb,
						  RD_KAFKA_BROKER_STATE_AUTH);
			rd_kafka_broker_unlock(rkb);

			if (rd_kafka_sasl_client_new(
				    rkb->rkb_transport, sasl_errstr,
				    sizeof(sasl_errstr)) == -1) {
				errno = EINVAL;
				rd_kafka_broker_fail(
					rkb, LOG_ERR,
					RD_KAFKA_RESP_ERR__AUTHENTICATION,
					"Failed to initialize "
					"SASL authentication: %s",
					sasl_errstr);
				return;
			}

			/* Enter non-Kafka-protocol-framed SASL communication
			 * state handled in rdkafka_sasl.c */
			rd_kafka_broker_lock(rkb);
			rd_kafka_broker_set_state(rkb,
						  RD_KAFKA_BROKER_STATE_AUTH);
			rd_kafka_broker_unlock(rkb);
		}

		return;
	}

	/* No authentication required. */
	rd_kafka_broker_connect_up(rkb);
}


/**
 * @brief Specify API versions to use for this connection.
 *
 * @param apis is an allocated list of supported partitions.
 *        If NULL the default set will be used based on the
 *        \p broker.version.fallback property.
 * @param api_cnt number of elements in \p apis
 *
 * @remark \p rkb takes ownership of \p apis.
 *
 * @locality Broker thread
 * @locks none
 */
static void rd_kafka_broker_set_api_versions (rd_kafka_broker_t *rkb,
					      struct rd_kafka_ApiVersion *apis,
					      size_t api_cnt) {

        rd_kafka_broker_lock(rkb);

	if (rkb->rkb_ApiVersions)
		rd_free(rkb->rkb_ApiVersions);


	if (!apis) {
		rd_rkb_dbg(rkb, PROTOCOL | RD_KAFKA_DBG_BROKER, "APIVERSION",
			   "Using (configuration fallback) %s protocol features",
			   rkb->rkb_rk->rk_conf.broker_version_fallback);


		rd_kafka_get_legacy_ApiVersions(rkb->rkb_rk->rk_conf.
						broker_version_fallback,
						&apis, &api_cnt,
						rkb->rkb_rk->rk_conf.
						broker_version_fallback);

		/* Make a copy to store on broker. */
		rd_kafka_ApiVersions_copy(apis, api_cnt, &apis, &api_cnt);
	}

	rkb->rkb_ApiVersions = apis;
	rkb->rkb_ApiVersions_cnt = api_cnt;

	/* Update feature set based on supported broker APIs. */
	rd_kafka_broker_features_set(rkb,
				     rd_kafka_features_check(rkb, apis, api_cnt));

        rd_kafka_broker_unlock(rkb);
}


/**
 * Handler for ApiVersion response.
 */
static void
rd_kafka_broker_handle_ApiVersion (rd_kafka_t *rk,
				   rd_kafka_broker_t *rkb,
				   rd_kafka_resp_err_t err,
				   rd_kafka_buf_t *rkbuf,
				   rd_kafka_buf_t *request, void *opaque) {
	struct rd_kafka_ApiVersion *apis;
	size_t api_cnt;

	if (err == RD_KAFKA_RESP_ERR__DESTROY)
		return;

	err = rd_kafka_handle_ApiVersion(rk, rkb, err, rkbuf, request,
					 &apis, &api_cnt);

	if (err) {
		rd_kafka_broker_fail(rkb, LOG_DEBUG,
				     RD_KAFKA_RESP_ERR__NOT_IMPLEMENTED,
				     "ApiVersionRequest failed: %s: "
				     "probably due to old broker version",
				     rd_kafka_err2str(err));
		return;
	}

	rd_kafka_broker_set_api_versions(rkb, apis, api_cnt);

	rd_kafka_broker_connect_auth(rkb);
}


/**
 * Call when asynchronous connection attempt completes, either succesfully
 * (if errstr is NULL) or fails.
 *
 * Locality: broker thread
 */
void rd_kafka_broker_connect_done (rd_kafka_broker_t *rkb, const char *errstr) {

	if (errstr) {
		/* Connect failed */
                rd_kafka_broker_fail(rkb,
                                     errno != 0 && rkb->rkb_err.err == errno ?
                                     LOG_DEBUG : LOG_ERR,
                                     RD_KAFKA_RESP_ERR__TRANSPORT,
                                     "%s", errstr);
		return;
	}

	/* Connect succeeded */
	rkb->rkb_connid++;
	rd_rkb_dbg(rkb, BROKER | RD_KAFKA_DBG_PROTOCOL,
		   "CONNECTED", "Connected (#%d)", rkb->rkb_connid);
	rkb->rkb_err.err = 0;
	rkb->rkb_max_inflight = 1; /* Hold back other requests until
				    * ApiVersion, SaslHandshake, etc
				    * are done. */

	rd_kafka_transport_poll_set(rkb->rkb_transport, POLLIN);

	if (rkb->rkb_rk->rk_conf.api_version_request &&
	    rd_interval_immediate(&rkb->rkb_ApiVersion_fail_intvl, 0, 0) > 0) {
		/* Use ApiVersion to query broker for supported API versions. */
		rd_kafka_broker_feature_enable(rkb, RD_KAFKA_FEATURE_APIVERSION);
	}

        if (!(rkb->rkb_features & RD_KAFKA_FEATURE_APIVERSION)) {
                /* Use configured broker.version.fallback to
                 * figure out API versions.
                 * In case broker.version.fallback indicates a version
                 * that supports ApiVersionRequest it will update
                 * rkb_features to have FEATURE_APIVERSION set which will
                 * trigger an ApiVersionRequest below. */
                rd_kafka_broker_set_api_versions(rkb, NULL, 0);
        }

	if (rkb->rkb_features & RD_KAFKA_FEATURE_APIVERSION) {
		/* Query broker for supported API versions.
		 * This may fail with a disconnect on non-supporting brokers
		 * so hold off any other requests until we get a response,
		 * and if the connection is torn down we disable this feature. */
		rd_kafka_broker_lock(rkb);
		rd_kafka_broker_set_state(rkb,RD_KAFKA_BROKER_STATE_APIVERSION_QUERY);
		rd_kafka_broker_unlock(rkb);

		rd_kafka_ApiVersionRequest(
			rkb, RD_KAFKA_NO_REPLYQ,
			rd_kafka_broker_handle_ApiVersion, NULL,
			1 /*Flash message: prepend to transmit queue*/);
	} else {
		/* Authenticate if necessary */
		rd_kafka_broker_connect_auth(rkb);
	}

}



/**
 * @brief Checks if the given API request+version is supported by the broker.
 * @returns 1 if supported, else 0.
 * @locality broker thread
 * @locks none
 */
static RD_INLINE int
rd_kafka_broker_request_supported (rd_kafka_broker_t *rkb,
                                   rd_kafka_buf_t *rkbuf) {
        struct rd_kafka_ApiVersion skel = {
                .ApiKey = rkbuf->rkbuf_reqhdr.ApiKey
        };
        struct rd_kafka_ApiVersion *ret;

        if (unlikely(rkbuf->rkbuf_reqhdr.ApiKey == RD_KAFKAP_ApiVersion))
                return 1; /* ApiVersion requests are used to detect
                           * the supported API versions, so should always
                           * be allowed through. */

        /* First try feature flags, if any, which may cover a larger
         * set of APIs. */
        if (rkbuf->rkbuf_features)
                return (rkb->rkb_features & rkbuf->rkbuf_features) ==
                        rkbuf->rkbuf_features;

        /* Then try the ApiVersion map. */
        ret = bsearch(&skel, rkb->rkb_ApiVersions, rkb->rkb_ApiVersions_cnt,
                      sizeof(*rkb->rkb_ApiVersions),
                      rd_kafka_ApiVersion_key_cmp);
        if (!ret)
                return 0;

        return ret->MinVer <= rkbuf->rkbuf_reqhdr.ApiVersion &&
                rkbuf->rkbuf_reqhdr.ApiVersion <= ret->MaxVer;
}


/**
 * Send queued messages to broker
 *
 * Locality: io thread
 */
int rd_kafka_send (rd_kafka_broker_t *rkb) {
	rd_kafka_buf_t *rkbuf;
	unsigned int cnt = 0;

	rd_kafka_assert(rkb->rkb_rk, thrd_is_current(rkb->rkb_thread));

	while (rkb->rkb_state >= RD_KAFKA_BROKER_STATE_UP &&
	       rd_kafka_bufq_cnt(&rkb->rkb_waitresps) < rkb->rkb_max_inflight &&
	       (rkbuf = TAILQ_FIRST(&rkb->rkb_outbufs.rkbq_bufs))) {
		ssize_t r;
                size_t pre_of = rd_slice_offset(&rkbuf->rkbuf_reader);

                /* Check for broker support */
                if (unlikely(!rd_kafka_broker_request_supported(rkb, rkbuf))) {
                        rd_kafka_bufq_deq(&rkb->rkb_outbufs, rkbuf);
                        rd_rkb_dbg(rkb, BROKER | RD_KAFKA_DBG_PROTOCOL,
                                   "UNSUPPORTED",
                                   "Failing %sResponse "
                                   "(v%hd, %"PRIusz" bytes, CorrId %"PRId32"): "
                                   "request not supported by broker "
                                   "(missing api.version.request or "
                                   "incorrect broker.version.fallback config?)",
                                   rd_kafka_ApiKey2str(rkbuf->rkbuf_reqhdr.
                                                       ApiKey),
                                   rkbuf->rkbuf_reqhdr.ApiVersion,
                                   rkbuf->rkbuf_totlen,
                                   rkbuf->rkbuf_reshdr.CorrId);
                        rd_kafka_buf_callback(
                                rkb->rkb_rk, rkb,
                                RD_KAFKA_RESP_ERR__UNSUPPORTED_FEATURE,
                                NULL, rkbuf);
                        continue;
                }

		/* Set CorrId header field, unless this is the latter part
		 * of a partial send in which case the corrid has already
		 * been set.
		 * Due to how SSL_write() will accept a buffer but still
		 * return 0 in some cases we can't rely on the buffer offset
		 * but need to use corrid to check this. SSL_write() expects
		 * us to send the same buffer again when 0 is returned.
		 */
		if (rkbuf->rkbuf_corrid == 0 ||
		    rkbuf->rkbuf_connid != rkb->rkb_connid) {
                        rd_assert(rd_slice_offset(&rkbuf->rkbuf_reader) == 0);
			rkbuf->rkbuf_corrid = ++rkb->rkb_corrid;
			rd_kafka_buf_update_i32(rkbuf, 4+2+2,
						rkbuf->rkbuf_corrid);
			rkbuf->rkbuf_connid = rkb->rkb_connid;
		} else if (pre_of > RD_KAFKAP_REQHDR_SIZE) {
			rd_kafka_assert(NULL,
					rkbuf->rkbuf_connid == rkb->rkb_connid);
                }

		if (0) {
			rd_rkb_dbg(rkb, PROTOCOL, "SEND",
				   "Send %s corrid %"PRId32" at "
				   "offset %"PRIusz"/%"PRIusz,
				   rd_kafka_ApiKey2str(rkbuf->rkbuf_reqhdr.
						       ApiKey),
				   rkbuf->rkbuf_corrid,
                                   pre_of, rd_slice_size(&rkbuf->rkbuf_reader));
		}

                if ((r = rd_kafka_broker_send(rkb, &rkbuf->rkbuf_reader)) == -1)
                        return -1;

                /* Partial send? Continue next time. */
                if (rd_slice_remains(&rkbuf->rkbuf_reader) > 0) {
                        rd_rkb_dbg(rkb, PROTOCOL, "SEND",
                                   "Sent partial %sRequest "
                                   "(v%hd, "
                                   "%"PRIdsz"+%"PRIdsz"/%"PRIusz" bytes, "
                                   "CorrId %"PRId32")",
                                   rd_kafka_ApiKey2str(rkbuf->rkbuf_reqhdr.
                                                       ApiKey),
                                   rkbuf->rkbuf_reqhdr.ApiVersion,
                                   (ssize_t)pre_of, r,
                                   rd_slice_size(&rkbuf->rkbuf_reader),
                                   rkbuf->rkbuf_corrid);
                        return 0;
                }

		rd_rkb_dbg(rkb, PROTOCOL, "SEND",
			   "Sent %sRequest (v%hd, %"PRIusz" bytes @ %"PRIusz", "
			   "CorrId %"PRId32")",
			   rd_kafka_ApiKey2str(rkbuf->rkbuf_reqhdr.ApiKey),
                           rkbuf->rkbuf_reqhdr.ApiVersion,
                           rd_slice_size(&rkbuf->rkbuf_reader),
                           pre_of, rkbuf->rkbuf_corrid);

                /* Notify transport layer of full request sent */
                if (likely(rkb->rkb_transport != NULL))
                        rd_kafka_transport_request_sent(rkb, rkbuf);

		/* Entire buffer sent, unlink from outbuf */
		rd_kafka_bufq_deq(&rkb->rkb_outbufs, rkbuf);

		/* Store time for RTT calculation */
		rkbuf->rkbuf_ts_sent = rd_clock();

                if (rkbuf->rkbuf_flags & RD_KAFKA_OP_F_BLOCKING &&
		    rd_atomic32_add(&rkb->rkb_blocking_request_cnt, 1) == 1)
			rd_kafka_brokers_broadcast_state_change(rkb->rkb_rk);

		/* Put buffer on response wait list unless we are not
		 * expecting a response (required_acks=0). */
		if (!(rkbuf->rkbuf_flags & RD_KAFKA_OP_F_NO_RESPONSE))
			rd_kafka_bufq_enq(&rkb->rkb_waitresps, rkbuf);
		else { /* Call buffer callback for delivery report. */
                        rd_kafka_buf_callback(rkb->rkb_rk, rkb, 0, NULL, rkbuf);
                }

		cnt++;
	}

	return cnt;
}


/**
 * Add 'rkbuf' to broker 'rkb's retry queue.
 */
void rd_kafka_broker_buf_retry (rd_kafka_broker_t *rkb, rd_kafka_buf_t *rkbuf) {

        /* Restore original replyq since replyq.q will have been NULLed
         * by buf_callback()/replyq_enq(). */
        if (!rkbuf->rkbuf_replyq.q && rkbuf->rkbuf_orig_replyq.q) {
                rkbuf->rkbuf_replyq = rkbuf->rkbuf_orig_replyq;
                rd_kafka_replyq_clear(&rkbuf->rkbuf_orig_replyq);
        }

        /* If called from another thread than rkb's broker thread
         * enqueue the buffer on the broker's op queue. */
        if (!thrd_is_current(rkb->rkb_thread)) {
                rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_XMIT_RETRY);
                rko->rko_u.xbuf.rkbuf = rkbuf;
                rd_kafka_q_enq(rkb->rkb_ops, rko);
                return;
        }

        rd_rkb_dbg(rkb, PROTOCOL, "RETRY",
                   "Retrying %sRequest (v%hd, %"PRIusz" bytes, retry %d/%d, "
                   "prev CorrId %"PRId32") in %dms",
                   rd_kafka_ApiKey2str(rkbuf->rkbuf_reqhdr.ApiKey),
                   rkbuf->rkbuf_reqhdr.ApiVersion,
                   rd_slice_size(&rkbuf->rkbuf_reader),
                   rkbuf->rkbuf_retries, rkb->rkb_rk->rk_conf.max_retries,
                   rkbuf->rkbuf_corrid,
                   rkb->rkb_rk->rk_conf.retry_backoff_ms);

	rd_atomic64_add(&rkb->rkb_c.tx_retries, 1);

	rkbuf->rkbuf_ts_retry = rd_clock() +
		(rkb->rkb_rk->rk_conf.retry_backoff_ms * 1000);
        /* Precaution: time out the request if it hasn't moved from the
         * retry queue within the retry interval (such as when the broker is
         * down). */
        // FIXME: implememt this properly.
        rkbuf->rkbuf_ts_timeout = rkbuf->rkbuf_ts_retry + (5*1000*1000);

        /* Reset send offset */
        rd_slice_seek(&rkbuf->rkbuf_reader, 0);
	rkbuf->rkbuf_corrid = 0;

	rd_kafka_bufq_enq(&rkb->rkb_retrybufs, rkbuf);
}


/**
 * Move buffers that have expired their retry backoff time from the 
 * retry queue to the outbuf.
 */
static void rd_kafka_broker_retry_bufs_move (rd_kafka_broker_t *rkb) {
	rd_ts_t now = rd_clock();
	rd_kafka_buf_t *rkbuf;
        int cnt = 0;

	while ((rkbuf = TAILQ_FIRST(&rkb->rkb_retrybufs.rkbq_bufs))) {
		if (rkbuf->rkbuf_ts_retry > now)
			break;

		rd_kafka_bufq_deq(&rkb->rkb_retrybufs, rkbuf);

		rd_kafka_broker_buf_enq0(rkb, rkbuf, 0/*tail*/);
                cnt++;
	}

        if (cnt > 0)
                rd_rkb_dbg(rkb, BROKER, "RETRY",
                           "Moved %d retry buffer(s) to output queue", cnt);
}


/**
 * Propagate delivery report for entire message queue.
 */
void rd_kafka_dr_msgq (rd_kafka_itopic_t *rkt,
		       rd_kafka_msgq_t *rkmq, rd_kafka_resp_err_t err) {
        rd_kafka_t *rk = rkt->rkt_rk;

	if (unlikely(rd_kafka_msgq_len(rkmq) == 0))
	    return;

        /* Call on_acknowledgement() interceptors */
        rd_kafka_interceptors_on_acknowledgement_queue(rk, rkmq);

        if ((rk->rk_conf.enabled_events & RD_KAFKA_EVENT_DR) &&
	    (!rk->rk_conf.dr_err_only || err)) {
		/* Pass all messages to application thread in one op. */
		rd_kafka_op_t *rko;

		rko = rd_kafka_op_new(RD_KAFKA_OP_DR);
		rko->rko_err = err;
		rko->rko_u.dr.s_rkt = rd_kafka_topic_keep(rkt);
		rd_kafka_msgq_init(&rko->rko_u.dr.msgq);

		/* Move all messages to op's msgq */
		rd_kafka_msgq_move(&rko->rko_u.dr.msgq, rkmq);

		rd_kafka_q_enq(rk->rk_rep, rko);

	} else {
		/* No delivery report callback. */

                /* Destroy the messages right away. */
                rd_kafka_msgq_purge(rk, rkmq);
	}
}











/**
 * @brief Map and assign existing partitions to this broker using
 *        the leader-id.
 *
 * @locks none
 * @locality any
 */
static void rd_kafka_broker_map_partitions (rd_kafka_broker_t *rkb) {
        rd_kafka_t *rk = rkb->rkb_rk;
        rd_kafka_itopic_t *rkt;
        int cnt = 0;

        if (rkb->rkb_nodeid == -1)
                return;

        rd_kafka_rdlock(rk);
        TAILQ_FOREACH(rkt, &rk->rk_topics, rkt_link) {
                int i;

                rd_kafka_topic_wrlock(rkt);
                for (i = 0 ; i < rkt->rkt_partition_cnt ; i++) {
                        shptr_rd_kafka_toppar_t *s_rktp = rkt->rkt_p[i];
                        rd_kafka_toppar_t *rktp = rd_kafka_toppar_s2i(s_rktp);

                        /* Only map unassigned partitions matching this broker*/
                        rd_kafka_toppar_lock(rktp);
                        if (rktp->rktp_leader_id == rkb->rkb_nodeid &&
                            !(rktp->rktp_leader && rktp->rktp_next_leader)) {
                                rd_kafka_toppar_leader_update(
                                        rktp, rktp->rktp_leader_id, rkb);
                                cnt++;
                        }
                        rd_kafka_toppar_unlock(rktp);
                }
                rd_kafka_topic_wrunlock(rkt);
        }
        rd_kafka_rdunlock(rk);

        rd_rkb_dbg(rkb, TOPIC|RD_KAFKA_DBG_BROKER, "LEADER",
                   "Mapped %d partition(s) to broker", cnt);
}


/**
 * @brief Broker id comparator
 */
static int rd_kafka_broker_cmp_by_id (const void *_a, const void *_b) {
        const rd_kafka_broker_t *a = _a, *b = _b;
        return a->rkb_nodeid - b->rkb_nodeid;
}



/**
 * @brief Serve a broker op (an op posted by another thread to be handled by
 *        this broker's thread).
 *
 * @returns 0 if calling op loop should break out, else 1 to continue.
 * @locality broker thread
 * @locks none
 */
static int rd_kafka_broker_op_serve (rd_kafka_broker_t *rkb,
				      rd_kafka_op_t *rko) {
        shptr_rd_kafka_toppar_t *s_rktp;
        rd_kafka_toppar_t *rktp;
        int ret = 1;

	rd_kafka_assert(rkb->rkb_rk, thrd_is_current(rkb->rkb_thread));

	switch (rko->rko_type)
	{
        case RD_KAFKA_OP_NODE_UPDATE:
        {
                enum {
                        _UPD_NAME = 0x1,
                        _UPD_ID = 0x2
                } updated = 0;
                char brokername[RD_KAFKA_NODENAME_SIZE];

                /* Need kafka_wrlock for updating rk_broker_by_id */
                rd_kafka_wrlock(rkb->rkb_rk);
                rd_kafka_broker_lock(rkb);

                if (strcmp(rkb->rkb_nodename,
                           rko->rko_u.node.nodename)) {
                        rd_rkb_dbg(rkb, BROKER, "UPDATE",
                                   "Nodename changed from %s to %s",
                                   rkb->rkb_nodename,
                                   rko->rko_u.node.nodename);
                        strncpy(rkb->rkb_nodename,
                                rko->rko_u.node.nodename,
                                sizeof(rkb->rkb_nodename)-1);
                        updated |= _UPD_NAME;
                }

                if (rko->rko_u.node.nodeid != -1 &&
                    rko->rko_u.node.nodeid != rkb->rkb_nodeid) {
                        int32_t old_nodeid = rkb->rkb_nodeid;
                        rd_rkb_dbg(rkb, BROKER, "UPDATE",
                                   "NodeId changed from %"PRId32" to %"PRId32,
                                   rkb->rkb_nodeid,
                                   rko->rko_u.node.nodeid);

                        rkb->rkb_nodeid = rko->rko_u.node.nodeid;

                        /* Update system thread name */
                        rd_kafka_set_thread_sysname("rdk:broker%"PRId32,
                                                    rkb->rkb_nodeid);

                        /* Update broker_by_id sorted list */
                        if (old_nodeid == -1)
                                rd_list_add(&rkb->rkb_rk->rk_broker_by_id, rkb);
                        rd_list_sort(&rkb->rkb_rk->rk_broker_by_id,
                                     rd_kafka_broker_cmp_by_id);

                        updated |= _UPD_ID;
                }

                rd_kafka_mk_brokername(brokername, sizeof(brokername),
                                       rkb->rkb_proto,
				       rkb->rkb_nodename, rkb->rkb_nodeid,
				       RD_KAFKA_LEARNED);
                if (strcmp(rkb->rkb_name, brokername)) {
                        /* Udate the name copy used for logging. */
                        mtx_lock(&rkb->rkb_logname_lock);
                        rd_free(rkb->rkb_logname);
                        rkb->rkb_logname = rd_strdup(brokername);
                        mtx_unlock(&rkb->rkb_logname_lock);

                        rd_rkb_dbg(rkb, BROKER, "UPDATE",
                                   "Name changed from %s to %s",
                                   rkb->rkb_name, brokername);
                        strncpy(rkb->rkb_name, brokername,
                                sizeof(rkb->rkb_name)-1);
                }
                rd_kafka_broker_unlock(rkb);
                rd_kafka_wrunlock(rkb->rkb_rk);

                if (updated & _UPD_NAME)
                        rd_kafka_broker_fail(rkb, LOG_NOTICE,
                                             RD_KAFKA_RESP_ERR__NODE_UPDATE,
                                             "Broker hostname updated");
                else if (updated & _UPD_ID) {
                        /* Map existing partitions to this broker. */
                        rd_kafka_broker_map_partitions(rkb);

			/* If broker is currently in state up we need
			 * to trigger a state change so it exits its
			 * state&type based .._serve() loop. */
                        rd_kafka_broker_lock(rkb);
			if (rkb->rkb_state == RD_KAFKA_BROKER_STATE_UP)
				rd_kafka_broker_set_state(
					rkb, RD_KAFKA_BROKER_STATE_UPDATE);
                        rd_kafka_broker_unlock(rkb);
                }
                break;
        }

        case RD_KAFKA_OP_XMIT_BUF:
                rd_kafka_broker_buf_enq2(rkb, rko->rko_u.xbuf.rkbuf);
                rko->rko_u.xbuf.rkbuf = NULL; /* buffer now owned by broker */
                if (rko->rko_replyq.q) {
                        /* Op will be reused for forwarding response. */
                        rko = NULL;
                }
                break;

        case RD_KAFKA_OP_XMIT_RETRY:
                rd_kafka_broker_buf_retry(rkb, rko->rko_u.xbuf.rkbuf);
                rko->rko_u.xbuf.rkbuf = NULL;
                break;

        case RD_KAFKA_OP_PARTITION_JOIN:
                /*
		 * Add partition to broker toppars
		 */
                rktp = rd_kafka_toppar_s2i(rko->rko_rktp);
                rd_kafka_toppar_lock(rktp);

                /* Abort join if instance is terminating */
                if (rd_kafka_terminating(rkb->rkb_rk) ||
		    (rktp->rktp_flags & RD_KAFKA_TOPPAR_F_REMOVE)) {
                        rd_rkb_dbg(rkb, BROKER | RD_KAFKA_DBG_TOPIC, "TOPBRK",
                                   "Topic %s [%"PRId32"]: not joining broker: "
                                   "%s",
                                   rktp->rktp_rkt->rkt_topic->str,
                                   rktp->rktp_partition,
				   rd_kafka_terminating(rkb->rkb_rk) ?
				   "instance is terminating" :
				   "partition removed");

                        rd_kafka_broker_destroy(rktp->rktp_next_leader);
                        rktp->rktp_next_leader = NULL;
                        rd_kafka_toppar_unlock(rktp);
                        break;
                }

                /* See if we are still the next leader */
                if (rktp->rktp_next_leader != rkb) {
                        rd_rkb_dbg(rkb, BROKER | RD_KAFKA_DBG_TOPIC, "TOPBRK",
                                   "Topic %s [%"PRId32"]: not joining broker "
                                   "(next leader %s)",
                                   rktp->rktp_rkt->rkt_topic->str,
                                   rktp->rktp_partition,
                                   rktp->rktp_next_leader ?
                                   rd_kafka_broker_name(rktp->rktp_next_leader):
                                   "(none)");

                        /* Need temporary refcount so we can safely unlock
                         * after q_enq(). */
                        s_rktp = rd_kafka_toppar_keep(rktp);

                        /* No, forward this op to the new next leader. */
                        rd_kafka_q_enq(rktp->rktp_next_leader->rkb_ops, rko);
                        rko = NULL;

                        rd_kafka_toppar_unlock(rktp);
                        rd_kafka_toppar_destroy(s_rktp);

                        break;
                }

                rd_rkb_dbg(rkb, BROKER | RD_KAFKA_DBG_TOPIC, "TOPBRK",
                           "Topic %s [%"PRId32"]: joining broker (rktp %p)",
                           rktp->rktp_rkt->rkt_topic->str,
                           rktp->rktp_partition, rktp);

                rd_kafka_assert(NULL, rktp->rktp_s_for_rkb == NULL);
		rktp->rktp_s_for_rkb = rd_kafka_toppar_keep(rktp);
                rd_kafka_broker_lock(rkb);
		TAILQ_INSERT_TAIL(&rkb->rkb_toppars, rktp, rktp_rkblink);
		rkb->rkb_toppar_cnt++;
                rd_kafka_broker_unlock(rkb);
		rktp->rktp_leader = rkb;
                rktp->rktp_msgq_wakeup_fd = rkb->rkb_toppar_wakeup_fd;
                rd_kafka_broker_keep(rkb);

                if (rkb->rkb_rk->rk_type == RD_KAFKA_PRODUCER)
                        rd_kafka_broker_active_toppar_add(rkb, rktp);

                rd_kafka_broker_destroy(rktp->rktp_next_leader);
                rktp->rktp_next_leader = NULL;

                rd_kafka_toppar_unlock(rktp);

		rd_kafka_brokers_broadcast_state_change(rkb->rkb_rk);
                break;

        case RD_KAFKA_OP_PARTITION_LEAVE:
                /*
		 * Remove partition from broker toppars
		 */
                rktp = rd_kafka_toppar_s2i(rko->rko_rktp);

		rd_kafka_toppar_lock(rktp);

		/* Multiple PARTITION_LEAVEs are possible during partition
		 * migration, make sure we're supposed to handle this one. */
		if (unlikely(rktp->rktp_leader != rkb)) {
			rd_rkb_dbg(rkb, BROKER | RD_KAFKA_DBG_TOPIC, "TOPBRK",
				   "Topic %s [%"PRId32"]: "
				   "ignoring PARTITION_LEAVE: "
				   "broker is not leader (%s)",
				   rktp->rktp_rkt->rkt_topic->str,
				   rktp->rktp_partition,
				   rktp->rktp_leader ?
				   rd_kafka_broker_name(rktp->rktp_leader) :
				   "none");
			rd_kafka_toppar_unlock(rktp);
			break;
		}
		rd_kafka_toppar_unlock(rktp);

		/* Remove from fetcher list */
		rd_kafka_toppar_fetch_decide(rktp, rkb, 1/*force remove*/);

		rd_kafka_toppar_lock(rktp);

		rd_rkb_dbg(rkb, BROKER | RD_KAFKA_DBG_TOPIC, "TOPBRK",
			   "Topic %s [%"PRId32"]: leaving broker "
			   "(%d messages in xmitq, next leader %s, rktp %p)",
			   rktp->rktp_rkt->rkt_topic->str, rktp->rktp_partition,
			   rd_kafka_msgq_len(&rktp->rktp_xmit_msgq),
			   rktp->rktp_next_leader ?
			   rd_kafka_broker_name(rktp->rktp_next_leader) :
			   "(none)", rktp);

                /* Insert xmitq(broker-local) messages to the msgq(global)
                 * at their sorted position to maintain ordering. */
                rd_kafka_msgq_insert_msgq(&rktp->rktp_msgq,
                                          &rktp->rktp_xmit_msgq,
                                          rktp->rktp_rkt->rkt_conf.
                                          msg_order_cmp);

                if (rkb->rkb_rk->rk_type == RD_KAFKA_PRODUCER)
                        rd_kafka_broker_active_toppar_del(rkb, rktp);

                rd_kafka_broker_lock(rkb);
		TAILQ_REMOVE(&rkb->rkb_toppars, rktp, rktp_rkblink);
		rkb->rkb_toppar_cnt--;
                rd_kafka_broker_unlock(rkb);
                rd_kafka_broker_destroy(rktp->rktp_leader);
                rktp->rktp_msgq_wakeup_fd = -1;
		rktp->rktp_leader = NULL;

                /* Need to hold on to a refcount past q_enq() and
                 * unlock() below */
                s_rktp = rktp->rktp_s_for_rkb;
                rktp->rktp_s_for_rkb = NULL;

                if (rktp->rktp_next_leader) {
                        /* There is a next leader we need to migrate to. */
                        rko->rko_type = RD_KAFKA_OP_PARTITION_JOIN;
                        rd_kafka_q_enq(rktp->rktp_next_leader->rkb_ops, rko);
                        rko = NULL;
                } else {
			rd_rkb_dbg(rkb, BROKER | RD_KAFKA_DBG_TOPIC, "TOPBRK",
				   "Topic %s [%"PRId32"]: no next leader, "
				   "failing %d message(s) in partition queue",
				   rktp->rktp_rkt->rkt_topic->str,
				   rktp->rktp_partition,
				   rd_kafka_msgq_len(&rktp->rktp_msgq));
			rd_kafka_assert(NULL, rd_kafka_msgq_len(&rktp->rktp_xmit_msgq) == 0);
			rd_kafka_dr_msgq(rktp->rktp_rkt, &rktp->rktp_msgq,
					 rd_kafka_terminating(rkb->rkb_rk) ?
					 RD_KAFKA_RESP_ERR__DESTROY :
					 RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION);

		}

                rd_kafka_toppar_unlock(rktp);
                rd_kafka_toppar_destroy(s_rktp);

		rd_kafka_brokers_broadcast_state_change(rkb->rkb_rk);
                break;

        case RD_KAFKA_OP_TERMINATE:
                /* nop: just a wake-up. */
                if (rkb->rkb_blocking_max_ms > 1)
                        rkb->rkb_blocking_max_ms = 1; /* Speed up termination*/
                rd_rkb_dbg(rkb, BROKER, "TERM",
                           "Received TERMINATE op in state %s: "
                           "%d refcnts, %d toppar(s), %d active toppar(s), "
                           "%d outbufs, %d waitresps, %d retrybufs",
                           rd_kafka_broker_state_names[rkb->rkb_state],
                           rd_refcnt_get(&rkb->rkb_refcnt),
                           rkb->rkb_toppar_cnt, rkb->rkb_active_toppar_cnt,
                           (int)rd_kafka_bufq_cnt(&rkb->rkb_outbufs),
                           (int)rd_kafka_bufq_cnt(&rkb->rkb_waitresps),
                           (int)rd_kafka_bufq_cnt(&rkb->rkb_retrybufs));
                ret = 0;
                break;

        case RD_KAFKA_OP_WAKEUP:
                ret = 0;
                break;

        default:
                rd_kafka_assert(rkb->rkb_rk, !*"unhandled op type");
                break;
        }

        if (rko)
                rd_kafka_op_destroy(rko);

        return ret;
}



/**
 * @brief Serve broker ops.
 * @returns the number of ops served
 */
static int rd_kafka_broker_ops_serve (rd_kafka_broker_t *rkb, int timeout_ms) {
        rd_kafka_op_t *rko;
        int cnt = 0;

        while ((rko = rd_kafka_q_pop(rkb->rkb_ops, timeout_ms, 0)) &&
               (cnt++, rd_kafka_broker_op_serve(rkb, rko)))
                timeout_ms = RD_POLL_NOWAIT;

        return cnt;
}

/**
 * @brief Serve broker ops and IOs.
 *
 * @param abs_timeout Maximum block time (absolute time).
 *
 * @locality broker thread
 * @locks none
 */
static void rd_kafka_broker_serve (rd_kafka_broker_t *rkb,
                                   rd_ts_t abs_timeout) {
        rd_ts_t now;
        int initial_state = rkb->rkb_state;
        int remains_ms = rd_timeout_remains(abs_timeout);

        /* Serve broker ops */
        if (rd_kafka_broker_ops_serve(rkb,
                                      !rkb->rkb_transport ?
                                      remains_ms : RD_POLL_NOWAIT))
                remains_ms = RD_POLL_NOWAIT;

        if (likely(rkb->rkb_transport != NULL)) {
                int blocking_max_ms;

                /* If the broker state changed in op_serve() we minimize
                 * the IO timeout since our caller might want to exit out of
                 * its loop on state change. */
                if (unlikely((int)rkb->rkb_state != initial_state))
                        blocking_max_ms = 0;
                else {
                        if (remains_ms == RD_POLL_NOWAIT)
                                remains_ms = rd_timeout_remains(abs_timeout);
                        if (remains_ms == RD_POLL_INFINITE ||
                            remains_ms > rkb->rkb_blocking_max_ms)
                                remains_ms = rkb->rkb_blocking_max_ms;
                        blocking_max_ms = remains_ms;
                }

                /* Serve IO events */
                rd_kafka_transport_io_serve(rkb->rkb_transport,
                                            blocking_max_ms);
        }

        /* Scan wait-response queue for timeouts. */
        now = rd_clock();
        if (rd_interval(&rkb->rkb_timeout_scan_intvl, 1000000, now) > 0)
                rd_kafka_broker_timeout_scan(rkb, now);
}


/**
 * @brief Serve the toppar's assigned to this broker.
 *
 * @returns the minimum Fetch backoff time (abs timestamp) for the
 *          partitions to fetch.
 *
 * @locality broker thread
 */
static rd_ts_t rd_kafka_broker_toppars_serve (rd_kafka_broker_t *rkb) {
        rd_kafka_toppar_t *rktp, *rktp_tmp;
        rd_ts_t min_backoff = RD_TS_MAX;

        TAILQ_FOREACH_SAFE(rktp, &rkb->rkb_toppars, rktp_rkblink, rktp_tmp) {
                rd_ts_t backoff;

                /* Serve toppar to update desired rktp state */
                backoff = rd_kafka_broker_consumer_toppar_serve(rkb, rktp);
                if (backoff < min_backoff)
                        min_backoff = backoff;
        }

        return min_backoff;
}


/**
 * Idle function for unassigned brokers
 * If \p timeout_ms is not RD_POLL_INFINITE the serve loop will be exited
 * regardless of state after this long (approximately).
 */
static void rd_kafka_broker_ua_idle (rd_kafka_broker_t *rkb, int timeout_ms) {
        int initial_state = rkb->rkb_state;
        rd_ts_t abs_timeout;

        if (rd_kafka_terminating(rkb->rkb_rk))
                timeout_ms = 1;
        else if (timeout_ms == RD_POLL_INFINITE)
                timeout_ms = rkb->rkb_blocking_max_ms;

        abs_timeout = rd_timeout_init(timeout_ms);

        /* Since ua_idle is used during connection setup
         * in state ..BROKER_STATE_CONNECT we only run this loop
         * as long as the state remains the same as the initial, on a state
         * change - most likely to UP, a correct serve() function
         * should be used instead.
         * Regardless of constraints (terminating, timeouts), poll at
         * least once. The state will not have changed on the first iteration.
         */
        do {
                rd_kafka_broker_toppars_serve(rkb);
                rd_kafka_broker_serve(rkb, abs_timeout);
        } while (!rd_kafka_broker_terminating(rkb) &&
                 (int)rkb->rkb_state == initial_state &&
                 !rd_timeout_expired(rd_timeout_remains(abs_timeout)));
}


/**
 * @brief Scan toppar's xmit queue for message timeouts.
 * @locality broker thread
 * @locks none
 */
static void rd_kafka_broker_toppar_msgq_scan (rd_kafka_broker_t *rkb,
                                              rd_kafka_toppar_t *rktp,
                                              rd_ts_t now) {
        rd_kafka_msgq_t timedout = RD_KAFKA_MSGQ_INITIALIZER(timedout);

        if (rd_kafka_msgq_age_scan(&rktp->rktp_xmit_msgq, &timedout, now)) {
                /* Trigger delivery report for timed out messages */
                rd_kafka_dr_msgq(rktp->rktp_rkt, &timedout,
                                 RD_KAFKA_RESP_ERR__MSG_TIMED_OUT);
        }
}

/**
 * @brief Serve a toppar for producing.
 *
 * @param next_wakeup will be updated to when the next wake-up/attempt is
 *                    desired, only lower (sooner) values will be set.
 *
 * @returns the number of messages produced.
 *
 * @locks toppar_lock(rktp) MUST be held.
 * @locality broker thread
 */
static int rd_kafka_toppar_producer_serve (rd_kafka_broker_t *rkb,
                                           rd_kafka_toppar_t *rktp,
                                           rd_ts_t now,
                                           rd_ts_t *next_wakeup,
                                           int do_timeout_scan) {
        int cnt = 0;
        int r;
        rd_kafka_msg_t *rkm;
        int move_cnt = 0;

        /* By limiting the number of not-yet-sent buffers (rkb_outbufs) we
         * provide a backpressure mechanism to the producer loop
         * which allows larger message batches to accumulate and thus
         * increase throughput.
         * This comes at no latency cost since there are already
         * buffers enqueued waiting for transmission.
         *
         * The !do_timeout_scan condition is an optimization to
         * avoid having to acquire the lock in the typical case
         * (do_timeout_scan==0). */
        if (unlikely(!do_timeout_scan &&
                     rd_atomic32_get(&rkb->rkb_outbufs.rkbq_cnt) >
                     rkb->rkb_rk->rk_conf.queue_backpressure_thres))
                return 0;

        rd_kafka_toppar_lock(rktp);

        if (unlikely(rktp->rktp_leader != rkb)) {
                /* Currently migrating away from this
                 * broker. */
                rd_kafka_toppar_unlock(rktp);
                return 0;
        }

        if (unlikely(do_timeout_scan)) {
                /* Scan xmit queue for msg timeouts */
                rd_kafka_broker_toppar_msgq_scan(rkb, rktp, now);
        }

        if (unlikely(RD_KAFKA_TOPPAR_IS_PAUSED(rktp))) {
                /* Partition is paused */
                rd_kafka_toppar_unlock(rktp);
                return 0;
        }



        /* Move messages from locked partition produce queue
         * to broker-local xmit queue. */
        if ((move_cnt = rktp->rktp_msgq.rkmq_msg_cnt) > 0)
                rd_kafka_msgq_insert_msgq(&rktp->rktp_xmit_msgq,
                                          &rktp->rktp_msgq,
                                          rktp->rktp_rkt->rkt_conf.
                                          msg_order_cmp);
        rd_kafka_toppar_unlock(rktp);

        r = rktp->rktp_xmit_msgq.rkmq_msg_cnt;
        if (r == 0)
                return 0;

        rd_rkb_dbg(rkb, QUEUE, "TOPPAR",
                   "%.*s [%"PRId32"] %d message(s) in "
                   "xmit queue (%d added from partition queue)",
                   RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                   rktp->rktp_partition,
                   r, move_cnt);

        rkm = TAILQ_FIRST(&rktp->rktp_xmit_msgq.rkmq_msgs);
        rd_dassert(rkm != NULL);

        /* Attempt to fill the batch size, but limit
         * our waiting to queue.buffering.max.ms
         * and batch.num.messages. */
        if (r < rkb->rkb_rk->rk_conf.batch_num_messages) {
                rd_ts_t wait_max;

                /* Calculate maximum wait-time to honour
                 * queue.buffering.max.ms contract. */
                wait_max = rd_kafka_msg_enq_time(rkm) +
                        (rkb->rkb_rk->rk_conf.buffering_max_ms * 1000);

                if (wait_max > now) {
                        /* Wait for more messages or queue.buffering.max.ms
                         * to expire. */
                        *next_wakeup = wait_max;
                        return 0;
                }
        }

        /* Honour retry.backoff.ms. */
        if (unlikely(rkm->rkm_u.producer.ts_backoff > now)) {
                *next_wakeup = rkm->rkm_u.producer.ts_backoff;
                /* Wait for backoff to expire */
                return 0;
        }

        /* Send Produce requests for this toppar */
        while (1) {
                r = rd_kafka_ProduceRequest(rkb, rktp);
                if (likely(r > 0))
                        cnt += r;
                else
                        break;
        }

        /* If there are messages still in the queue, make the next
         * wakeup immediate. */
        if (rd_kafka_msgq_len(&rktp->rktp_xmit_msgq) > 0)
                *next_wakeup = now;

        return cnt;
}



/**
 * @brief Produce from all toppars assigned to this broker.
 * @returns the total number of messages produced.
 */
static int rd_kafka_broker_produce_toppars (rd_kafka_broker_t *rkb,
                                            rd_ts_t now,
                                            rd_ts_t *next_wakeup,
                                            int do_timeout_scan) {
        rd_kafka_toppar_t *rktp;
        int cnt = 0;
        rd_ts_t ret_next_wakeup = *next_wakeup;

        /* Round-robin serve each toppar. */
        rktp = rkb->rkb_active_toppar_next;
        if (unlikely(!rktp))
                return 0;

        do {
                rd_ts_t this_next_wakeup = ret_next_wakeup;

                /* Try producing toppar */
                cnt += rd_kafka_toppar_producer_serve(
                        rkb, rktp, now, &this_next_wakeup,
                        do_timeout_scan);

                if (this_next_wakeup < ret_next_wakeup)
                        ret_next_wakeup = this_next_wakeup;

        } while ((rktp = CIRCLEQ_LOOP_NEXT(&rkb->
                                           rkb_active_toppars,
                                           rktp, rktp_activelink)) !=
                 rkb->rkb_active_toppar_next);

        *next_wakeup = ret_next_wakeup;


        return cnt;
}

/**
 * Producer serving
 */
static void rd_kafka_broker_producer_serve (rd_kafka_broker_t *rkb) {
        rd_interval_t timeout_scan;

        rd_interval_init(&timeout_scan);

        rd_kafka_assert(rkb->rkb_rk, thrd_is_current(rkb->rkb_thread));

	rd_kafka_broker_lock(rkb);

	while (!rd_kafka_broker_terminating(rkb) &&
	       rkb->rkb_state == RD_KAFKA_BROKER_STATE_UP) {
		rd_ts_t now;
                rd_ts_t next_wakeup;
                int do_timeout_scan;

		rd_kafka_broker_unlock(rkb);

		now = rd_clock();
                next_wakeup = now + (rkb->rkb_rk->rk_conf.
                                     socket_blocking_max_ms * 1000);

                do_timeout_scan = rd_interval(&timeout_scan, 1000*1000,
                                              now) >= 0;

                rd_kafka_broker_produce_toppars(rkb, now, &next_wakeup,
                                                do_timeout_scan);

		/* Check and move retry buffers */
		if (unlikely(rd_atomic32_get(&rkb->rkb_retrybufs.rkbq_cnt) > 0))
			rd_kafka_broker_retry_bufs_move(rkb);

                rkb->rkb_blocking_max_ms = (int)
                        (next_wakeup > now ? (next_wakeup - now) / 1000 : 0);
		rd_kafka_broker_serve(rkb, next_wakeup);

		rd_kafka_broker_lock(rkb);
	}

	rd_kafka_broker_unlock(rkb);
}







/**
 * Backoff the next Fetch request (due to error).
 */
static void rd_kafka_broker_fetch_backoff (rd_kafka_broker_t *rkb,
                                           rd_kafka_resp_err_t err) {
        int backoff_ms = rkb->rkb_rk->rk_conf.fetch_error_backoff_ms;
        rkb->rkb_ts_fetch_backoff = rd_clock() + (backoff_ms * 1000);
        rd_rkb_dbg(rkb, FETCH, "BACKOFF",
                   "Fetch backoff for %dms: %s",
                   backoff_ms, rd_kafka_err2str(err));
}

/**
 * @brief Backoff the next Fetch for specific partition
 */
static void rd_kafka_toppar_fetch_backoff (rd_kafka_broker_t *rkb,
                                           rd_kafka_toppar_t *rktp,
                                           rd_kafka_resp_err_t err) {
        int backoff_ms = rkb->rkb_rk->rk_conf.fetch_error_backoff_ms;

        /* Don't back off on reaching end of partition */
        if (err == RD_KAFKA_RESP_ERR__PARTITION_EOF)
                return;

        rktp->rktp_ts_fetch_backoff = rd_clock() + (backoff_ms * 1000);
        rd_rkb_dbg(rkb, FETCH, "BACKOFF",
                   "%s [%"PRId32"]: Fetch backoff for %dms: %s",
                   rktp->rktp_rkt->rkt_topic->str, rktp->rktp_partition,
                   backoff_ms, rd_kafka_err2str(err));
}


/**
 * Parses and handles a Fetch reply.
 * Returns 0 on success or an error code on failure.
 */
static rd_kafka_resp_err_t
rd_kafka_fetch_reply_handle (rd_kafka_broker_t *rkb,
			     rd_kafka_buf_t *rkbuf, rd_kafka_buf_t *request) {
	int32_t TopicArrayCnt;
	int i;
        const int log_decode_errors = LOG_ERR;
        shptr_rd_kafka_itopic_t *s_rkt = NULL;

	if (rd_kafka_buf_ApiVersion(request) >= 1) {
		int32_t Throttle_Time;
		rd_kafka_buf_read_i32(rkbuf, &Throttle_Time);

		rd_kafka_op_throttle_time(rkb, rkb->rkb_rk->rk_rep,
					  Throttle_Time);
	}

	rd_kafka_buf_read_i32(rkbuf, &TopicArrayCnt);
	/* Verify that TopicArrayCnt seems to be in line with remaining size */
	rd_kafka_buf_check_len(rkbuf,
			       TopicArrayCnt * (3/*topic min size*/ +
						4/*PartitionArrayCnt*/ +
						4+2+8+4/*inner header*/));

	for (i = 0 ; i < TopicArrayCnt ; i++) {
		rd_kafkap_str_t topic;
		int32_t fetch_version;
		int32_t PartitionArrayCnt;
		int j;

		rd_kafka_buf_read_str(rkbuf, &topic);
		rd_kafka_buf_read_i32(rkbuf, &PartitionArrayCnt);

                s_rkt = rd_kafka_topic_find0(rkb->rkb_rk, &topic);

		for (j = 0 ; j < PartitionArrayCnt ; j++) {
			struct rd_kafka_toppar_ver *tver, tver_skel;
                        rd_kafka_toppar_t *rktp;
                        shptr_rd_kafka_toppar_t *s_rktp = NULL;
                        rd_slice_t save_slice;
                        struct {
                                int32_t Partition;
                                int16_t ErrorCode;
                                int64_t HighwaterMarkOffset;
                                int64_t LastStableOffset;       /* v4 */
                                int32_t MessageSetSize;
                        } hdr;
                        rd_kafka_resp_err_t err;

			rd_kafka_buf_read_i32(rkbuf, &hdr.Partition);
			rd_kafka_buf_read_i16(rkbuf, &hdr.ErrorCode);
			rd_kafka_buf_read_i64(rkbuf, &hdr.HighwaterMarkOffset);

                        if (rd_kafka_buf_ApiVersion(request) == 4) {
                                int32_t AbortedTxCnt;
                                rd_kafka_buf_read_i64(rkbuf,
                                                      &hdr.LastStableOffset);
                                rd_kafka_buf_read_i32(rkbuf, &AbortedTxCnt);
                                /* Ignore aborted transactions for now */
                                if (AbortedTxCnt > 0)
                                        rd_kafka_buf_skip(rkbuf,
                                                          AbortedTxCnt * (8+8));
                        } else
                                hdr.LastStableOffset = -1;

			rd_kafka_buf_read_i32(rkbuf, &hdr.MessageSetSize);

                        if (unlikely(hdr.MessageSetSize < 0))
                                rd_kafka_buf_parse_fail(
                                        rkbuf,
                                        "%.*s [%"PRId32"]: "
                                        "invalid MessageSetSize %"PRId32,
                                        RD_KAFKAP_STR_PR(&topic),
                                        hdr.Partition,
                                        hdr.MessageSetSize);

			/* Look up topic+partition */
                        if (likely(s_rkt != NULL)) {
                                rd_kafka_itopic_t *rkt;
                                rkt = rd_kafka_topic_s2i(s_rkt);
                                rd_kafka_topic_rdlock(rkt);
                                s_rktp = rd_kafka_toppar_get(
                                        rkt, hdr.Partition, 0/*no ua-on-miss*/);
                                rd_kafka_topic_rdunlock(rkt);
                        }

			if (unlikely(!s_rkt || !s_rktp)) {
				rd_rkb_dbg(rkb, TOPIC, "UNKTOPIC",
					   "Received Fetch response "
					   "(error %hu) for unknown topic "
					   "%.*s [%"PRId32"]: ignoring",
					   hdr.ErrorCode,
					   RD_KAFKAP_STR_PR(&topic),
					   hdr.Partition);
				rd_kafka_buf_skip(rkbuf, hdr.MessageSetSize);
				continue;
			}

                        rktp = rd_kafka_toppar_s2i(s_rktp);

                        rd_kafka_toppar_lock(rktp);
                        /* Make sure toppar hasn't moved to another broker
                         * during the lifetime of the request. */
                        if (unlikely(rktp->rktp_leader != rkb)) {
                                rd_kafka_toppar_unlock(rktp);
                                rd_rkb_dbg(rkb, MSG, "FETCH",
                                           "%.*s [%"PRId32"]: "
                                           "partition leadership changed: "
                                           "discarding fetch response",
                                           RD_KAFKAP_STR_PR(&topic),
                                           hdr.Partition);
                                rd_kafka_toppar_destroy(s_rktp); /* from get */
                                rd_kafka_buf_skip(rkbuf, hdr.MessageSetSize);
                                continue;
                        }
			fetch_version = rktp->rktp_fetch_version;
                        rd_kafka_toppar_unlock(rktp);

			/* Check if this Fetch is for an outdated fetch version,
                         * if so ignore it. */
			tver_skel.s_rktp = s_rktp;
			tver = rd_list_find(request->rkbuf_rktp_vers,
					    &tver_skel,
					    rd_kafka_toppar_ver_cmp);
			rd_kafka_assert(NULL, tver &&
					rd_kafka_toppar_s2i(tver->s_rktp) ==
					rktp);
			if (tver->version < fetch_version) {
				rd_rkb_dbg(rkb, MSG, "DROP",
					   "%s [%"PRId32"]: "
					   "dropping outdated fetch response "
					   "(v%d < %d)",
					   rktp->rktp_rkt->rkt_topic->str,
					   rktp->rktp_partition,
					   tver->version, fetch_version);
                                rd_atomic64_add(&rktp->rktp_c. rx_ver_drops, 1);
                                rd_kafka_toppar_destroy(s_rktp); /* from get */
                                rd_kafka_buf_skip(rkbuf, hdr.MessageSetSize);
                                continue;
                        }

			rd_rkb_dbg(rkb, MSG, "FETCH",
				   "Topic %.*s [%"PRId32"] MessageSet "
				   "size %"PRId32", error \"%s\", "
				   "MaxOffset %"PRId64", "
                                   "Ver %"PRId32"/%"PRId32,
				   RD_KAFKAP_STR_PR(&topic), hdr.Partition,
				   hdr.MessageSetSize,
				   rd_kafka_err2str(hdr.ErrorCode),
				   hdr.HighwaterMarkOffset,
                                   tver->version, fetch_version);


                        /* Update hi offset to be able to compute
                         * consumer lag. */
                        /* FIXME: if IsolationLevel==READ_COMMITTED,
                         *        use hdr.LastStableOffset */
                        rktp->rktp_offsets.hi_offset = hdr.HighwaterMarkOffset;


			/* High offset for get_watermark_offsets() */
			rd_kafka_toppar_lock(rktp);
			rktp->rktp_hi_offset = hdr.HighwaterMarkOffset;
			rd_kafka_toppar_unlock(rktp);

			/* If this is the last message of the queue,
			 * signal EOF back to the application. */
			if (hdr.HighwaterMarkOffset ==
                            rktp->rktp_offsets.fetch_offset
			    &&
			    rktp->rktp_offsets.eof_offset !=
                            rktp->rktp_offsets.fetch_offset) {
				hdr.ErrorCode =
					RD_KAFKA_RESP_ERR__PARTITION_EOF;
				rktp->rktp_offsets.eof_offset =
                                        rktp->rktp_offsets.fetch_offset;
			}

			/* Handle partition-level errors. */
			if (unlikely(hdr.ErrorCode !=
				     RD_KAFKA_RESP_ERR_NO_ERROR)) {
				/* Some errors should be passed to the
				 * application while some handled by rdkafka */
				switch (hdr.ErrorCode)
				{
					/* Errors handled by rdkafka */
				case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART:
				case RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE:
				case RD_KAFKA_RESP_ERR_NOT_LEADER_FOR_PARTITION:
				case RD_KAFKA_RESP_ERR_BROKER_NOT_AVAILABLE:
                                        /* Request metadata information update*/
                                        rd_kafka_toppar_leader_unavailable(
                                                rktp, "fetch", hdr.ErrorCode);
                                        break;

					/* Application errors */
				case RD_KAFKA_RESP_ERR_OFFSET_OUT_OF_RANGE:
                                {
                                        int64_t err_offset =
                                                rktp->rktp_offsets.fetch_offset;
                                        rktp->rktp_offsets.fetch_offset =
                                                RD_KAFKA_OFFSET_INVALID;
					rd_kafka_offset_reset(
						rktp, err_offset,
						hdr.ErrorCode,
						rd_kafka_err2str(hdr.
								 ErrorCode));
                                }
                                break;
				case RD_KAFKA_RESP_ERR__PARTITION_EOF:
					if (!rkb->rkb_rk->rk_conf.enable_partition_eof)
						break;
					/* FALLTHRU */
				case RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE:
				default: /* and all other errors */
					rd_dassert(tver->version > 0);
					rd_kafka_q_op_err(
						rktp->rktp_fetchq,
						RD_KAFKA_OP_CONSUMER_ERR,
						hdr.ErrorCode, tver->version,
						rktp,
						rktp->rktp_offsets.fetch_offset,
						"%s",
						rd_kafka_err2str(hdr.ErrorCode));
					break;
				}

                                rd_kafka_toppar_fetch_backoff(rkb, rktp,
                                                              hdr.ErrorCode);

				rd_kafka_toppar_destroy(s_rktp);/* from get()*/

                                rd_kafka_buf_skip(rkbuf, hdr.MessageSetSize);
				continue;
			}

			if (unlikely(hdr.MessageSetSize <= 0)) {
				rd_kafka_toppar_destroy(s_rktp); /*from get()*/
				continue;
			}

                        /**
                         * Parse MessageSet
                         */
                        if (!rd_slice_narrow_relative(
                                    &rkbuf->rkbuf_reader,
                                    &save_slice,
                                    (size_t)hdr.MessageSetSize))
                                rd_kafka_buf_check_len(rkbuf,
                                                       hdr.MessageSetSize);

                        /* Parse messages */
                        err = rd_kafka_msgset_parse(rkbuf, request, rktp, tver);

                        rd_slice_widen(&rkbuf->rkbuf_reader, &save_slice);
                        /* Continue with next partition regardless of
                         * parse errors (which are partition-specific) */

                        /* On error: back off the fetcher for this partition */
                        if (unlikely(err))
                                rd_kafka_toppar_fetch_backoff(rkb, rktp, err);

                        rd_kafka_toppar_destroy(s_rktp); /* from get */
                }

                if (s_rkt) {
                        rd_kafka_topic_destroy0(s_rkt);
                        s_rkt = NULL;
                }
	}

	if (rd_kafka_buf_read_remain(rkbuf) != 0) {
		rd_kafka_buf_parse_fail(rkbuf,
					"Remaining data after message set "
					"parse: %"PRIusz" bytes",
					rd_kafka_buf_read_remain(rkbuf));
		RD_NOTREACHED();
	}

	return 0;

err_parse:
        if (s_rkt)
                rd_kafka_topic_destroy0(s_rkt);
	rd_rkb_dbg(rkb, MSG, "BADMSG", "Bad message (Fetch v%d): "
		   "is broker.version.fallback incorrectly set?",
		   (int)request->rkbuf_reqhdr.ApiVersion);
	return rkbuf->rkbuf_err;
}



static void rd_kafka_broker_fetch_reply (rd_kafka_t *rk,
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
		switch (err)
		{
		case RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART:
		case RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE:
		case RD_KAFKA_RESP_ERR_NOT_LEADER_FOR_PARTITION:
		case RD_KAFKA_RESP_ERR_BROKER_NOT_AVAILABLE:
		case RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE:
                        /* Request metadata information update */
                        rd_snprintf(tmp, sizeof(tmp),
                                    "FetchRequest failed: %s",
                                    rd_kafka_err2str(err));
                        rd_kafka_metadata_refresh_known_topics(rkb->rkb_rk,
                                                               NULL, 1/*force*/,
                                                               tmp);
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
 * Build and send a Fetch request message for all underflowed toppars
 * for a specific broker.
 */
static int rd_kafka_broker_fetch_toppars (rd_kafka_broker_t *rkb, rd_ts_t now) {
	rd_kafka_toppar_t *rktp;
	rd_kafka_buf_t *rkbuf;
	int cnt = 0;
	size_t of_TopicArrayCnt = 0;
	int TopicArrayCnt = 0;
	size_t of_PartitionArrayCnt = 0;
	int PartitionArrayCnt = 0;
	rd_kafka_itopic_t *rkt_last = NULL;

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

	rkbuf = rd_kafka_buf_new_request(
                rkb, RD_KAFKAP_Fetch, 1,
                /* ReplicaId+MaxWaitTime+MinBytes+TopicCnt */
                4+4+4+4+
                /* N x PartCnt+Partition+FetchOffset+MaxBytes+?TopicNameLen?*/
                (rkb->rkb_active_toppar_cnt * (4+4+8+4+40)));

        if (rkb->rkb_features & RD_KAFKA_FEATURE_MSGVER2)
                rd_kafka_buf_ApiVersion_set(rkbuf, 4,
                                            RD_KAFKA_FEATURE_MSGVER2);
        else if (rkb->rkb_features & RD_KAFKA_FEATURE_MSGVER1)
                rd_kafka_buf_ApiVersion_set(rkbuf, 2,
                                            RD_KAFKA_FEATURE_MSGVER1);
        else if (rkb->rkb_features & RD_KAFKA_FEATURE_THROTTLETIME)
                rd_kafka_buf_ApiVersion_set(rkbuf, 1,
                                            RD_KAFKA_FEATURE_THROTTLETIME);


	/* FetchRequest header */
	/* ReplicaId */
	rd_kafka_buf_write_i32(rkbuf, -1);
	/* MaxWaitTime */
	rd_kafka_buf_write_i32(rkbuf, rkb->rkb_rk->rk_conf.fetch_wait_max_ms);
	/* MinBytes */
	rd_kafka_buf_write_i32(rkbuf, rkb->rkb_rk->rk_conf.fetch_min_bytes);

        if (rd_kafka_buf_ApiVersion(rkbuf) == 4) {
                /* MaxBytes */
                rd_kafka_buf_write_i32(rkbuf,
                                       rkb->rkb_rk->rk_conf.fetch_max_bytes);
                /* IsolationLevel */
                rd_kafka_buf_write_i8(rkbuf, RD_KAFKAP_READ_UNCOMMITTED);
        }

	/* Write zero TopicArrayCnt but store pointer for later update */
	of_TopicArrayCnt = rd_kafka_buf_write_i32(rkbuf, 0);

        /* Prepare map for storing the fetch version for each partition,
         * this will later be checked in Fetch response to purge outdated
         * responses (e.g., after a seek). */
        rkbuf->rkbuf_rktp_vers = rd_list_new(
                0, (void *)rd_kafka_toppar_ver_destroy);
        rd_list_prealloc_elems(rkbuf->rkbuf_rktp_vers,
                               sizeof(struct rd_kafka_toppar_ver),
                               rkb->rkb_active_toppar_cnt);

	/* Round-robin start of the list. */
        rktp = rkb->rkb_active_toppar_next;
        do {
		struct rd_kafka_toppar_ver *tver;

		if (rkt_last != rktp->rktp_rkt) {
			if (rkt_last != NULL) {
				/* Update PartitionArrayCnt */
				rd_kafka_buf_update_i32(rkbuf,
							of_PartitionArrayCnt,
							PartitionArrayCnt);
			}

                        /* Topic name */
			rd_kafka_buf_write_kstr(rkbuf,
                                                rktp->rktp_rkt->rkt_topic);
			TopicArrayCnt++;
			rkt_last = rktp->rktp_rkt;
                        /* Partition count */
			of_PartitionArrayCnt = rd_kafka_buf_write_i32(rkbuf, 0);
			PartitionArrayCnt = 0;
		}

		PartitionArrayCnt++;
		/* Partition */
		rd_kafka_buf_write_i32(rkbuf, rktp->rktp_partition);
		/* FetchOffset */
		rd_kafka_buf_write_i64(rkbuf, rktp->rktp_offsets.fetch_offset);
		/* MaxBytes */
		rd_kafka_buf_write_i32(rkbuf, rktp->rktp_fetch_msg_max_bytes);

		rd_rkb_dbg(rkb, FETCH, "FETCH",
			   "Fetch topic %.*s [%"PRId32"] at offset %"PRId64
			   " (v%d)",
			   RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
			   rktp->rktp_partition,
                           rktp->rktp_offsets.fetch_offset,
			   rktp->rktp_fetch_version);

		/* Add toppar + op version mapping. */
		tver = rd_list_add(rkbuf->rkbuf_rktp_vers, NULL);
		tver->s_rktp = rd_kafka_toppar_keep(rktp);
		tver->version = rktp->rktp_fetch_version;

		cnt++;
	} while ((rktp = CIRCLEQ_LOOP_NEXT(&rkb->rkb_active_toppars,
                                           rktp, rktp_activelink)) !=
                 rkb->rkb_active_toppar_next);

        /* Update next toppar to fetch in round-robin list. */
        rd_kafka_broker_active_toppar_next(
                rkb,
                rktp ?
                CIRCLEQ_LOOP_NEXT(&rkb->rkb_active_toppars,
                                  rktp, rktp_activelink) : NULL);

	rd_rkb_dbg(rkb, FETCH, "FETCH", "Fetch %i/%i/%i toppar(s)",
                   cnt, rkb->rkb_active_toppar_cnt, rkb->rkb_toppar_cnt);
	if (!cnt) {
		rd_kafka_buf_destroy(rkbuf);
		return cnt;
	}

	if (rkt_last != NULL) {
		/* Update last topic's PartitionArrayCnt */
		rd_kafka_buf_update_i32(rkbuf,
					of_PartitionArrayCnt,
					PartitionArrayCnt);
	}

	/* Update TopicArrayCnt */
	rd_kafka_buf_update_i32(rkbuf, of_TopicArrayCnt, TopicArrayCnt);

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
 * Consumer serving
 */
static void rd_kafka_broker_consumer_serve (rd_kafka_broker_t *rkb) {

	rd_kafka_assert(rkb->rkb_rk, thrd_is_current(rkb->rkb_thread));

	rd_kafka_broker_lock(rkb);

	while (!rd_kafka_broker_terminating(rkb) &&
	       rkb->rkb_state == RD_KAFKA_BROKER_STATE_UP) {
		rd_ts_t now;
                rd_ts_t min_backoff;

		rd_kafka_broker_unlock(rkb);

		now = rd_clock();

                /* Serve toppars */
                min_backoff = rd_kafka_broker_toppars_serve(rkb);
                if (rkb->rkb_ts_fetch_backoff > now &&
                    rkb->rkb_ts_fetch_backoff < min_backoff)
                        min_backoff = rkb->rkb_ts_fetch_backoff;

		/* Send Fetch request message for all underflowed toppars */
		if (!rkb->rkb_fetching) {
                        if (min_backoff < now) {
                                rd_kafka_broker_fetch_toppars(rkb, now);
                                rkb->rkb_blocking_max_ms =
                                        rkb->rkb_rk->
                                        rk_conf.socket_blocking_max_ms;
                        } else {
                                if (min_backoff < RD_TS_MAX)
                                        rd_rkb_dbg(rkb, FETCH, "FETCH",
                                                   "Fetch backoff for %"PRId64
                                                   "ms",
                                                   (min_backoff-now)/1000);

                                /* Don't block for more than 1000 ms
                                 * or less than 1 ms. */
                                rkb->rkb_blocking_max_ms = 1 +
                                        (int)RD_MIN(1000,
                                        (min_backoff - now) / 1000);
                        }
                }

		/* Check and move retry buffers */
		if (unlikely(rd_atomic32_get(&rkb->rkb_retrybufs.rkbq_cnt) > 0))
			rd_kafka_broker_retry_bufs_move(rkb);

		rd_kafka_broker_serve(rkb,
                                      now + (rkb->rkb_blocking_max_ms * 1000));

		rd_kafka_broker_lock(rkb);
	}

	rd_kafka_broker_unlock(rkb);
}


static int rd_kafka_broker_thread_main (void *arg) {
	rd_kafka_broker_t *rkb = arg;
	rd_kafka_t *rk = rkb->rkb_rk;

        rd_kafka_set_thread_name("%s", rkb->rkb_name);
        rd_kafka_set_thread_sysname("rdk:broker%"PRId32, rkb->rkb_nodeid);

	(void)rd_atomic32_add(&rd_kafka_thread_cnt_curr, 1);

        /* Our own refcount was increased just prior to thread creation,
         * when refcount drops to 1 it is just us left and the broker 
         * thread should terminate. */

	/* Acquire lock (which was held by thread creator during creation)
	 * to synchronise state. */
	rd_kafka_broker_lock(rkb);
	rd_kafka_broker_unlock(rkb);

	rd_rkb_dbg(rkb, BROKER, "BRKMAIN", "Enter main broker thread");

	while (!rd_kafka_broker_terminating(rkb)) {
                rd_ts_t backoff;

		switch (rkb->rkb_state)
		{
		case RD_KAFKA_BROKER_STATE_INIT:
			/* The INIT state exists so that an initial connection
			 * failure triggers a state transition which might
			 * trigger a ALL_BROKERS_DOWN error. */
		case RD_KAFKA_BROKER_STATE_DOWN:
			if (rkb->rkb_source == RD_KAFKA_INTERNAL) {
                                rd_kafka_broker_lock(rkb);
				rd_kafka_broker_set_state(rkb,
							  RD_KAFKA_BROKER_STATE_UP);
                                rd_kafka_broker_unlock(rkb);
				break;
			}

                        /* Throttle & jitter reconnects to avoid
                         * thundering horde of reconnecting clients after
                         * a broker / network outage. Issue #403 */
                        if (rkb->rkb_rk->rk_conf.reconnect_jitter_ms &&
                            (backoff =
                             rd_interval_immediate(
                                     &rkb->rkb_connect_intvl,
                                     rd_jitter(rkb->rkb_rk->rk_conf.
                                               reconnect_jitter_ms*500,
                                               rkb->rkb_rk->rk_conf.
                                               reconnect_jitter_ms*1500),
                                     0)) <= 0) {
                                backoff = -backoff/1000;
                                rd_rkb_dbg(rkb, BROKER, "RECONNECT",
                                           "Delaying next reconnect by %dms",
                                           (int)backoff);
                                rd_kafka_broker_ua_idle(rkb, (int)backoff);
                                continue;
                        }

			/* Initiate asynchronous connection attempt.
			 * Only the host lookup is blocking here. */
			if (rd_kafka_broker_connect(rkb) == -1) {
				/* Immediate failure, most likely host
				 * resolving failed.
				 * Try the next resolve result until we've
				 * tried them all, in which case we sleep a
				 * short while to avoid busy looping. */
				if (!rkb->rkb_rsal ||
                                    rkb->rkb_rsal->rsal_cnt == 0 ||
                                    rkb->rkb_rsal->rsal_curr + 1 ==
                                    rkb->rkb_rsal->rsal_cnt)
                                        rd_kafka_broker_ua_idle(rkb, 1000);
			}
			break;

		case RD_KAFKA_BROKER_STATE_CONNECT:
		case RD_KAFKA_BROKER_STATE_AUTH:
		case RD_KAFKA_BROKER_STATE_AUTH_HANDSHAKE:
		case RD_KAFKA_BROKER_STATE_APIVERSION_QUERY:
			/* Asynchronous connect in progress. */
			rd_kafka_broker_ua_idle(rkb, RD_POLL_INFINITE);

			if (rkb->rkb_state == RD_KAFKA_BROKER_STATE_DOWN) {
				/* Connect failure.
				 * Try the next resolve result until we've
				 * tried them all, in which case we sleep a
				 * short while to avoid busy looping. */
				if (!rkb->rkb_rsal ||
                                    rkb->rkb_rsal->rsal_cnt == 0 ||
                                    rkb->rkb_rsal->rsal_curr + 1 ==
                                    rkb->rkb_rsal->rsal_cnt)
                                        rd_kafka_broker_ua_idle(rkb, 1000);
			}
			break;

                case RD_KAFKA_BROKER_STATE_UPDATE:
                        /* FALLTHRU */
		case RD_KAFKA_BROKER_STATE_UP:
			if (rkb->rkb_nodeid == RD_KAFKA_NODEID_UA)
				rd_kafka_broker_ua_idle(rkb, RD_POLL_INFINITE);
			else if (rk->rk_type == RD_KAFKA_PRODUCER)
				rd_kafka_broker_producer_serve(rkb);
			else if (rk->rk_type == RD_KAFKA_CONSUMER)
				rd_kafka_broker_consumer_serve(rkb);

			if (rkb->rkb_state == RD_KAFKA_BROKER_STATE_UPDATE) {
                                rd_kafka_broker_lock(rkb);
				rd_kafka_broker_set_state(rkb, RD_KAFKA_BROKER_STATE_UP);
                                rd_kafka_broker_unlock(rkb);
			} else {
				/* Connection torn down, sleep a short while to
				 * avoid busy-looping on protocol errors */
				rd_usleep(100*1000/*100ms*/, &rk->rk_terminate);
			}
			break;
		}

                if (rd_kafka_terminating(rkb->rkb_rk)) {
                        /* Handle is terminating: fail the send+retry queue
                         * to speed up termination, otherwise we'll
                         * need to wait for request timeouts. */
                        int r;

                        r = rd_kafka_broker_bufq_timeout_scan(
                                rkb, 0, &rkb->rkb_outbufs, NULL,
                                RD_KAFKA_RESP_ERR__DESTROY, 0);
                        r += rd_kafka_broker_bufq_timeout_scan(
                                rkb, 0, &rkb->rkb_retrybufs, NULL,
                                RD_KAFKA_RESP_ERR__DESTROY, 0);
                        rd_rkb_dbg(rkb, BROKER, "TERMINATE",
                                   "Handle is terminating: "
                                   "failed %d request(s) in "
                                   "retry+outbuf", r);
                }
	}

	if (rkb->rkb_source != RD_KAFKA_INTERNAL) {
		rd_kafka_wrlock(rkb->rkb_rk);
		TAILQ_REMOVE(&rkb->rkb_rk->rk_brokers, rkb, rkb_link);
                if (rkb->rkb_nodeid != -1)
                        rd_list_remove(&rkb->rkb_rk->rk_broker_by_id, rkb);
		(void)rd_atomic32_sub(&rkb->rkb_rk->rk_broker_cnt, 1);
		rd_kafka_wrunlock(rkb->rkb_rk);
	}

	rd_kafka_broker_fail(rkb, LOG_DEBUG, RD_KAFKA_RESP_ERR__DESTROY, NULL);

        /* Disable and drain ops queue.
         * Simply purging the ops queue risks leaving dangling references
         * for ops such as PARTITION_JOIN/PARTITION_LEAVE where the broker
         * reference is not maintained in the rko (but in rktp_next_leader).
         * #1596 */
        rd_kafka_q_disable(rkb->rkb_ops);
        while (rd_kafka_broker_ops_serve(rkb, RD_POLL_NOWAIT))
                ;

	rd_kafka_broker_destroy(rkb);

#if WITH_SSL
        /* Remove OpenSSL per-thread error state to avoid memory leaks */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
        /*(OpenSSL libraries handle thread init and deinit)
         * https://github.com/openssl/openssl/pull/1048 */
#elif OPENSSL_VERSION_NUMBER >= 0x10000000L
        ERR_remove_thread_state(NULL);
#endif
#endif

	rd_atomic32_sub(&rd_kafka_thread_cnt_curr, 1);

	return 0;
}


/**
 * Final destructor. Refcnt must be 0.
 */
void rd_kafka_broker_destroy_final (rd_kafka_broker_t *rkb) {

        rd_kafka_assert(rkb->rkb_rk, thrd_is_current(rkb->rkb_thread));
        rd_kafka_assert(rkb->rkb_rk, TAILQ_EMPTY(&rkb->rkb_outbufs.rkbq_bufs));
        rd_kafka_assert(rkb->rkb_rk, TAILQ_EMPTY(&rkb->rkb_waitresps.rkbq_bufs));
        rd_kafka_assert(rkb->rkb_rk, TAILQ_EMPTY(&rkb->rkb_retrybufs.rkbq_bufs));
        rd_kafka_assert(rkb->rkb_rk, TAILQ_EMPTY(&rkb->rkb_toppars));

        if (rkb->rkb_source != RD_KAFKA_INTERNAL &&
            (rkb->rkb_rk->rk_conf.security_protocol ==
             RD_KAFKA_PROTO_SASL_PLAINTEXT ||
             rkb->rkb_rk->rk_conf.security_protocol ==
             RD_KAFKA_PROTO_SASL_SSL))
                rd_kafka_sasl_broker_term(rkb);

        if (rkb->rkb_wakeup_fd[0] != -1)
                rd_close(rkb->rkb_wakeup_fd[0]);
        if (rkb->rkb_wakeup_fd[1] != -1)
                rd_close(rkb->rkb_wakeup_fd[1]);

	if (rkb->rkb_recv_buf)
		rd_kafka_buf_destroy(rkb->rkb_recv_buf);

	if (rkb->rkb_rsal)
		rd_sockaddr_list_destroy(rkb->rkb_rsal);

	if (rkb->rkb_ApiVersions)
		rd_free(rkb->rkb_ApiVersions);
        rd_free(rkb->rkb_origname);

	rd_kafka_q_purge(rkb->rkb_ops);
        rd_kafka_q_destroy_owner(rkb->rkb_ops);

        rd_avg_destroy(&rkb->rkb_avg_int_latency);
        rd_avg_destroy(&rkb->rkb_avg_rtt);
	rd_avg_destroy(&rkb->rkb_avg_throttle);

        mtx_lock(&rkb->rkb_logname_lock);
        rd_free(rkb->rkb_logname);
        rkb->rkb_logname = NULL;
        mtx_unlock(&rkb->rkb_logname_lock);
        mtx_destroy(&rkb->rkb_logname_lock);

	mtx_destroy(&rkb->rkb_lock);

        rd_refcnt_destroy(&rkb->rkb_refcnt);

	rd_free(rkb);
}

/**
 * Returns the internal broker with refcnt increased.
 */
rd_kafka_broker_t *rd_kafka_broker_internal (rd_kafka_t *rk) {
	rd_kafka_broker_t *rkb;

        mtx_lock(&rk->rk_internal_rkb_lock);
	rkb = rk->rk_internal_rkb;
	if (rkb)
		rd_kafka_broker_keep(rkb);
        mtx_unlock(&rk->rk_internal_rkb_lock);

	return rkb;
}


/**
 * Adds a broker with refcount set to 1.
 * If 'source' is RD_KAFKA_INTERNAL an internal broker is added
 * that does not actually represent or connect to a real broker, it is used
 * for serving unassigned toppar's op queues.
 *
 * Locks: rd_kafka_wrlock(rk) must be held
 */
rd_kafka_broker_t *rd_kafka_broker_add (rd_kafka_t *rk,
					rd_kafka_confsource_t source,
					rd_kafka_secproto_t proto,
					const char *name, uint16_t port,
					int32_t nodeid) {
	rd_kafka_broker_t *rkb;
#ifndef _MSC_VER
        int r;
        sigset_t newset, oldset;
#endif

	rkb = rd_calloc(1, sizeof(*rkb));

        rd_kafka_mk_nodename(rkb->rkb_nodename, sizeof(rkb->rkb_nodename),
                             name, port);
        rd_kafka_mk_brokername(rkb->rkb_name, sizeof(rkb->rkb_name),
                               proto, rkb->rkb_nodename, nodeid, source);

	rkb->rkb_source = source;
	rkb->rkb_rk = rk;
	rkb->rkb_nodeid = nodeid;
	rkb->rkb_proto = proto;
        rkb->rkb_port = port;
        rkb->rkb_origname = rd_strdup(name);

	mtx_init(&rkb->rkb_lock, mtx_plain);
        mtx_init(&rkb->rkb_logname_lock, mtx_plain);
        rkb->rkb_logname = rd_strdup(rkb->rkb_name);
	TAILQ_INIT(&rkb->rkb_toppars);
        CIRCLEQ_INIT(&rkb->rkb_active_toppars);
	rd_kafka_bufq_init(&rkb->rkb_outbufs);
	rd_kafka_bufq_init(&rkb->rkb_waitresps);
	rd_kafka_bufq_init(&rkb->rkb_retrybufs);
	rkb->rkb_ops = rd_kafka_q_new(rk);
        rd_interval_init(&rkb->rkb_connect_intvl);
	rd_avg_init(&rkb->rkb_avg_int_latency, RD_AVG_GAUGE);
	rd_avg_init(&rkb->rkb_avg_rtt, RD_AVG_GAUGE);
	rd_avg_init(&rkb->rkb_avg_throttle, RD_AVG_GAUGE);
        rd_refcnt_init(&rkb->rkb_refcnt, 0);
        rd_kafka_broker_keep(rkb); /* rk_broker's refcount */

        rkb->rkb_blocking_max_ms = rk->rk_conf.socket_blocking_max_ms;

	/* ApiVersion fallback interval */
	if (rkb->rkb_rk->rk_conf.api_version_request) {
		rd_interval_init(&rkb->rkb_ApiVersion_fail_intvl);
		rd_interval_fixed(&rkb->rkb_ApiVersion_fail_intvl,
				  rkb->rkb_rk->rk_conf.api_version_fallback_ms*1000);
	}

	/* Set next intervalled metadata refresh, offset by a random
	 * value to avoid all brokers to be queried simultaneously. */
	if (rkb->rkb_rk->rk_conf.metadata_refresh_interval_ms >= 0)
		rkb->rkb_ts_metadata_poll = rd_clock() +
			(rkb->rkb_rk->rk_conf.
			 metadata_refresh_interval_ms * 1000) +
			(rd_jitter(500,1500) * 1000);
	else /* disabled */
		rkb->rkb_ts_metadata_poll = UINT64_MAX;

#ifndef _MSC_VER
        /* Block all signals in newly created thread.
         * To avoid race condition we block all signals in the calling
         * thread, which the new thread will inherit its sigmask from,
         * and then restore the original sigmask of the calling thread when
         * we're done creating the thread.
	 * NOTE: term_sig remains unblocked since we use it on termination
	 *       to quickly interrupt system calls. */
        sigemptyset(&oldset);
        sigfillset(&newset);
	if (rkb->rkb_rk->rk_conf.term_sig)
		sigdelset(&newset, rkb->rkb_rk->rk_conf.term_sig);
        pthread_sigmask(SIG_SETMASK, &newset, &oldset);
#endif

        /*
         * Fd-based queue wake-ups using a non-blocking pipe.
         * Writes are best effort, if the socket queue is full
         * the write fails (silently) but this has no effect on latency
         * since the POLLIN flag will already have been raised for fd.
         */
        rkb->rkb_wakeup_fd[0]     = -1;
        rkb->rkb_wakeup_fd[1]     = -1;
        rkb->rkb_toppar_wakeup_fd = -1;

#ifndef _MSC_VER /* pipes cant be mixed with WSAPoll on Win32 */
        if ((r = rd_pipe_nonblocking(rkb->rkb_wakeup_fd)) == -1) {
                rd_rkb_log(rkb, LOG_ERR, "WAKEUPFD",
                           "Failed to setup broker queue wake-up fds: "
                           "%s: disabling low-latency mode",
                           rd_strerror(r));

        } else if (source == RD_KAFKA_INTERNAL) {
                /* nop: internal broker has no IO transport. */

        } else {
                char onebyte = 1;

                /* Since there is a small syscall penalty,
                 * only enable partition message queue wake-ups
                 * if latency contract demands it.
                 * rkb_ops queue wakeups are always enabled though,
                 * since they are much more infrequent. */
                if (rk->rk_conf.buffering_max_ms <
                    rk->rk_conf.socket_blocking_max_ms) {
                        rd_rkb_dbg(rkb, QUEUE, "WAKEUPFD",
                                   "Enabled low-latency partition "
                                   "queue wake-ups");
                        rkb->rkb_toppar_wakeup_fd = rkb->rkb_wakeup_fd[1];
                }


                rd_rkb_dbg(rkb, QUEUE, "WAKEUPFD",
                           "Enabled low-latency ops queue wake-ups");
                rd_kafka_q_io_event_enable(rkb->rkb_ops, rkb->rkb_wakeup_fd[1],
                                           &onebyte, sizeof(onebyte));
        }
#endif

        /* Lock broker's lock here to synchronise state, i.e., hold off
	 * the broker thread until we've finalized the rkb. */
	rd_kafka_broker_lock(rkb);
        rd_kafka_broker_keep(rkb); /* broker thread's refcnt */
	if (thrd_create(&rkb->rkb_thread,
			rd_kafka_broker_thread_main, rkb) != thrd_success) {
		char tmp[512];
		rd_snprintf(tmp, sizeof(tmp),
			 "Unable to create broker thread: %s (%i)",
			 rd_strerror(errno), errno);
		rd_kafka_log(rk, LOG_CRIT, "THREAD", "%s", tmp);

		rd_kafka_broker_unlock(rkb);

		/* Send ERR op back to application for processing. */
		rd_kafka_op_err(rk, RD_KAFKA_RESP_ERR__CRIT_SYS_RESOURCE,
				"%s", tmp);

		rd_free(rkb);

#ifndef _MSC_VER
		/* Restore sigmask of caller */
		pthread_sigmask(SIG_SETMASK, &oldset, NULL);
#endif

		return NULL;
	}

        if (rkb->rkb_source != RD_KAFKA_INTERNAL) {
                if (rk->rk_conf.security_protocol ==
                    RD_KAFKA_PROTO_SASL_PLAINTEXT ||
                    rk->rk_conf.security_protocol == RD_KAFKA_PROTO_SASL_SSL)
                        rd_kafka_sasl_broker_init(rkb);

		TAILQ_INSERT_TAIL(&rkb->rkb_rk->rk_brokers, rkb, rkb_link);
		(void)rd_atomic32_add(&rkb->rkb_rk->rk_broker_cnt, 1);

                if (rkb->rkb_nodeid != -1) {
                        rd_list_add(&rkb->rkb_rk->rk_broker_by_id, rkb);
                        rd_list_sort(&rkb->rkb_rk->rk_broker_by_id,
                                     rd_kafka_broker_cmp_by_id);
                }

		rd_rkb_dbg(rkb, BROKER, "BROKER",
			   "Added new broker with NodeId %"PRId32,
			   rkb->rkb_nodeid);
	}

	rd_kafka_broker_unlock(rkb);

#ifndef _MSC_VER
	/* Restore sigmask of caller */
	pthread_sigmask(SIG_SETMASK, &oldset, NULL);
#endif

	return rkb;
}

/**
 * @brief Find broker by nodeid (not -1) and
 *        possibly filtered by state (unless -1).
 *
 * @locks: rd_kafka_*lock() MUST be held
 * @remark caller must release rkb reference by rd_kafka_broker_destroy()
 */
rd_kafka_broker_t *rd_kafka_broker_find_by_nodeid0 (rd_kafka_t *rk,
                                                    int32_t nodeid,
                                                    int state) {
        rd_kafka_broker_t *rkb;
        rd_kafka_broker_t skel = { .rkb_nodeid = nodeid };

        if (rd_kafka_terminating(rk))
                return NULL;

        rkb = rd_list_find(&rk->rk_broker_by_id, &skel,
                           rd_kafka_broker_cmp_by_id);

        if (!rkb)
                return NULL;

        if (state != -1) {
                int broker_state;
                rd_kafka_broker_lock(rkb);
                broker_state = (int)rkb->rkb_state;
                rd_kafka_broker_unlock(rkb);

                if (broker_state != state)
                        return NULL;
        }

        rd_kafka_broker_keep(rkb);
        return rkb;
}

/**
 * Locks: rd_kafka_rdlock(rk) must be held
 * NOTE: caller must release rkb reference by rd_kafka_broker_destroy()
 */
static rd_kafka_broker_t *rd_kafka_broker_find (rd_kafka_t *rk,
						rd_kafka_secproto_t proto,
						const char *name,
						uint16_t port) {
	rd_kafka_broker_t *rkb;
	char nodename[RD_KAFKA_NODENAME_SIZE];

        rd_kafka_mk_nodename(nodename, sizeof(nodename), name, port);

	TAILQ_FOREACH(rkb, &rk->rk_brokers, rkb_link) {
		rd_kafka_broker_lock(rkb);
		if (!rd_atomic32_get(&rk->rk_terminate) &&
		    rkb->rkb_proto == proto &&
		    !strcmp(rkb->rkb_nodename, nodename)) {
			rd_kafka_broker_keep(rkb);
			rd_kafka_broker_unlock(rkb);
			return rkb;
		}
		rd_kafka_broker_unlock(rkb);
	}

	return NULL;
}


/**
 * Parse a broker host name.
 * The string 'name' is modified and null-terminated portions of it
 * are returned in 'proto', 'host', and 'port'.
 *
 * Returns 0 on success or -1 on parse error.
 */
static int rd_kafka_broker_name_parse (rd_kafka_t *rk,
				       char **name,
				       rd_kafka_secproto_t *proto,
				       const char **host,
				       uint16_t *port) {
	char *s = *name;
	char *orig;
	char *n, *t, *t2;

	/* Save a temporary copy of the original name for logging purposes */
	rd_strdupa(&orig, *name);

	/* Find end of this name (either by delimiter or end of string */
	if ((n = strchr(s, ',')))
		*n = '\0';
	else
		n = s + strlen(s)-1;


	/* Check if this looks like an url. */
	if ((t = strstr(s, "://"))) {
		int i;
		/* "proto://host[:port]" */

		if (t == s) {
			rd_kafka_log(rk, LOG_WARNING, "BROKER",
				     "Broker name \"%s\" parse error: "
				     "empty protocol name", orig);
			return -1;
		}

		/* Make protocol uppercase */
		for (t2 = s ; t2 < t ; t2++)
			*t2 = toupper(*t2);

		*t = '\0';

		/* Find matching protocol by name. */
		for (i = 0 ; i < RD_KAFKA_PROTO_NUM ; i++)
			if (!rd_strcasecmp(s, rd_kafka_secproto_names[i]))
				break;

		/* Unsupported protocol */
		if (i == RD_KAFKA_PROTO_NUM) {
			rd_kafka_log(rk, LOG_WARNING, "BROKER",
				     "Broker name \"%s\" parse error: "
				     "unsupported protocol \"%s\"", orig, s);

			return -1;
		}

		*proto = i;

                /* Enforce protocol */
		if (rk->rk_conf.security_protocol != *proto) {
			rd_kafka_log(rk, LOG_WARNING, "BROKER",
				     "Broker name \"%s\" parse error: "
				     "protocol \"%s\" does not match "
				     "security.protocol setting \"%s\"",
				     orig, s,
				     rd_kafka_secproto_names[
					     rk->rk_conf.security_protocol]);
			return -1;
		}

		/* Hostname starts here */
		s = t+3;

		/* Ignore anything that looks like the path part of an URL */
		if ((t = strchr(s, '/')))
			*t = '\0';

	} else
		*proto = rk->rk_conf.security_protocol; /* Default protocol */


	*port = RD_KAFKA_PORT;
	/* Check if port has been specified, but try to identify IPv6
	 * addresses first:
	 *  t = last ':' in string
	 *  t2 = first ':' in string
	 *  If t and t2 are equal then only one ":" exists in name
	 *  and thus an IPv4 address with port specified.
	 *  Else if not equal and t is prefixed with "]" then it's an
	 *  IPv6 address with port specified.
	 *  Else no port specified. */
	if ((t = strrchr(s, ':')) &&
	    ((t2 = strchr(s, ':')) == t || *(t-1) == ']')) {
		*t = '\0';
		*port = atoi(t+1);
	}

	/* Empty host name -> localhost */
	if (!*s) 
		s = "localhost";

	*host = s;
	*name = n+1;  /* past this name. e.g., next name/delimiter to parse */

	return 0;
}


/**
 * Adds a (csv list of) broker(s).
 * Returns the number of brokers succesfully added.
 *
 * Locality: any thread
 * Lock prereqs: none
 */
int rd_kafka_brokers_add0 (rd_kafka_t *rk, const char *brokerlist) {
	char *s_copy = rd_strdup(brokerlist);
	char *s = s_copy;
	int cnt = 0;
	rd_kafka_broker_t *rkb;

	/* Parse comma-separated list of brokers. */
	while (*s) {
		uint16_t port;
		const char *host;
		rd_kafka_secproto_t proto;

		if (*s == ',' || *s == ' ') {
			s++;
			continue;
		}

		if (rd_kafka_broker_name_parse(rk, &s, &proto,
					       &host, &port) == -1)
			break;

		rd_kafka_wrlock(rk);

		if ((rkb = rd_kafka_broker_find(rk, proto, host, port)) &&
		    rkb->rkb_source == RD_KAFKA_CONFIGURED) {
			cnt++;
		} else if (rd_kafka_broker_add(rk, RD_KAFKA_CONFIGURED,
					       proto, host, port,
					       RD_KAFKA_NODEID_UA) != NULL)
			cnt++;

		/* If rd_kafka_broker_find returned a broker its
		 * reference needs to be released 
		 * See issue #193 */
		if (rkb)
			rd_kafka_broker_destroy(rkb);

		rd_kafka_wrunlock(rk);
	}

	rd_free(s_copy);

	return cnt;
}


int rd_kafka_brokers_add (rd_kafka_t *rk, const char *brokerlist) {
        return rd_kafka_brokers_add0(rk, brokerlist);
}


/**
 * Adds a new broker or updates an existing one.
 *
 */
void rd_kafka_broker_update (rd_kafka_t *rk, rd_kafka_secproto_t proto,
                             const struct rd_kafka_metadata_broker *mdb) {
	rd_kafka_broker_t *rkb;
        char nodename[RD_KAFKA_NODENAME_SIZE];
        int needs_update = 0;

        rd_kafka_mk_nodename(nodename, sizeof(nodename), mdb->host, mdb->port);

	rd_kafka_wrlock(rk);
	if (unlikely(rd_atomic32_get(&rk->rk_terminate))) {
		/* Dont update metadata while terminating, do this
		 * after acquiring lock for proper synchronisation */
		rd_kafka_wrunlock(rk);
		return;
	}

	if ((rkb = rd_kafka_broker_find_by_nodeid(rk, mdb->id))) {
                /* Broker matched by nodeid, see if we need to update
                 * the hostname. */
                if (strcmp(rkb->rkb_nodename, nodename))
                        needs_update = 1;
        } else if ((rkb = rd_kafka_broker_find(rk, proto,
					       mdb->host, mdb->port))) {
                /* Broker matched by hostname (but not by nodeid),
                 * update the nodeid. */
                needs_update = 1;

        } else {
		rd_kafka_broker_add(rk, RD_KAFKA_LEARNED,
				    proto, mdb->host, mdb->port, mdb->id);
	}

	rd_kafka_wrunlock(rk);

        if (rkb) {
                /* Existing broker */
                if (needs_update) {
                        rd_kafka_op_t *rko;

                        rko = rd_kafka_op_new(RD_KAFKA_OP_NODE_UPDATE);
                        strncpy(rko->rko_u.node.nodename, nodename,
				sizeof(rko->rko_u.node.nodename)-1);
                        rko->rko_u.node.nodeid   = mdb->id;
                        rd_kafka_q_enq(rkb->rkb_ops, rko);
                }
                rd_kafka_broker_destroy(rkb);
        }
}


/**
 * Returns a thread-safe temporary copy of the broker name.
 * Must not be called more than 4 times from the same expression.
 *
 * Locks: none
 * Locality: any thread
 */
const char *rd_kafka_broker_name (rd_kafka_broker_t *rkb) {
        static RD_TLS char ret[4][RD_KAFKA_NODENAME_SIZE];
        static RD_TLS int reti = 0;

        reti = (reti + 1) % 4;
        mtx_lock(&rkb->rkb_logname_lock);
        rd_snprintf(ret[reti], sizeof(ret[reti]), "%s", rkb->rkb_logname);
        mtx_unlock(&rkb->rkb_logname_lock);

        return ret[reti];
}


/**
 * @brief Send dummy OP to broker thread to wake it up from IO sleep.
 *
 * @locality any
 * @locks none
 */
void rd_kafka_broker_wakeup (rd_kafka_broker_t *rkb) {
        rd_kafka_op_t *rko = rd_kafka_op_new(RD_KAFKA_OP_WAKEUP);
        rd_kafka_op_set_prio(rko, RD_KAFKA_PRIO_FLASH);
        rd_kafka_q_enq(rkb->rkb_ops, rko);
        rd_rkb_dbg(rkb, QUEUE, "WAKEUP", "Wake-up");
}


/**
 * @brief Add toppar to broker's active list list.
 *
 * For consumer this means the fetch list.
 * For producers this is all partitions assigned to this broker.
 *
 * @locality broker thread
 * @locks none
 */
void rd_kafka_broker_active_toppar_add (rd_kafka_broker_t *rkb,
                                        rd_kafka_toppar_t *rktp) {
        int is_consumer = rkb->rkb_rk->rk_type == RD_KAFKA_CONSUMER;

        if (is_consumer && rktp->rktp_fetch)
                return; /* Already added */

        CIRCLEQ_INSERT_TAIL(&rkb->rkb_active_toppars, rktp, rktp_activelink);
        rkb->rkb_active_toppar_cnt++;

        if (is_consumer)
                rktp->rktp_fetch = 1;

        if (unlikely(rkb->rkb_active_toppar_cnt == 1))
                rd_kafka_broker_active_toppar_next(rkb, rktp);

        rd_rkb_dbg(rkb, TOPIC, "FETCHADD",
                   "Added %.*s [%"PRId32"] to %s list (%d entries, opv %d)",
                   RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                   rktp->rktp_partition,
                   is_consumer ? "fetch" : "active",
                   rkb->rkb_active_toppar_cnt, rktp->rktp_fetch_version);
}


/**
 * @brief Remove toppar from active list.
 *
 * Locality: broker thread
 * Locks: none
 */
void rd_kafka_broker_active_toppar_del (rd_kafka_broker_t *rkb,
                                        rd_kafka_toppar_t *rktp) {
        int is_consumer = rkb->rkb_rk->rk_type == RD_KAFKA_CONSUMER;

        if (is_consumer && !rktp->rktp_fetch)
                return; /* Not added */

        CIRCLEQ_REMOVE(&rkb->rkb_active_toppars, rktp, rktp_activelink);
        rd_kafka_assert(NULL, rkb->rkb_active_toppar_cnt > 0);
        rkb->rkb_active_toppar_cnt--;

        if (is_consumer)
                rktp->rktp_fetch = 0;

        if (rkb->rkb_active_toppar_next == rktp) {
                /* Update next pointer */
                rd_kafka_broker_active_toppar_next(
                        rkb, CIRCLEQ_LOOP_NEXT(&rkb->rkb_active_toppars,
                                               rktp, rktp_activelink));
        }

        rd_rkb_dbg(rkb, TOPIC, "FETCHADD",
                   "Removed %.*s [%"PRId32"] from %s list "
                   "(%d entries, opv %d)",
                   RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                   rktp->rktp_partition,
                   is_consumer ? "fetch" : "active",
                   rkb->rkb_active_toppar_cnt, rktp->rktp_fetch_version);

}


void rd_kafka_brokers_init (void) {
}








