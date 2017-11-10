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


#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "rdkafka_int.h"
#include "rdkafka_msg.h"
#include "rdkafka_broker.h"
#include "rdkafka_topic.h"
#include "rdkafka_partition.h"
#include "rdkafka_offset.h"
#include "rdkafka_transport.h"
#include "rdkafka_cgrp.h"
#include "rdkafka_assignor.h"
#include "rdkafka_request.h"
#include "rdkafka_event.h"
#include "rdkafka_sasl.h"
#include "rdkafka_interceptor.h"

#include "rdtime.h"
#include "crc32c.h"
#include "rdunittest.h"

#ifdef _MSC_VER
#include <sys/types.h>
#include <sys/timeb.h>
#endif



static once_flag rd_kafka_global_init_once = ONCE_FLAG_INIT;

/**
 * @brief Global counter+lock for all active librdkafka instances
 */
mtx_t rd_kafka_global_lock;
int rd_kafka_global_cnt;


/**
 * Last API error code, per thread.
 * Shared among all rd_kafka_t instances.
 */
rd_kafka_resp_err_t RD_TLS rd_kafka_last_error_code;


/**
 * Current number of threads created by rdkafka.
 * This is used in regression tests.
 */
rd_atomic32_t rd_kafka_thread_cnt_curr;
int rd_kafka_thread_cnt (void) {
#if ENABLE_SHAREDPTR_DEBUG
        rd_shared_ptrs_dump();
#endif

	return rd_atomic32_get(&rd_kafka_thread_cnt_curr);
}

/**
 * Current thread's name (TLS)
 */
char RD_TLS rd_kafka_thread_name[64] = "app";



static void rd_kafka_global_init (void) {
#if ENABLE_SHAREDPTR_DEBUG
        LIST_INIT(&rd_shared_ptr_debug_list);
        mtx_init(&rd_shared_ptr_debug_mtx, mtx_plain);
        atexit(rd_shared_ptrs_dump);
#endif
	mtx_init(&rd_kafka_global_lock, mtx_plain);
#if ENABLE_DEVEL
	rd_atomic32_init(&rd_kafka_op_cnt, 0);
#endif
        crc32c_global_init();
}

/**
 * @returns the current number of active librdkafka instances
 */
static int rd_kafka_global_cnt_get (void) {
	int r;
	mtx_lock(&rd_kafka_global_lock);
	r = rd_kafka_global_cnt;
	mtx_unlock(&rd_kafka_global_lock);
	return r;
}


/**
 * @brief Increase counter for active librdkafka instances.
 * If this is the first instance the global constructors will be called, if any.
 */
static void rd_kafka_global_cnt_incr (void) {
	mtx_lock(&rd_kafka_global_lock);
	rd_kafka_global_cnt++;
	if (rd_kafka_global_cnt == 1) {
		rd_kafka_transport_init();
#if WITH_SSL
		rd_kafka_transport_ssl_init();
#endif
                rd_kafka_sasl_global_init();
	}
	mtx_unlock(&rd_kafka_global_lock);
}

/**
 * @brief Decrease counter for active librdkafka instances.
 * If this counter reaches 0 the global destructors will be called, if any.
 */
static void rd_kafka_global_cnt_decr (void) {
	mtx_lock(&rd_kafka_global_lock);
	rd_kafka_assert(NULL, rd_kafka_global_cnt > 0);
	rd_kafka_global_cnt--;
	if (rd_kafka_global_cnt == 0) {
                rd_kafka_sasl_global_term();
#if WITH_SSL
		rd_kafka_transport_ssl_term();
#endif
	}
	mtx_unlock(&rd_kafka_global_lock);
}


/**
 * Wait for all rd_kafka_t objects to be destroyed.
 * Returns 0 if all kafka objects are now destroyed, or -1 if the
 * timeout was reached.
 */
int rd_kafka_wait_destroyed (int timeout_ms) {
	rd_ts_t timeout = rd_clock() + (timeout_ms * 1000);

	while (rd_kafka_thread_cnt() > 0 ||
	       rd_kafka_global_cnt_get() > 0) {
		if (rd_clock() >= timeout) {
			rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__TIMED_OUT,
						ETIMEDOUT);
#if ENABLE_SHAREDPTR_DEBUG
                        rd_shared_ptrs_dump();
#endif
			return -1;
		}
		rd_usleep(25000, NULL); /* 25ms */
	}

	return 0;
}

static void rd_kafka_log_buf (const rd_kafka_conf_t *conf,
                              const rd_kafka_t *rk, int level, const char *fac,
                              const char *buf) {
        if (level > conf->log_level)
                return;
        else if (rk && conf->log_queue) {
                rd_kafka_op_t *rko;

                if (!rk->rk_logq)
                        return; /* Terminating */

                rko = rd_kafka_op_new(RD_KAFKA_OP_LOG);
                rd_kafka_op_set_prio(rko, RD_KAFKA_PRIO_MEDIUM);
                rko->rko_u.log.level = level;
                strncpy(rko->rko_u.log.fac, fac,
                        sizeof(rko->rko_u.log.fac) - 1);
                rko->rko_u.log.str = rd_strdup(buf);
                rd_kafka_q_enq(rk->rk_logq, rko);

        } else if (conf->log_cb) {
                conf->log_cb(rk, level, fac, buf);
        }
}

/**
 * @brief Logger
 *
 * @remark conf must be set, but rk may be NULL
 */
void rd_kafka_log0 (const rd_kafka_conf_t *conf,
                    const rd_kafka_t *rk,
                    const char *extra, int level,
                    const char *fac, const char *fmt, ...) {
	char buf[2048];
	va_list ap;
	unsigned int elen = 0;
        unsigned int of = 0;

	if (level > conf->log_level)
		return;

	if (conf->log_thread_name) {
		elen = rd_snprintf(buf, sizeof(buf), "[thrd:%s]: ",
				   rd_kafka_thread_name);
		if (unlikely(elen >= sizeof(buf)))
			elen = sizeof(buf);
		of = elen;
	}

	if (extra) {
		elen = rd_snprintf(buf+of, sizeof(buf)-of, "%s: ", extra);
		if (unlikely(elen >= sizeof(buf)-of))
			elen = sizeof(buf)-of;
                of += elen;
	}

	va_start(ap, fmt);
	rd_vsnprintf(buf+of, sizeof(buf)-of, fmt, ap);
	va_end(ap);

        rd_kafka_log_buf(conf, rk, level, fac, buf);
}



void rd_kafka_log_print(const rd_kafka_t *rk, int level,
	const char *fac, const char *buf) {
	int secs, msecs;
	struct timeval tv;
	rd_gettimeofday(&tv, NULL);
	secs = (int)tv.tv_sec;
	msecs = (int)(tv.tv_usec / 1000);
	fprintf(stderr, "%%%i|%u.%03u|%s|%s| %s\n",
		level, secs, msecs,
		fac, rk ? rk->rk_name : "", buf);
}

#ifndef _MSC_VER
void rd_kafka_log_syslog (const rd_kafka_t *rk, int level,
			  const char *fac, const char *buf) {
	static int initialized = 0;

	if (!initialized)
		openlog("rdkafka", LOG_PID|LOG_CONS, LOG_USER);

	syslog(level, "%s: %s: %s", fac, rk ? rk->rk_name : "", buf);
}
#endif

void rd_kafka_set_logger (rd_kafka_t *rk,
			  void (*func) (const rd_kafka_t *rk, int level,
					const char *fac, const char *buf)) {
	rk->rk_conf.log_cb = func;
}

void rd_kafka_set_log_level (rd_kafka_t *rk, int level) {
	rk->rk_conf.log_level = level;
}






static const char *rd_kafka_type2str (rd_kafka_type_t type) {
	static const char *types[] = {
		[RD_KAFKA_PRODUCER] = "producer",
		[RD_KAFKA_CONSUMER] = "consumer",
	};
	return types[type];
}

#define _ERR_DESC(ENUM,DESC) \
	[ENUM - RD_KAFKA_RESP_ERR__BEGIN] = { ENUM, # ENUM + 18/*pfx*/, DESC }

static const struct rd_kafka_err_desc rd_kafka_err_descs[] = {
	_ERR_DESC(RD_KAFKA_RESP_ERR__BEGIN, NULL),
	_ERR_DESC(RD_KAFKA_RESP_ERR__BAD_MSG,
		  "Local: Bad message format"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__BAD_COMPRESSION,
		  "Local: Invalid compressed data"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__DESTROY,
		  "Local: Broker handle destroyed"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__FAIL,
		  "Local: Communication failure with broker"), //FIXME: too specific
	_ERR_DESC(RD_KAFKA_RESP_ERR__TRANSPORT,
		  "Local: Broker transport failure"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__CRIT_SYS_RESOURCE,
		  "Local: Critical system resource failure"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__RESOLVE,
		  "Local: Host resolution failure"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__MSG_TIMED_OUT,
		  "Local: Message timed out"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__PARTITION_EOF,
		  "Broker: No more messages"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION,
		  "Local: Unknown partition"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__FS,
		  "Local: File or filesystem error"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC,
		  "Local: Unknown topic"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN,
		  "Local: All broker connections are down"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__INVALID_ARG,
		  "Local: Invalid argument or configuration"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__TIMED_OUT,
		  "Local: Timed out"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__QUEUE_FULL,
		  "Local: Queue full"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__ISR_INSUFF,
		  "Local: ISR count insufficient"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__NODE_UPDATE,
		  "Local: Broker node update"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__SSL,
		  "Local: SSL error"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__WAIT_COORD,
		  "Local: Waiting for coordinator"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__UNKNOWN_GROUP,
		  "Local: Unknown group"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__IN_PROGRESS,
		  "Local: Operation in progress"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__PREV_IN_PROGRESS,
		  "Local: Previous operation in progress"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__EXISTING_SUBSCRIPTION,
		  "Local: Existing subscription"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__ASSIGN_PARTITIONS,
		  "Local: Assign partitions"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__REVOKE_PARTITIONS,
		  "Local: Revoke partitions"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__CONFLICT,
		  "Local: Conflicting use"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__STATE,
		  "Local: Erroneous state"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__UNKNOWN_PROTOCOL,
		  "Local: Unknown protocol"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__NOT_IMPLEMENTED,
		  "Local: Not implemented"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__AUTHENTICATION,
		  "Local: Authentication failure"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__NO_OFFSET,
		  "Local: No offset stored"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__OUTDATED,
		  "Local: Outdated"),
	_ERR_DESC(RD_KAFKA_RESP_ERR__TIMED_OUT_QUEUE,
		  "Local: Timed out in queue"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__UNSUPPORTED_FEATURE,
                  "Local: Required feature not supported by broker"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__WAIT_CACHE,
                  "Local: Awaiting cache update"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__INTR,
                  "Local: Operation interrupted"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__KEY_SERIALIZATION,
                  "Local: Key serialization error"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__VALUE_SERIALIZATION,
                  "Local: Value serialization error"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__KEY_DESERIALIZATION,
                  "Local: Key deserialization error"),
        _ERR_DESC(RD_KAFKA_RESP_ERR__VALUE_DESERIALIZATION,
                  "Local: Value deserialization error"),

	_ERR_DESC(RD_KAFKA_RESP_ERR_UNKNOWN,
		  "Unknown broker error"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_NO_ERROR,
		  "Success"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_OFFSET_OUT_OF_RANGE,
		  "Broker: Offset out of range"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_MSG,
		  "Broker: Invalid message"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_UNKNOWN_TOPIC_OR_PART,
		  "Broker: Unknown topic or partition"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_MSG_SIZE,
		  "Broker: Invalid message size"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_LEADER_NOT_AVAILABLE,
		  "Broker: Leader not available"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_NOT_LEADER_FOR_PARTITION,
		  "Broker: Not leader for partition"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_REQUEST_TIMED_OUT,
		  "Broker: Request timed out"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_BROKER_NOT_AVAILABLE,
		  "Broker: Broker not available"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_REPLICA_NOT_AVAILABLE,
		  "Broker: Replica not available"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE,
		  "Broker: Message size too large"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_STALE_CTRL_EPOCH,
		  "Broker: StaleControllerEpochCode"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_OFFSET_METADATA_TOO_LARGE,
		  "Broker: Offset metadata string too large"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_NETWORK_EXCEPTION,
		  "Broker: Broker disconnected before response received"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_GROUP_LOAD_IN_PROGRESS,
		  "Broker: Group coordinator load in progress"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_GROUP_COORDINATOR_NOT_AVAILABLE,
		  "Broker: Group coordinator not available"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_NOT_COORDINATOR_FOR_GROUP,
		  "Broker: Not coordinator for group"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_TOPIC_EXCEPTION,
		  "Broker: Invalid topic"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_RECORD_LIST_TOO_LARGE,
		  "Broker: Message batch larger than configured server "
		  "segment size"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS,
		  "Broker: Not enough in-sync replicas"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_NOT_ENOUGH_REPLICAS_AFTER_APPEND,
		  "Broker: Message(s) written to insufficient number of "
		  "in-sync replicas"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_REQUIRED_ACKS,
		  "Broker: Invalid required acks value"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_ILLEGAL_GENERATION,
		  "Broker: Specified group generation id is not valid"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_INCONSISTENT_GROUP_PROTOCOL,
		  "Broker: Inconsistent group protocol"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_GROUP_ID,
		  "Broker: Invalid group.id"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_UNKNOWN_MEMBER_ID,
		  "Broker: Unknown member"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_SESSION_TIMEOUT,
		  "Broker: Invalid session timeout"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_REBALANCE_IN_PROGRESS,
		  "Broker: Group rebalance in progress"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_COMMIT_OFFSET_SIZE,
		  "Broker: Commit offset data size is not valid"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_TOPIC_AUTHORIZATION_FAILED,
		  "Broker: Topic authorization failed"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_GROUP_AUTHORIZATION_FAILED,
		  "Broker: Group authorization failed"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_CLUSTER_AUTHORIZATION_FAILED,
		  "Broker: Cluster authorization failed"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_TIMESTAMP,
		  "Broker: Invalid timestamp"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_UNSUPPORTED_SASL_MECHANISM,
		  "Broker: Unsupported SASL mechanism"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_ILLEGAL_SASL_STATE,
		  "Broker: Request not valid in current SASL state"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_UNSUPPORTED_VERSION,
		  "Broker: API version not supported"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_TOPIC_ALREADY_EXISTS,
		  "Broker: Topic already exists"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_PARTITIONS,
		  "Broker: Invalid number of partitions"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_REPLICATION_FACTOR,
		  "Broker: Invalid replication factor"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_REPLICA_ASSIGNMENT,
		  "Broker: Invalid replica assignment"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_CONFIG,
		  "Broker: Configuration is invalid"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_NOT_CONTROLLER,
		  "Broker: Not controller for cluster"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_REQUEST,
		  "Broker: Invalid request"),
	_ERR_DESC(RD_KAFKA_RESP_ERR_UNSUPPORTED_FOR_MESSAGE_FORMAT,
		  "Broker: Message format on broker does not support request"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_POLICY_VIOLATION,
                  "Broker: Isolation policy volation"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_OUT_OF_ORDER_SEQUENCE_NUMBER,
                  "Broker: Broker received an out of order sequence number"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_DUPLICATE_SEQUENCE_NUMBER,
                  "Broker: Broker received a duplicate sequence number"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_PRODUCER_EPOCH,
                  "Broker: Producer attempted an operation with an old epoch"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_TXN_STATE,
                  "Broker: Producer attempted a transactional operation in "
                  "an invalid state"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_PRODUCER_ID_MAPPING,
                  "Broker: Producer attempted to use a producer id which is "
                  "not currently assigned to its transactional id"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_INVALID_TRANSACTION_TIMEOUT,
                  "Broker: Transaction timeout is larger than the maximum "
                  "value allowed by the broker's max.transaction.timeout.ms"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_CONCURRENT_TRANSACTIONS,
                  "Broker: Producer attempted to update a transaction while "
                  "another concurrent operation on the same transaction was "
                  "ongoing"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_TRANSACTION_COORDINATOR_FENCED,
                  "Broker: Indicates that the transaction coordinator sending "
                  "a WriteTxnMarker is no longer the current coordinator for "
                  "a given producer"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_TRANSACTIONAL_ID_AUTHORIZATION_FAILED,
                  "Broker: Transactional Id authorization failed"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_SECURITY_DISABLED,
                  "Broker: Security features are disabled"),
        _ERR_DESC(RD_KAFKA_RESP_ERR_OPERATION_NOT_ATTEMPTED,
                  "Broker: Operation not attempted"),

	_ERR_DESC(RD_KAFKA_RESP_ERR__END, NULL)
};


void rd_kafka_get_err_descs (const struct rd_kafka_err_desc **errdescs,
			     size_t *cntp) {
	*errdescs = rd_kafka_err_descs;
	*cntp = RD_ARRAYSIZE(rd_kafka_err_descs);
}


const char *rd_kafka_err2str (rd_kafka_resp_err_t err) {
	static RD_TLS char ret[32];
	int idx = err - RD_KAFKA_RESP_ERR__BEGIN;

	if (unlikely(err <= RD_KAFKA_RESP_ERR__BEGIN ||
		     err >= RD_KAFKA_RESP_ERR_END_ALL ||
		     !rd_kafka_err_descs[idx].desc)) {
		rd_snprintf(ret, sizeof(ret), "Err-%i?", err);
		return ret;
	}

	return rd_kafka_err_descs[idx].desc;
}


const char *rd_kafka_err2name (rd_kafka_resp_err_t err) {
	static RD_TLS char ret[32];
	int idx = err - RD_KAFKA_RESP_ERR__BEGIN;

	if (unlikely(err <= RD_KAFKA_RESP_ERR__BEGIN ||
		     err >= RD_KAFKA_RESP_ERR_END_ALL ||
		     !rd_kafka_err_descs[idx].desc)) {
		rd_snprintf(ret, sizeof(ret), "ERR_%i?", err);
		return ret;
	}

	return rd_kafka_err_descs[idx].name;
}


rd_kafka_resp_err_t rd_kafka_last_error (void) {
	return rd_kafka_last_error_code;
}


rd_kafka_resp_err_t rd_kafka_errno2err (int errnox) {
	switch (errnox)
	{
	case EINVAL:
		return RD_KAFKA_RESP_ERR__INVALID_ARG;

        case EBUSY:
                return RD_KAFKA_RESP_ERR__CONFLICT;

	case ENOENT:
		return RD_KAFKA_RESP_ERR__UNKNOWN_TOPIC;

	case ESRCH:
		return RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;

	case ETIMEDOUT:
		return RD_KAFKA_RESP_ERR__TIMED_OUT;

	case EMSGSIZE:
		return RD_KAFKA_RESP_ERR_MSG_SIZE_TOO_LARGE;

	case ENOBUFS:
		return RD_KAFKA_RESP_ERR__QUEUE_FULL;

	default:
		return RD_KAFKA_RESP_ERR__FAIL;
	}
}



/**
 * @brief Final destructor for rd_kafka_t, must only be called with refcnt 0.
 *
 * @locality application thread
 */
void rd_kafka_destroy_final (rd_kafka_t *rk) {

        rd_kafka_assert(rk, rd_atomic32_get(&rk->rk_terminate) != 0);

        /* Synchronize state */
        rd_kafka_wrlock(rk);
        rd_kafka_wrunlock(rk);

        rd_kafka_assignors_term(rk);

        rd_kafka_metadata_cache_destroy(rk);

        rd_kafka_timers_destroy(&rk->rk_timers);

        rd_kafka_dbg(rk, GENERIC, "TERMINATE", "Destroying op queues");

        /* Destroy cgrp */
        if (rk->rk_cgrp) {
                rd_kafka_dbg(rk, GENERIC, "TERMINATE",
                             "Destroying cgrp");
                /* Reset queue forwarding (rep -> cgrp) */
                rd_kafka_q_fwd_set(rk->rk_rep, NULL);
                rd_kafka_cgrp_destroy_final(rk->rk_cgrp);
        }

	/* Purge op-queues */
	rd_kafka_q_destroy(rk->rk_rep);
	rd_kafka_q_destroy(rk->rk_ops);

#if WITH_SSL
	if (rk->rk_conf.ssl.ctx) {
                rd_kafka_dbg(rk, GENERIC, "TERMINATE", "Destroying SSL CTX");
                rd_kafka_transport_ssl_ctx_term(rk);
        }
#endif

        /* It is not safe to log after this point. */
        rd_kafka_dbg(rk, GENERIC, "TERMINATE",
                     "Termination done: freeing resources");

        if (rk->rk_logq) {
                rd_kafka_q_destroy(rk->rk_logq);
                rk->rk_logq = NULL;
        }

        if (rk->rk_type == RD_KAFKA_PRODUCER) {
		cnd_destroy(&rk->rk_curr_msgs.cnd);
		mtx_destroy(&rk->rk_curr_msgs.lock);
	}

	cnd_destroy(&rk->rk_broker_state_change_cnd);
	mtx_destroy(&rk->rk_broker_state_change_lock);

	if (rk->rk_full_metadata)
		rd_kafka_metadata_destroy(rk->rk_full_metadata);
        rd_kafkap_str_destroy(rk->rk_client_id);
        rd_kafkap_str_destroy(rk->rk_group_id);
        rd_kafkap_str_destroy(rk->rk_eos.TransactionalId);
	rd_kafka_anyconf_destroy(_RK_GLOBAL, &rk->rk_conf);
        rd_list_destroy(&rk->rk_broker_by_id);

	rd_kafkap_bytes_destroy((rd_kafkap_bytes_t *)rk->rk_null_bytes);
	rwlock_destroy(&rk->rk_lock);

	rd_free(rk);
	rd_kafka_global_cnt_decr();
}


static void rd_kafka_destroy_app (rd_kafka_t *rk, int blocking) {
        thrd_t thrd;
#ifndef _MSC_VER
	int term_sig = rk->rk_conf.term_sig;
#endif
        rd_kafka_dbg(rk, ALL, "DESTROY", "Terminating instance");

        /* The legacy/simple consumer lacks an API to close down the consumer*/
        if (rk->rk_cgrp) {
                rd_kafka_dbg(rk, GENERIC, "TERMINATE",
                             "Closing consumer group");
                rd_kafka_consumer_close(rk);
        }

        rd_kafka_dbg(rk, GENERIC, "TERMINATE", "Interrupting timers");
        rd_kafka_wrlock(rk);
        thrd = rk->rk_thread;
	rd_atomic32_add(&rk->rk_terminate, 1);
        rd_kafka_timers_interrupt(&rk->rk_timers);
        rd_kafka_wrunlock(rk);

        rd_kafka_dbg(rk, GENERIC, "TERMINATE",
                     "Sending TERMINATE to main background thread");
        /* Send op to trigger queue/io wake-up.
         * The op itself is (likely) ignored by the receiver. */
        rd_kafka_q_enq(rk->rk_ops, rd_kafka_op_new(RD_KAFKA_OP_TERMINATE));

	rd_kafka_brokers_broadcast_state_change(rk);

#ifndef _MSC_VER
        /* Interrupt main kafka thread to speed up termination. */
	if (term_sig) {
                rd_kafka_dbg(rk, GENERIC, "TERMINATE",
                             "Sending thread kill signal %d", term_sig);
                pthread_kill(thrd, term_sig);
        }
#endif

        if (!blocking)
                return; /* FIXME: thread resource leak */

        rd_kafka_dbg(rk, GENERIC, "TERMINATE",
                     "Joining main background thread");

        if (thrd_join(thrd, NULL) != thrd_success)
                rd_kafka_assert(NULL, !*"failed to join main thread");

        rd_kafka_destroy_final(rk);
}


/* NOTE: Must only be called by application.
 *       librdkafka itself must use rd_kafka_destroy0(). */
void rd_kafka_destroy (rd_kafka_t *rk) {
        rd_kafka_destroy_app(rk, 1);
}


/**
 * Main destructor for rd_kafka_t
 *
 * Locality: rdkafka main thread or application thread during rd_kafka_new()
 */
static void rd_kafka_destroy_internal (rd_kafka_t *rk) {
	rd_kafka_itopic_t *rkt, *rkt_tmp;
	rd_kafka_broker_t *rkb, *rkb_tmp;
        rd_list_t wait_thrds;
        thrd_t *thrd;
        int i;

        rd_kafka_dbg(rk, ALL, "DESTROY", "Destroy internal");

        /* Call on_destroy() interceptors */
        rd_kafka_interceptors_on_destroy(rk);

	/* Brokers pick up on rk_terminate automatically. */

        /* List of (broker) threads to join to synchronize termination */
        rd_list_init(&wait_thrds, rd_atomic32_get(&rk->rk_broker_cnt), NULL);

	rd_kafka_wrlock(rk);

        rd_kafka_dbg(rk, ALL, "DESTROY", "Removing all topics");
	/* Decommission all topics */
	TAILQ_FOREACH_SAFE(rkt, &rk->rk_topics, rkt_link, rkt_tmp) {
		rd_kafka_wrunlock(rk);
		rd_kafka_topic_partitions_remove(rkt);
		rd_kafka_wrlock(rk);
	}

        /* Decommission brokers.
         * Broker thread holds a refcount and detects when broker refcounts
         * reaches 1 and then decommissions itself. */
        TAILQ_FOREACH_SAFE(rkb, &rk->rk_brokers, rkb_link, rkb_tmp) {
                /* Add broker's thread to wait_thrds list for later joining */
                thrd = malloc(sizeof(*thrd));
                *thrd = rkb->rkb_thread;
                rd_list_add(&wait_thrds, thrd);
                rd_kafka_wrunlock(rk);

                /* Send op to trigger queue/io wake-up.
                 * The op itself is (likely) ignored by the broker thread. */
                rd_kafka_q_enq(rkb->rkb_ops,
                               rd_kafka_op_new(RD_KAFKA_OP_TERMINATE));

#ifndef _MSC_VER
                /* Interrupt IO threads to speed up termination. */
                if (rk->rk_conf.term_sig)
			pthread_kill(rkb->rkb_thread, rk->rk_conf.term_sig);
#endif

                rd_kafka_broker_destroy(rkb);

                rd_kafka_wrlock(rk);
        }

        if (rk->rk_clusterid) {
                rd_free(rk->rk_clusterid);
                rk->rk_clusterid = NULL;
        }

        rd_kafka_wrunlock(rk);

        rd_kafka_dbg(rk, GENERIC, "TERMINATE",
                     "Purging reply queue");

	/* Purge op-queue */
        rd_kafka_q_disable(rk->rk_rep);
	rd_kafka_q_purge(rk->rk_rep);

	/* Loose our special reference to the internal broker. */
        mtx_lock(&rk->rk_internal_rkb_lock);
	if ((rkb = rk->rk_internal_rkb)) {
                rd_kafka_dbg(rk, GENERIC, "TERMINATE",
                             "Decommissioning internal broker");

                /* Send op to trigger queue wake-up. */
                rd_kafka_q_enq(rkb->rkb_ops,
                               rd_kafka_op_new(RD_KAFKA_OP_TERMINATE));

                rk->rk_internal_rkb = NULL;
                thrd = malloc(sizeof(*thrd));
                *thrd = rkb->rkb_thread;
                rd_list_add(&wait_thrds, thrd);
        }
        mtx_unlock(&rk->rk_internal_rkb_lock);
	if (rkb)
		rd_kafka_broker_destroy(rkb);


        rd_kafka_dbg(rk, GENERIC, "TERMINATE",
                     "Join %d broker thread(s)", rd_list_cnt(&wait_thrds));

        /* Join broker threads */
        RD_LIST_FOREACH(thrd, &wait_thrds, i) {
                if (thrd_join(*thrd, NULL) != thrd_success)
                        ;
                free(thrd);
        }

        rd_list_destroy(&wait_thrds);
}


/* Stats buffer printf */
#define _st_printf(...) do {					\
		ssize_t r;					\
		ssize_t rem = size-of;				\
		r = rd_snprintf(buf+of, rem, __VA_ARGS__);	\
		if (r >= rem) {					\
			size *= 2;				\
			rem = size-of;				\
			buf = rd_realloc(buf, size);		\
			r = rd_snprintf(buf+of, rem, __VA_ARGS__);	\
		}						\
		of += r;					\
	} while (0)

/**
 * Emit stats for toppar
 */
static RD_INLINE void rd_kafka_stats_emit_toppar (char **bufp, size_t *sizep,
					       size_t *ofp,
					       rd_kafka_toppar_t *rktp,
					       int first) {
	char *buf = *bufp;
	size_t size = *sizep;
	size_t of = *ofp;
        int64_t consumer_lag = -1;
        struct offset_stats offs;
        int32_t leader_nodeid = -1;

        rd_kafka_toppar_lock(rktp);

        if (rktp->rktp_leader) {
                rd_kafka_broker_lock(rktp->rktp_leader);
                leader_nodeid = rktp->rktp_leader->rkb_nodeid;
                rd_kafka_broker_unlock(rktp->rktp_leader);
        }

        /* Grab a copy of the latest finalized offset stats */
        offs = rktp->rktp_offsets_fin;

        if (rktp->rktp_hi_offset != RD_KAFKA_OFFSET_INVALID &&
            rktp->rktp_app_offset >= 0) {
                if (unlikely(rktp->rktp_app_offset > rktp->rktp_hi_offset))
                        consumer_lag = 0;
                else
                        consumer_lag = rktp->rktp_hi_offset -
                                rktp->rktp_app_offset;
        }

	_st_printf("%s\"%"PRId32"\": { "
		   "\"partition\":%"PRId32", "
		   "\"leader\":%"PRId32", "
		   "\"desired\":%s, "
		   "\"unknown\":%s, "
		   "\"msgq_cnt\":%i, "
		   "\"msgq_bytes\":%"PRIu64", "
		   "\"xmit_msgq_cnt\":%i, "
		   "\"xmit_msgq_bytes\":%"PRIu64", "
		   "\"fetchq_cnt\":%i, "
		   "\"fetchq_size\":%"PRIu64", "
		   "\"fetch_state\":\"%s\", "
		   "\"query_offset\":%"PRId64", "
		   "\"next_offset\":%"PRId64", "
		   "\"app_offset\":%"PRId64", "
		   "\"stored_offset\":%"PRId64", "
		   "\"commited_offset\":%"PRId64", " /*FIXME: issue #80 */
		   "\"committed_offset\":%"PRId64", "
		   "\"eof_offset\":%"PRId64", "
		   "\"lo_offset\":%"PRId64", "
		   "\"hi_offset\":%"PRId64", "
                   "\"consumer_lag\":%"PRId64", "
		   "\"txmsgs\":%"PRIu64", "
		   "\"txbytes\":%"PRIu64", "
                   "\"msgs\": %"PRIu64", "
                   "\"rx_ver_drops\": %"PRIu64" "
		   "} ",
		   first ? "" : ", ",
		   rktp->rktp_partition,
		   rktp->rktp_partition,
                   leader_nodeid,
		   (rktp->rktp_flags&RD_KAFKA_TOPPAR_F_DESIRED)?"true":"false",
		   (rktp->rktp_flags&RD_KAFKA_TOPPAR_F_UNKNOWN)?"true":"false",
		   rd_atomic32_get(&rktp->rktp_msgq.rkmq_msg_cnt),
		   rd_atomic64_get(&rktp->rktp_msgq.rkmq_msg_bytes),
		   rd_atomic32_get(&rktp->rktp_xmit_msgq.rkmq_msg_cnt),
		   rd_atomic64_get(&rktp->rktp_xmit_msgq.rkmq_msg_bytes),
		   rd_kafka_q_len(rktp->rktp_fetchq),
		   rd_kafka_q_size(rktp->rktp_fetchq),
		   rd_kafka_fetch_states[rktp->rktp_fetch_state],
		   rktp->rktp_query_offset,
                   offs.fetch_offset,
		   rktp->rktp_app_offset,
		   rktp->rktp_stored_offset,
		   rktp->rktp_committed_offset, /* FIXME: issue #80 */
		   rktp->rktp_committed_offset,
                   offs.eof_offset,
		   rktp->rktp_lo_offset,
		   rktp->rktp_hi_offset,
                   consumer_lag,
                   rd_atomic64_get(&rktp->rktp_c.tx_msgs),
		   rd_atomic64_get(&rktp->rktp_c.tx_bytes),
		   rd_atomic64_get(&rktp->rktp_c.msgs),
                   rd_atomic64_get(&rktp->rktp_c.rx_ver_drops));

        rd_kafka_toppar_unlock(rktp);

	*bufp = buf;
	*sizep = size;
	*ofp = of;
}

/**
 * Emit all statistics
 */
static void rd_kafka_stats_emit_all (rd_kafka_t *rk) {
	char  *buf;
	size_t size = 1024*10;
	size_t of = 0;
	rd_kafka_broker_t *rkb;
	rd_kafka_itopic_t *rkt;
	shptr_rd_kafka_toppar_t *s_rktp;
	rd_ts_t now;
	rd_kafka_op_t *rko;
	unsigned int tot_cnt;
	size_t tot_size;

	buf = rd_malloc(size);


	rd_kafka_curr_msgs_get(rk, &tot_cnt, &tot_size);
	rd_kafka_rdlock(rk);

	now = rd_clock();
	_st_printf("{ "
                   "\"name\": \"%s\", "
                   "\"type\": \"%s\", "
		   "\"ts\":%"PRId64", "
		   "\"time\":%lli, "
		   "\"replyq\":%i, "
                   "\"msg_cnt\":%u, "
		   "\"msg_size\":%"PRIusz", "
                   "\"msg_max\":%u, "
		   "\"msg_size_max\":%"PRIusz", "
                   "\"simple_cnt\":%i, "
                   "\"metadata_cache_cnt\":%i, "
		   "\"brokers\":{ "/*open brokers*/,
                   rk->rk_name,
                   rd_kafka_type2str(rk->rk_type),
		   now,
		   (signed long long)time(NULL),
		   rd_kafka_q_len(rk->rk_rep),
		   tot_cnt, tot_size,
		   rk->rk_curr_msgs.max_cnt, rk->rk_curr_msgs.max_size,
                   rd_atomic32_get(&rk->rk_simple_cnt),
                   rk->rk_metadata_cache.rkmc_cnt);


	TAILQ_FOREACH(rkb, &rk->rk_brokers, rkb_link) {
		rd_avg_t rtt, throttle, int_latency;
		rd_kafka_toppar_t *rktp;

		rd_kafka_broker_lock(rkb);
		rd_avg_rollover(&int_latency, &rkb->rkb_avg_int_latency);
		rd_avg_rollover(&rtt, &rkb->rkb_avg_rtt);
		rd_avg_rollover(&throttle, &rkb->rkb_avg_throttle);
		_st_printf("%s\"%s\": { "/*open broker*/
			   "\"name\":\"%s\", "
			   "\"nodeid\":%"PRId32", "
			   "\"state\":\"%s\", "
                           "\"stateage\":%"PRId64", "
			   "\"outbuf_cnt\":%i, "
			   "\"outbuf_msg_cnt\":%i, "
			   "\"waitresp_cnt\":%i, "
			   "\"waitresp_msg_cnt\":%i, "
			   "\"tx\":%"PRIu64", "
			   "\"txbytes\":%"PRIu64", "
			   "\"txerrs\":%"PRIu64", "
			   "\"txretries\":%"PRIu64", "
			   "\"req_timeouts\":%"PRIu64", "
			   "\"rx\":%"PRIu64", "
			   "\"rxbytes\":%"PRIu64", "
			   "\"rxerrs\":%"PRIu64", "
                           "\"rxcorriderrs\":%"PRIu64", "
                           "\"rxpartial\":%"PRIu64", "
                           "\"zbuf_grow\":%"PRIu64", "
                           "\"buf_grow\":%"PRIu64", "
                           "\"wakeups\":%"PRIu64", "
			   "\"int_latency\": {"
			   " \"min\":%"PRId64","
			   " \"max\":%"PRId64","
			   " \"avg\":%"PRId64","
			   " \"sum\":%"PRId64","
			   " \"cnt\":%i "
			   "}, "
			   "\"rtt\": {"
			   " \"min\":%"PRId64","
			   " \"max\":%"PRId64","
			   " \"avg\":%"PRId64","
			   " \"sum\":%"PRId64","
			   " \"cnt\":%i "
			   "}, "
			   "\"throttle\": {"
			   " \"min\":%"PRId64","
			   " \"max\":%"PRId64","
			   " \"avg\":%"PRId64","
			   " \"sum\":%"PRId64","
			   " \"cnt\":%i "
			   "}, "
			   "\"toppars\":{ "/*open toppars*/,
			   rkb == TAILQ_FIRST(&rk->rk_brokers) ? "" : ", ",
			   rkb->rkb_name,
			   rkb->rkb_name,
			   rkb->rkb_nodeid,
			   rd_kafka_broker_state_names[rkb->rkb_state],
                           rkb->rkb_ts_state ? now - rkb->rkb_ts_state : 0,
			   rd_atomic32_get(&rkb->rkb_outbufs.rkbq_cnt),
			   rd_atomic32_get(&rkb->rkb_outbufs.rkbq_msg_cnt),
			   rd_atomic32_get(&rkb->rkb_waitresps.rkbq_cnt),
			   rd_atomic32_get(&rkb->rkb_waitresps.rkbq_msg_cnt),
			   rd_atomic64_get(&rkb->rkb_c.tx),
			   rd_atomic64_get(&rkb->rkb_c.tx_bytes),
			   rd_atomic64_get(&rkb->rkb_c.tx_err),
			   rd_atomic64_get(&rkb->rkb_c.tx_retries),
			   rd_atomic64_get(&rkb->rkb_c.req_timeouts),
			   rd_atomic64_get(&rkb->rkb_c.rx),
			   rd_atomic64_get(&rkb->rkb_c.rx_bytes),
			   rd_atomic64_get(&rkb->rkb_c.rx_err),
			   rd_atomic64_get(&rkb->rkb_c.rx_corrid_err),
			   rd_atomic64_get(&rkb->rkb_c.rx_partial),
                           rd_atomic64_get(&rkb->rkb_c.zbuf_grow),
                           rd_atomic64_get(&rkb->rkb_c.buf_grow),
                           rd_atomic64_get(&rkb->rkb_c.wakeups),
			   int_latency.ra_v.minv,
			   int_latency.ra_v.maxv,
			   int_latency.ra_v.avg,
			   int_latency.ra_v.sum,
			   int_latency.ra_v.cnt,
			   rtt.ra_v.minv,
			   rtt.ra_v.maxv,
			   rtt.ra_v.avg,
			   rtt.ra_v.sum,
			   rtt.ra_v.cnt,
			   throttle.ra_v.minv,
			   throttle.ra_v.maxv,
			   throttle.ra_v.avg,
			   throttle.ra_v.sum,
			   throttle.ra_v.cnt);

		TAILQ_FOREACH(rktp, &rkb->rkb_toppars, rktp_rkblink) {
			_st_printf("%s\"%.*s-%"PRId32"\": { "
				   "\"topic\":\"%.*s\", "
				   "\"partition\":%"PRId32"} ",
				   rktp==TAILQ_FIRST(&rkb->rkb_toppars)?"":", ",
				   RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                                   rktp->rktp_partition,
				   RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
				   rktp->rktp_partition);
		}

		rd_kafka_broker_unlock(rkb);

		_st_printf("} "/*close toppars*/
			   "} "/*close broker*/);
	}


	_st_printf("}, " /* close "brokers" array */
		   "\"topics\":{ ");

	TAILQ_FOREACH(rkt, &rk->rk_topics, rkt_link) {
		int i, j;

		rd_kafka_topic_rdlock(rkt);
		_st_printf("%s\"%.*s\": { "
			   "\"topic\":\"%.*s\", "
			   "\"metadata_age\":%"PRId64", "
			   "\"partitions\":{ " /*open partitions*/,
			   rkt==TAILQ_FIRST(&rk->rk_topics)?"":", ",
			   RD_KAFKAP_STR_PR(rkt->rkt_topic),
			   RD_KAFKAP_STR_PR(rkt->rkt_topic),
			   rkt->rkt_ts_metadata ?
			   (rd_clock() - rkt->rkt_ts_metadata)/1000 : 0);

		for (i = 0 ; i < rkt->rkt_partition_cnt ; i++)
			rd_kafka_stats_emit_toppar(&buf, &size, &of,
						   rd_kafka_toppar_s2i(rkt->rkt_p[i]),
						   i == 0);

                RD_LIST_FOREACH(s_rktp, &rkt->rkt_desp, j)
			rd_kafka_stats_emit_toppar(&buf, &size, &of,
						   rd_kafka_toppar_s2i(s_rktp),
						   i+j == 0);

                i += j;

		if (rkt->rkt_ua)
			rd_kafka_stats_emit_toppar(&buf, &size, &of,
						   rd_kafka_toppar_s2i(rkt->rkt_ua),
                                                   i++ == 0);
		rd_kafka_topic_rdunlock(rkt);

		_st_printf("} "/*close partitions*/
			   "} "/*close topic*/);

	}
	_st_printf("} "/*close topics*/);

        if (rk->rk_cgrp) {
                rd_kafka_cgrp_t *rkcg = rk->rk_cgrp;
                _st_printf(", \"cgrp\": { "
                           "\"rebalance_age\": %"PRId64", "
                           "\"rebalance_cnt\": %d, "
                           "\"assignment_size\": %d }",
                           rkcg->rkcg_c.ts_rebalance ?
                           (rd_clock() - rkcg->rkcg_c.ts_rebalance)/1000 : 0,
                           rkcg->rkcg_c.rebalance_cnt,
                           rkcg->rkcg_c.assignment_size);
        }
	rd_kafka_rdunlock(rk);

        _st_printf("}"/*close object*/);


	/* Enqueue op for application */
	rko = rd_kafka_op_new(RD_KAFKA_OP_STATS);
        rd_kafka_op_set_prio(rko, RD_KAFKA_PRIO_HIGH);
	rko->rko_u.stats.json = buf;
	rko->rko_u.stats.json_len = of;
	rd_kafka_q_enq(rk->rk_rep, rko);
}



static void rd_kafka_topic_scan_tmr_cb (rd_kafka_timers_t *rkts, void *arg) {
        rd_kafka_t *rk = rkts->rkts_rk;
	rd_kafka_topic_scan_all(rk, rd_clock());
}

static void rd_kafka_stats_emit_tmr_cb (rd_kafka_timers_t *rkts, void *arg) {
        rd_kafka_t *rk = rkts->rkts_rk;
	rd_kafka_stats_emit_all(rk);
}


/**
 * @brief Periodic metadata refresh callback
 *
 * @locality rdkafka main thread
 */
static void rd_kafka_metadata_refresh_cb (rd_kafka_timers_t *rkts, void *arg) {
        rd_kafka_t *rk = rkts->rkts_rk;
        int sparse = 1;

        /* Dont do sparse requests if there is a consumer group with an
         * active subscription since subscriptions need to be able to match
         * on all topics. */
        if (rk->rk_type == RD_KAFKA_CONSUMER && rk->rk_cgrp &&
            rk->rk_cgrp->rkcg_flags & RD_KAFKA_CGRP_F_WILDCARD_SUBSCRIPTION)
                sparse = 0;

        if (sparse)
                rd_kafka_metadata_refresh_known_topics(rk, NULL, 1/*force*/,
                                                       "periodic refresh");
        else
                rd_kafka_metadata_refresh_all(rk, NULL, "periodic refresh");
}


/**
 * Main loop for Kafka handler thread.
 */
static int rd_kafka_thread_main (void *arg) {
        rd_kafka_t *rk = arg;
	rd_kafka_timer_t tmr_topic_scan = RD_ZERO_INIT;
	rd_kafka_timer_t tmr_stats_emit = RD_ZERO_INIT;
	rd_kafka_timer_t tmr_metadata_refresh = RD_ZERO_INIT;

        rd_snprintf(rd_kafka_thread_name, sizeof(rd_kafka_thread_name), "main");

	(void)rd_atomic32_add(&rd_kafka_thread_cnt_curr, 1);

	/* Acquire lock (which was held by thread creator during creation)
	 * to synchronise state. */
	rd_kafka_wrlock(rk);
	rd_kafka_wrunlock(rk);

	rd_kafka_timer_start(&rk->rk_timers, &tmr_topic_scan, 1000000,
			     rd_kafka_topic_scan_tmr_cb, NULL);
	rd_kafka_timer_start(&rk->rk_timers, &tmr_stats_emit,
			     rk->rk_conf.stats_interval_ms * 1000ll,
			     rd_kafka_stats_emit_tmr_cb, NULL);
        if (rk->rk_conf.metadata_refresh_interval_ms > 0)
                rd_kafka_timer_start(&rk->rk_timers, &tmr_metadata_refresh,
                                     rk->rk_conf.metadata_refresh_interval_ms *
                                     1000ll,
                                     rd_kafka_metadata_refresh_cb, NULL);

        if (rk->rk_cgrp) {
                rd_kafka_cgrp_reassign_broker(rk->rk_cgrp);
                rd_kafka_q_fwd_set(rk->rk_cgrp->rkcg_ops, rk->rk_ops);
        }

	while (likely(!rd_kafka_terminating(rk) ||
		      rd_kafka_q_len(rk->rk_ops))) {
                rd_ts_t sleeptime = rd_kafka_timers_next(
                        &rk->rk_timers, 1000*1000/*1s*/, 1/*lock*/);
                rd_kafka_q_serve(rk->rk_ops, (int)(sleeptime / 1000), 0,
                                 RD_KAFKA_Q_CB_CALLBACK, NULL, NULL);
		if (rk->rk_cgrp) /* FIXME: move to timer-triggered */
			rd_kafka_cgrp_serve(rk->rk_cgrp);
		rd_kafka_timers_run(&rk->rk_timers, RD_POLL_NOWAIT);
	}

	rd_kafka_q_disable(rk->rk_ops);
	rd_kafka_q_purge(rk->rk_ops);

        rd_kafka_timer_stop(&rk->rk_timers, &tmr_topic_scan, 1);
        rd_kafka_timer_stop(&rk->rk_timers, &tmr_stats_emit, 1);
        rd_kafka_timer_stop(&rk->rk_timers, &tmr_metadata_refresh, 1);

        /* Synchronise state */
        rd_kafka_wrlock(rk);
        rd_kafka_wrunlock(rk);

        rd_kafka_destroy_internal(rk);

        rd_kafka_dbg(rk, GENERIC, "TERMINATE",
                     "Main background thread exiting");

	rd_atomic32_sub(&rd_kafka_thread_cnt_curr, 1);

	return 0;
}


static void rd_kafka_term_sig_handler (int sig) {
	/* nop */
}


rd_kafka_t *rd_kafka_new (rd_kafka_type_t type, rd_kafka_conf_t *app_conf,
			  char *errstr, size_t errstr_size) {
	rd_kafka_t *rk;
	static rd_atomic32_t rkid;
        rd_kafka_conf_t *conf;
        rd_kafka_resp_err_t ret_err = RD_KAFKA_RESP_ERR_NO_ERROR;
        int ret_errno = 0;
#ifndef _MSC_VER
        sigset_t newset, oldset;
#endif

	call_once(&rd_kafka_global_init_once, rd_kafka_global_init);

        /* rd_kafka_new() takes ownership of the provided \p app_conf
         * object if rd_kafka_new() succeeds.
         * Since \p app_conf is optional we allocate a default configuration
         * object here if \p app_conf is NULL.
         * The configuration object itself is struct-copied later
         * leaving the default *conf pointer to be ready for freeing.
         * In case new() fails and app_conf was specified we will clear out
         * rk_conf to avoid double-freeing from destroy_internal() and the
         * user's eventual call to rd_kafka_conf_destroy().
         * This is all a bit tricky but that's the nature of
         * legacy interfaces. */
        if (!app_conf)
                conf = rd_kafka_conf_new();
        else
                conf = app_conf;

        /* Verify mandatory configuration */
        if (!conf->socket_cb) {
                rd_snprintf(errstr, errstr_size,
                            "Mandatory config property 'socket_cb' not set");
                if (!app_conf)
                        rd_kafka_conf_destroy(conf);
                rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__INVALID_ARG, EINVAL);
                return NULL;
        }

        if (!conf->open_cb) {
                rd_snprintf(errstr, errstr_size,
                            "Mandatory config property 'open_cb' not set");
                if (!app_conf)
                        rd_kafka_conf_destroy(conf);
                rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__INVALID_ARG, EINVAL);
                return NULL;
        }

        if (conf->metadata_max_age_ms == -1) {
                if (conf->metadata_refresh_interval_ms > 0)
                        conf->metadata_max_age_ms =
                                conf->metadata_refresh_interval_ms * 3;
                else /* use default value of refresh * 3 */
                        conf->metadata_max_age_ms = 5*60*1000 * 3;
        }

	rd_kafka_global_cnt_incr();

	/*
	 * Set up the handle.
	 */
	rk = rd_calloc(1, sizeof(*rk));

	rk->rk_type = type;

        /* Struct-copy the config object. */
	rk->rk_conf = *conf;
        if (!app_conf)
                rd_free(conf); /* Free the base config struct only,
                                * not its fields since they were copied to
                                * rk_conf just above. Those fields are
                                * freed from rd_kafka_destroy_internal()
                                * as the rk itself is destroyed. */

        /* Call on_new() interceptors */
        rd_kafka_interceptors_on_new(rk, &rk->rk_conf);

	rwlock_init(&rk->rk_lock);
        mtx_init(&rk->rk_internal_rkb_lock, mtx_plain);

	cnd_init(&rk->rk_broker_state_change_cnd);
	mtx_init(&rk->rk_broker_state_change_lock, mtx_plain);

	rk->rk_rep = rd_kafka_q_new(rk);
	rk->rk_ops = rd_kafka_q_new(rk);
        rk->rk_ops->rkq_serve = rd_kafka_poll_cb;
        rk->rk_ops->rkq_opaque = rk;

        if (rk->rk_conf.log_queue) {
                rk->rk_logq = rd_kafka_q_new(rk);
                rk->rk_logq->rkq_serve = rd_kafka_poll_cb;
                rk->rk_logq->rkq_opaque = rk;
        }

	TAILQ_INIT(&rk->rk_brokers);
	TAILQ_INIT(&rk->rk_topics);
        rd_kafka_timers_init(&rk->rk_timers, rk);
        rd_kafka_metadata_cache_init(rk);

	if (rk->rk_conf.dr_cb || rk->rk_conf.dr_msg_cb)
		rk->rk_conf.enabled_events |= RD_KAFKA_EVENT_DR;
	if (rk->rk_conf.rebalance_cb)
		rk->rk_conf.enabled_events |= RD_KAFKA_EVENT_REBALANCE;
	if (rk->rk_conf.offset_commit_cb)
		rk->rk_conf.enabled_events |= RD_KAFKA_EVENT_OFFSET_COMMIT;

	/* Convenience Kafka protocol null bytes */
	rk->rk_null_bytes = rd_kafkap_bytes_new(NULL, 0);

	if (rk->rk_conf.debug)
                rk->rk_conf.log_level = LOG_DEBUG;

	rd_snprintf(rk->rk_name, sizeof(rk->rk_name), "%s#%s-%i",
                    rk->rk_conf.client_id_str, rd_kafka_type2str(rk->rk_type),
                    rd_atomic32_add(&rkid, 1));

	/* Construct clientid kafka string */
	rk->rk_client_id = rd_kafkap_str_new(rk->rk_conf.client_id_str,-1);

        /* Convert group.id to kafka string (may be NULL) */
        rk->rk_group_id = rd_kafkap_str_new(rk->rk_conf.group_id_str,-1);

        /* Config fixups */
        rk->rk_conf.queued_max_msg_bytes =
                (int64_t)rk->rk_conf.queued_max_msg_kbytes * 1000ll;

	/* Enable api.version.request=true if fallback.broker.version
	 * indicates a supporting broker. */
	if (rd_kafka_ApiVersion_is_queryable(rk->rk_conf.broker_version_fallback))
		rk->rk_conf.api_version_request = 1;

	if (rk->rk_type == RD_KAFKA_PRODUCER) {
		mtx_init(&rk->rk_curr_msgs.lock, mtx_plain);
		cnd_init(&rk->rk_curr_msgs.cnd);
		rk->rk_curr_msgs.max_cnt =
			rk->rk_conf.queue_buffering_max_msgs;
                if ((unsigned long long)rk->rk_conf.queue_buffering_max_kbytes * 1024 >
                    (unsigned long long)SIZE_MAX)
                        rk->rk_curr_msgs.max_size = SIZE_MAX;
                else
                        rk->rk_curr_msgs.max_size =
                        (size_t)rk->rk_conf.queue_buffering_max_kbytes * 1024;
	}

        if (rd_kafka_assignors_init(rk, errstr, errstr_size) == -1) {
                ret_err = RD_KAFKA_RESP_ERR__INVALID_ARG;
                ret_errno = EINVAL;
                goto fail;
        }

        if (rk->rk_conf.security_protocol == RD_KAFKA_PROTO_SASL_SSL ||
            rk->rk_conf.security_protocol == RD_KAFKA_PROTO_SASL_PLAINTEXT) {
                if (rd_kafka_sasl_select_provider(rk,
                                                  errstr, errstr_size) == -1) {
                        ret_err = RD_KAFKA_RESP_ERR__INVALID_ARG;
                        ret_errno = EINVAL;
                        goto fail;
                }
        }

#if WITH_SSL
	if (rk->rk_conf.security_protocol == RD_KAFKA_PROTO_SSL ||
	    rk->rk_conf.security_protocol == RD_KAFKA_PROTO_SASL_SSL) {
		/* Create SSL context */
		if (rd_kafka_transport_ssl_ctx_init(rk, errstr,
						    errstr_size) == -1) {
                        ret_err = RD_KAFKA_RESP_ERR__INVALID_ARG;
                        ret_errno = EINVAL;
                        goto fail;
                }
        }
#endif

	/* Client group, eligible both in consumer and producer mode. */
        if (type == RD_KAFKA_CONSUMER &&
	    RD_KAFKAP_STR_LEN(rk->rk_group_id) > 0)
                rk->rk_cgrp = rd_kafka_cgrp_new(rk,
                                                rk->rk_group_id,
                                                rk->rk_client_id);



#ifndef _MSC_VER
        /* Block all signals in newly created thread.
         * To avoid race condition we block all signals in the calling
         * thread, which the new thread will inherit its sigmask from,
         * and then restore the original sigmask of the calling thread when
         * we're done creating the thread. */
        sigemptyset(&oldset);
        sigfillset(&newset);
	if (rk->rk_conf.term_sig) {
		struct sigaction sa_term = {
			.sa_handler = rd_kafka_term_sig_handler
		};
		sigaction(rk->rk_conf.term_sig, &sa_term, NULL);
	}
        pthread_sigmask(SIG_SETMASK, &newset, &oldset);
#endif

	/* Lock handle here to synchronise state, i.e., hold off
	 * the thread until we've finalized the handle. */
	rd_kafka_wrlock(rk);

	/* Create handler thread */
	if ((thrd_create(&rk->rk_thread,
			 rd_kafka_thread_main, rk)) != thrd_success) {
                ret_err = RD_KAFKA_RESP_ERR__CRIT_SYS_RESOURCE;
                ret_errno = errno;
		if (errstr)
			rd_snprintf(errstr, errstr_size,
				    "Failed to create thread: %s (%i)",
				    rd_strerror(errno), errno);
		rd_kafka_wrunlock(rk);
#ifndef _MSC_VER
                /* Restore sigmask of caller */
                pthread_sigmask(SIG_SETMASK, &oldset, NULL);
#endif
                goto fail;
        }

        rd_kafka_wrunlock(rk);

        rk->rk_eos.PID = -1;
        rk->rk_eos.TransactionalId = rd_kafkap_str_new(NULL, 0);

        mtx_lock(&rk->rk_internal_rkb_lock);
	rk->rk_internal_rkb = rd_kafka_broker_add(rk, RD_KAFKA_INTERNAL,
						  RD_KAFKA_PROTO_PLAINTEXT,
						  "", 0, RD_KAFKA_NODEID_UA);
        mtx_unlock(&rk->rk_internal_rkb_lock);

	/* Add initial list of brokers from configuration */
	if (rk->rk_conf.brokerlist) {
		if (rd_kafka_brokers_add0(rk, rk->rk_conf.brokerlist) == 0)
			rd_kafka_op_err(rk, RD_KAFKA_RESP_ERR__ALL_BROKERS_DOWN,
					"No brokers configured");
	}

#ifndef _MSC_VER
	/* Restore sigmask of caller */
	pthread_sigmask(SIG_SETMASK, &oldset, NULL);
#endif

        /* Free user supplied conf's base pointer on success,
         * but not the actual allocated fields since the struct
         * will have been copied in its entirety above. */
        if (app_conf)
                rd_free(app_conf);
	rd_kafka_set_last_error(0, 0);

        rk->rk_initialized = 1;

	return rk;

fail:
        /*
         * Error out and clean up
         */

        /* If on_new() interceptors have been called we also need
         * to allow interceptor clean-up by calling on_destroy() */
        rd_kafka_interceptors_on_destroy(rk);

        /* If rk_conf is a struct-copy of the application configuration
         * we need to avoid rk_conf fields from being freed from
         * rd_kafka_destroy_internal() since they belong to app_conf.
         * However, there are some internal fields, such as interceptors,
         * that belong to rk_conf and thus needs to be cleaned up.
         * Legacy APIs, sigh.. */
        if (app_conf) {
                rd_kafka_assignors_term(rk);
                rd_kafka_interceptors_destroy(&rk->rk_conf);
                memset(&rk->rk_conf, 0, sizeof(rk->rk_conf));
        }

        rd_atomic32_add(&rk->rk_terminate, 1);
        rd_kafka_destroy_internal(rk);
        rd_kafka_destroy_final(rk);

        rd_kafka_set_last_error(ret_err, ret_errno);

        return NULL;
}





/**
 * Produce a single message.
 * Locality: any application thread
 */
int rd_kafka_produce (rd_kafka_topic_t *rkt, int32_t partition,
		      int msgflags,
		      void *payload, size_t len,
		      const void *key, size_t keylen,
		      void *msg_opaque) {
	return rd_kafka_msg_new(rd_kafka_topic_a2i(rkt), partition,
				msgflags, payload, len,
				key, keylen, msg_opaque);
}


/**
 * Counts usage of the legacy/simple consumer (rd_kafka_consume_start() with
 * friends) since it does not have an API for stopping the cgrp we will need to
 * sort that out automatically in the background when all consumption
 * has stopped.
 *
 * Returns 0 if a  High level consumer is already instantiated
 * which means a Simple consumer cannot co-operate with it, else 1.
 *
 * A rd_kafka_t handle can never migrate from simple to high-level, or
 * vice versa, so we dont need a ..consumer_del().
 */
int rd_kafka_simple_consumer_add (rd_kafka_t *rk) {
        if (rd_atomic32_get(&rk->rk_simple_cnt) < 0)
                return 0;

        return (int)rd_atomic32_add(&rk->rk_simple_cnt, 1);
}




/**
 * rktp fetch is split up in these parts:
 *   * application side:
 *   * broker side (handled by current leader broker thread for rktp):
 *          - the fetch state, initial offset, etc.
 *          - fetching messages, updating fetched offset, etc.
 *          - offset commits
 *
 * Communication between the two are:
 *    app side -> rdkafka main side: rktp_ops
 *    broker thread -> app side: rktp_fetchq
 *
 * There is no shared state between these threads, instead
 * state is communicated through the two op queues, and state synchronization
 * is performed by version barriers.
 *
 */

static RD_UNUSED
int rd_kafka_consume_start0 (rd_kafka_itopic_t *rkt, int32_t partition,
				    int64_t offset, rd_kafka_q_t *rkq) {
	shptr_rd_kafka_toppar_t *s_rktp;

	if (partition < 0) {
		rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION,
					ESRCH);
		return -1;
	}

        if (!rd_kafka_simple_consumer_add(rkt->rkt_rk)) {
		rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__INVALID_ARG, EINVAL);
                return -1;
        }

	rd_kafka_topic_wrlock(rkt);
	s_rktp = rd_kafka_toppar_desired_add(rkt, partition);
	rd_kafka_topic_wrunlock(rkt);

        /* Verify offset */
	if (offset == RD_KAFKA_OFFSET_BEGINNING ||
	    offset == RD_KAFKA_OFFSET_END ||
            offset <= RD_KAFKA_OFFSET_TAIL_BASE) {
                /* logical offsets */

	} else if (offset == RD_KAFKA_OFFSET_STORED) {
		/* offset manager */

                if (rkt->rkt_conf.offset_store_method ==
                    RD_KAFKA_OFFSET_METHOD_BROKER &&
                    RD_KAFKAP_STR_IS_NULL(rkt->rkt_rk->rk_group_id)) {
                        /* Broker based offsets require a group id. */
                        rd_kafka_toppar_destroy(s_rktp);
			rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__INVALID_ARG,
						EINVAL);
                        return -1;
                }

	} else if (offset < 0) {
		rd_kafka_toppar_destroy(s_rktp);
		rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__INVALID_ARG,
					EINVAL);
		return -1;

        }

        rd_kafka_toppar_op_fetch_start(rd_kafka_toppar_s2i(s_rktp), offset,
				       rkq, RD_KAFKA_NO_REPLYQ);

        rd_kafka_toppar_destroy(s_rktp);

	rd_kafka_set_last_error(0, 0);
	return 0;
}




int rd_kafka_consume_start (rd_kafka_topic_t *app_rkt, int32_t partition,
			    int64_t offset) {
        rd_kafka_itopic_t *rkt = rd_kafka_topic_a2i(app_rkt);
        rd_kafka_dbg(rkt->rkt_rk, TOPIC, "START",
                     "Start consuming partition %"PRId32,partition);
 	return rd_kafka_consume_start0(rkt, partition, offset, NULL);
}

int rd_kafka_consume_start_queue (rd_kafka_topic_t *app_rkt, int32_t partition,
				  int64_t offset, rd_kafka_queue_t *rkqu) {
        rd_kafka_itopic_t *rkt = rd_kafka_topic_a2i(app_rkt);

 	return rd_kafka_consume_start0(rkt, partition, offset, rkqu->rkqu_q);
}




static RD_UNUSED int rd_kafka_consume_stop0 (rd_kafka_toppar_t *rktp) {
        rd_kafka_q_t *tmpq = NULL;
        rd_kafka_resp_err_t err;

        rd_kafka_topic_wrlock(rktp->rktp_rkt);
        rd_kafka_toppar_lock(rktp);
	rd_kafka_toppar_desired_del(rktp);
        rd_kafka_toppar_unlock(rktp);
	rd_kafka_topic_wrunlock(rktp->rktp_rkt);

        tmpq = rd_kafka_q_new(rktp->rktp_rkt->rkt_rk);

        rd_kafka_toppar_op_fetch_stop(rktp, RD_KAFKA_REPLYQ(tmpq, 0));

        /* Synchronisation: Wait for stop reply from broker thread */
        err = rd_kafka_q_wait_result(tmpq, RD_POLL_INFINITE);
        rd_kafka_q_destroy(tmpq);

	rd_kafka_set_last_error(err, err ? EINVAL : 0);

	return err ? -1 : 0;
}


int rd_kafka_consume_stop (rd_kafka_topic_t *app_rkt, int32_t partition) {
        rd_kafka_itopic_t *rkt = rd_kafka_topic_a2i(app_rkt);
	shptr_rd_kafka_toppar_t *s_rktp;
        int r;

	if (partition == RD_KAFKA_PARTITION_UA) {
		rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__INVALID_ARG, EINVAL);
		return -1;
	}

	rd_kafka_topic_wrlock(rkt);
	if (!(s_rktp = rd_kafka_toppar_get(rkt, partition, 0)) &&
	    !(s_rktp = rd_kafka_toppar_desired_get(rkt, partition))) {
		rd_kafka_topic_wrunlock(rkt);
		rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION,
					ESRCH);
		return -1;
	}
        rd_kafka_topic_wrunlock(rkt);

        r = rd_kafka_consume_stop0(rd_kafka_toppar_s2i(s_rktp));
	/* set_last_error() called by stop0() */

        rd_kafka_toppar_destroy(s_rktp);

        return r;
}



rd_kafka_resp_err_t rd_kafka_seek (rd_kafka_topic_t *app_rkt,
                                   int32_t partition,
                                   int64_t offset,
                                   int timeout_ms) {
        rd_kafka_itopic_t *rkt = rd_kafka_topic_a2i(app_rkt);
        shptr_rd_kafka_toppar_t *s_rktp;
	rd_kafka_toppar_t *rktp;
        rd_kafka_q_t *tmpq = NULL;
        rd_kafka_resp_err_t err;

        /* FIXME: simple consumer check */

	if (partition == RD_KAFKA_PARTITION_UA)
                return RD_KAFKA_RESP_ERR__INVALID_ARG;

	rd_kafka_topic_rdlock(rkt);
	if (!(s_rktp = rd_kafka_toppar_get(rkt, partition, 0)) &&
	    !(s_rktp = rd_kafka_toppar_desired_get(rkt, partition))) {
		rd_kafka_topic_rdunlock(rkt);
                return RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;
	}
	rd_kafka_topic_rdunlock(rkt);

        if (timeout_ms)
                tmpq = rd_kafka_q_new(rkt->rkt_rk);

        rktp = rd_kafka_toppar_s2i(s_rktp);
        if ((err = rd_kafka_toppar_op_seek(rktp, offset,
					   RD_KAFKA_REPLYQ(tmpq, 0)))) {
                if (tmpq)
                        rd_kafka_q_destroy(tmpq);
                rd_kafka_toppar_destroy(s_rktp);
                return err;
        }

	rd_kafka_toppar_destroy(s_rktp);

        if (tmpq) {
                err = rd_kafka_q_wait_result(tmpq, timeout_ms);
                rd_kafka_q_destroy(tmpq);
                return err;
        }

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}



static ssize_t rd_kafka_consume_batch0 (rd_kafka_q_t *rkq,
					int timeout_ms,
					rd_kafka_message_t **rkmessages,
					size_t rkmessages_size) {
	/* Populate application's rkmessages array. */
	return rd_kafka_q_serve_rkmessages(rkq, timeout_ms,
					   rkmessages, rkmessages_size);
}


ssize_t rd_kafka_consume_batch (rd_kafka_topic_t *app_rkt, int32_t partition,
				int timeout_ms,
				rd_kafka_message_t **rkmessages,
				size_t rkmessages_size) {
        rd_kafka_itopic_t *rkt = rd_kafka_topic_a2i(app_rkt);
	shptr_rd_kafka_toppar_t *s_rktp;
        rd_kafka_toppar_t *rktp;
	ssize_t cnt;

	/* Get toppar */
	rd_kafka_topic_rdlock(rkt);
	s_rktp = rd_kafka_toppar_get(rkt, partition, 0/*no ua on miss*/);
	if (unlikely(!s_rktp))
		s_rktp = rd_kafka_toppar_desired_get(rkt, partition);
	rd_kafka_topic_rdunlock(rkt);

	if (unlikely(!s_rktp)) {
		/* No such toppar known */
		rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION,
					ESRCH);
		return -1;
	}

        rktp = rd_kafka_toppar_s2i(s_rktp);

	/* Populate application's rkmessages array. */
	cnt = rd_kafka_q_serve_rkmessages(rktp->rktp_fetchq, timeout_ms,
					  rkmessages, rkmessages_size);

	rd_kafka_toppar_destroy(s_rktp); /* refcnt from .._get() */

	rd_kafka_set_last_error(0, 0);

	return cnt;
}

ssize_t rd_kafka_consume_batch_queue (rd_kafka_queue_t *rkqu,
				      int timeout_ms,
				      rd_kafka_message_t **rkmessages,
				      size_t rkmessages_size) {
	/* Populate application's rkmessages array. */
	return rd_kafka_consume_batch0(rkqu->rkqu_q, timeout_ms,
				       rkmessages, rkmessages_size);
}


struct consume_ctx {
	void (*consume_cb) (rd_kafka_message_t *rkmessage, void *opaque);
	void *opaque;
};


/**
 * Trampoline for application's consume_cb()
 */
static rd_kafka_op_res_t
rd_kafka_consume_cb (rd_kafka_t *rk,
                     rd_kafka_q_t *rkq,
                     rd_kafka_op_t *rko,
                     rd_kafka_q_cb_type_t cb_type, void *opaque) {
	struct consume_ctx *ctx = opaque;
	rd_kafka_message_t *rkmessage;

        if (unlikely(rd_kafka_op_version_outdated(rko, 0))) {
                rd_kafka_op_destroy(rko);
                return RD_KAFKA_OP_RES_HANDLED;
        }

	rkmessage = rd_kafka_message_get(rko);

	rd_kafka_op_offset_store(rk, rko, rkmessage);

	ctx->consume_cb(rkmessage, ctx->opaque);

        rd_kafka_op_destroy(rko);

        return RD_KAFKA_OP_RES_HANDLED;
}



static rd_kafka_op_res_t
rd_kafka_consume_callback0 (rd_kafka_q_t *rkq, int timeout_ms, int max_cnt,
                            void (*consume_cb) (rd_kafka_message_t
                                                *rkmessage,
                                                void *opaque),
                            void *opaque) {
        struct consume_ctx ctx = { .consume_cb = consume_cb, .opaque = opaque };
        return rd_kafka_q_serve(rkq, timeout_ms, max_cnt,
                                RD_KAFKA_Q_CB_RETURN,
                                rd_kafka_consume_cb, &ctx);

}


int rd_kafka_consume_callback (rd_kafka_topic_t *app_rkt, int32_t partition,
			       int timeout_ms,
			       void (*consume_cb) (rd_kafka_message_t
						   *rkmessage,
						   void *opaque),
			       void *opaque) {
        rd_kafka_itopic_t *rkt = rd_kafka_topic_a2i(app_rkt);
        shptr_rd_kafka_toppar_t *s_rktp;
	rd_kafka_toppar_t *rktp;
	int r;

	/* Get toppar */
	rd_kafka_topic_rdlock(rkt);
	s_rktp = rd_kafka_toppar_get(rkt, partition, 0/*no ua on miss*/);
	if (unlikely(!s_rktp))
		s_rktp = rd_kafka_toppar_desired_get(rkt, partition);
	rd_kafka_topic_rdunlock(rkt);

	if (unlikely(!s_rktp)) {
		/* No such toppar known */
		rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION,
					ESRCH);
		return -1;
	}

        rktp = rd_kafka_toppar_s2i(s_rktp);
	r = rd_kafka_consume_callback0(rktp->rktp_fetchq, timeout_ms,
                                       rkt->rkt_conf.consume_callback_max_msgs,
				       consume_cb, opaque);

	rd_kafka_toppar_destroy(s_rktp);

	rd_kafka_set_last_error(0, 0);

	return r;
}



int rd_kafka_consume_callback_queue (rd_kafka_queue_t *rkqu,
				     int timeout_ms,
				     void (*consume_cb) (rd_kafka_message_t
							 *rkmessage,
							 void *opaque),
				     void *opaque) {
	return rd_kafka_consume_callback0(rkqu->rkqu_q, timeout_ms, 0,
					  consume_cb, opaque);
}


/**
 * Serve queue 'rkq' and return one message.
 * By serving the queue it will also call any registered callbacks
 * registered for matching events, this includes consumer_cb()
 * in which case no message will be returned.
 */
static rd_kafka_message_t *rd_kafka_consume0 (rd_kafka_t *rk,
                                              rd_kafka_q_t *rkq,
					      int timeout_ms) {
	rd_kafka_op_t *rko;
	rd_kafka_message_t *rkmessage = NULL;
	rd_ts_t abs_timeout = rd_timeout_init(timeout_ms);

	rd_kafka_yield_thread = 0;
        while ((rko = rd_kafka_q_pop(rkq,
                                     rd_timeout_remains(abs_timeout), 0))) {
                rd_kafka_op_res_t res;

                res = rd_kafka_poll_cb(rk, rkq, rko,
                                       RD_KAFKA_Q_CB_RETURN, NULL);

                if (res == RD_KAFKA_OP_RES_PASS)
                        break;

                if (unlikely(res == RD_KAFKA_OP_RES_YIELD ||
                            rd_kafka_yield_thread)) {
                        /* Callback called rd_kafka_yield(), we must
                         * stop dispatching the queue and return. */
                        rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__INTR,
                                                EINTR);
                        return NULL;
                }

                /* Message was handled by callback. */
                continue;
        }

	if (!rko) {
		/* Timeout reached with no op returned. */
		rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__TIMED_OUT,
					ETIMEDOUT);
		return NULL;
	}

        rd_kafka_assert(rk,
                        rko->rko_type == RD_KAFKA_OP_FETCH ||
                        rko->rko_type == RD_KAFKA_OP_CONSUMER_ERR);

	/* Get rkmessage from rko */
	rkmessage = rd_kafka_message_get(rko);

	/* Store offset */
	rd_kafka_op_offset_store(rk, rko, rkmessage);

	rd_kafka_set_last_error(0, 0);

	return rkmessage;
}

rd_kafka_message_t *rd_kafka_consume (rd_kafka_topic_t *app_rkt,
                                      int32_t partition,
				      int timeout_ms) {
        rd_kafka_itopic_t *rkt = rd_kafka_topic_a2i(app_rkt);
        shptr_rd_kafka_toppar_t *s_rktp;
	rd_kafka_toppar_t *rktp;
	rd_kafka_message_t *rkmessage;

	rd_kafka_topic_rdlock(rkt);
	s_rktp = rd_kafka_toppar_get(rkt, partition, 0/*no ua on miss*/);
	if (unlikely(!s_rktp))
		s_rktp = rd_kafka_toppar_desired_get(rkt, partition);
	rd_kafka_topic_rdunlock(rkt);

	if (unlikely(!s_rktp)) {
		/* No such toppar known */
		rd_kafka_set_last_error(RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION,
					ESRCH);
		return NULL;
	}

        rktp = rd_kafka_toppar_s2i(s_rktp);
	rkmessage = rd_kafka_consume0(rkt->rkt_rk,
                                      rktp->rktp_fetchq, timeout_ms);

	rd_kafka_toppar_destroy(s_rktp); /* refcnt from .._get() */

	return rkmessage;
}


rd_kafka_message_t *rd_kafka_consume_queue (rd_kafka_queue_t *rkqu,
					    int timeout_ms) {
	return rd_kafka_consume0(rkqu->rkqu_rk, rkqu->rkqu_q, timeout_ms);
}




rd_kafka_resp_err_t rd_kafka_poll_set_consumer (rd_kafka_t *rk) {
        rd_kafka_cgrp_t *rkcg;

        if (!(rkcg = rd_kafka_cgrp_get(rk)))
                return RD_KAFKA_RESP_ERR__UNKNOWN_GROUP;

        rd_kafka_q_fwd_set(rk->rk_rep, rkcg->rkcg_q);
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}




rd_kafka_message_t *rd_kafka_consumer_poll (rd_kafka_t *rk,
                                            int timeout_ms) {
        rd_kafka_cgrp_t *rkcg;

        if (unlikely(!(rkcg = rd_kafka_cgrp_get(rk)))) {
                rd_kafka_message_t *rkmessage = rd_kafka_message_new();
                rkmessage->err = RD_KAFKA_RESP_ERR__UNKNOWN_GROUP;
                return rkmessage;
        }

        return rd_kafka_consume0(rk, rkcg->rkcg_q, timeout_ms);
}


rd_kafka_resp_err_t rd_kafka_consumer_close (rd_kafka_t *rk) {
        rd_kafka_cgrp_t *rkcg;
        rd_kafka_op_t *rko;
        rd_kafka_resp_err_t err = RD_KAFKA_RESP_ERR__TIMED_OUT;
	rd_kafka_q_t *rkq;

        if (!(rkcg = rd_kafka_cgrp_get(rk)))
                return RD_KAFKA_RESP_ERR__UNKNOWN_GROUP;

	/* Redirect cgrp queue to our temporary queue to make sure
	 * all posted ops (e.g., rebalance callbacks) are served by
	 * this function. */
	rkq = rd_kafka_q_new(rk);
	rd_kafka_q_fwd_set(rkcg->rkcg_q, rkq);

        rd_kafka_cgrp_terminate(rkcg, RD_KAFKA_REPLYQ(rkq, 0)); /* async */

        while ((rko = rd_kafka_q_pop(rkq, RD_POLL_INFINITE, 0))) {
                rd_kafka_op_res_t res;
                if ((rko->rko_type & ~RD_KAFKA_OP_FLAGMASK) ==
		    RD_KAFKA_OP_TERMINATE) {
                        err = rko->rko_err;
                        rd_kafka_op_destroy(rko);
                        break;
                }
                res = rd_kafka_poll_cb(rk, rkq, rko,
                                       RD_KAFKA_Q_CB_RETURN, NULL);
                if (res == RD_KAFKA_OP_RES_PASS)
                        rd_kafka_op_destroy(rko);
                /* Ignore YIELD, we need to finish */
        }

        rd_kafka_q_destroy(rkq);

	rd_kafka_q_fwd_set(rkcg->rkcg_q, NULL);

        return err;
}



rd_kafka_resp_err_t
rd_kafka_committed (rd_kafka_t *rk,
		    rd_kafka_topic_partition_list_t *partitions,
		    int timeout_ms) {
        rd_kafka_q_t *rkq;
        rd_kafka_resp_err_t err;
        rd_kafka_cgrp_t *rkcg;
	rd_ts_t abs_timeout = rd_timeout_init(timeout_ms);

        if (!partitions)
                return RD_KAFKA_RESP_ERR__INVALID_ARG;

        if (!(rkcg = rd_kafka_cgrp_get(rk)))
                return RD_KAFKA_RESP_ERR__UNKNOWN_GROUP;

	/* Set default offsets. */
	rd_kafka_topic_partition_list_reset_offsets(partitions,
                                                    RD_KAFKA_OFFSET_INVALID);

	rkq = rd_kafka_q_new(rk);

        do {
                rd_kafka_op_t *rko;
		int state_version = rd_kafka_brokers_get_state_version(rk);

                rko = rd_kafka_op_new(RD_KAFKA_OP_OFFSET_FETCH);
		rd_kafka_op_set_replyq(rko, rkq, NULL);

                /* Issue #827
                 * Copy partition list to avoid use-after-free if we time out
                 * here, the app frees the list, and then cgrp starts
                 * processing the op. */
		rko->rko_u.offset_fetch.partitions =
                        rd_kafka_topic_partition_list_copy(partitions);
		rko->rko_u.offset_fetch.do_free = 1;

                if (!rd_kafka_q_enq(rkcg->rkcg_ops, rko)) {
                        err = RD_KAFKA_RESP_ERR__DESTROY;
                        break;
                }

                rko = rd_kafka_q_pop(rkq, rd_timeout_remains(abs_timeout), 0);
                if (rko) {
                        if (!(err = rko->rko_err))
                                rd_kafka_topic_partition_list_update(
                                        partitions,
                                        rko->rko_u.offset_fetch.partitions);
                        else if ((err == RD_KAFKA_RESP_ERR__WAIT_COORD ||
				    err == RD_KAFKA_RESP_ERR__TRANSPORT) &&
				   !rd_kafka_brokers_wait_state_change(
					   rk, state_version,
					   rd_timeout_remains(abs_timeout)))
				err = RD_KAFKA_RESP_ERR__TIMED_OUT;

                        rd_kafka_op_destroy(rko);
                } else
                        err = RD_KAFKA_RESP_ERR__TIMED_OUT;
        } while (err == RD_KAFKA_RESP_ERR__TRANSPORT ||
		 err == RD_KAFKA_RESP_ERR__WAIT_COORD);

        rd_kafka_q_destroy(rkq);

        return err;
}



rd_kafka_resp_err_t
rd_kafka_position (rd_kafka_t *rk,
		   rd_kafka_topic_partition_list_t *partitions) {
 	int i;

	/* Set default offsets. */
	rd_kafka_topic_partition_list_reset_offsets(partitions,
						    RD_KAFKA_OFFSET_INVALID);

	for (i = 0 ; i < partitions->cnt ; i++) {
		rd_kafka_topic_partition_t *rktpar = &partitions->elems[i];
		shptr_rd_kafka_toppar_t *s_rktp;
		rd_kafka_toppar_t *rktp;

		if (!(s_rktp = rd_kafka_toppar_get2(rk, rktpar->topic,
						    rktpar->partition, 0, 1))) {
			rktpar->err = RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;
			rktpar->offset = RD_KAFKA_OFFSET_INVALID;
			continue;
		}

		rktp = rd_kafka_toppar_s2i(s_rktp);
		rd_kafka_toppar_lock(rktp);
		rktpar->offset = rktp->rktp_app_offset;
		rktpar->err = RD_KAFKA_RESP_ERR_NO_ERROR;
		rd_kafka_toppar_unlock(rktp);
		rd_kafka_toppar_destroy(s_rktp);
	}

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}



struct _query_wmark_offsets_state {
	rd_kafka_resp_err_t err;
	const char *topic;
	int32_t partition;
	int64_t offsets[2];
	int     offidx;  /* next offset to set from response */
	rd_ts_t ts_end;
	int     state_version;  /* Broker state version */
};

static void rd_kafka_query_wmark_offsets_resp_cb (rd_kafka_t *rk,
						  rd_kafka_broker_t *rkb,
						  rd_kafka_resp_err_t err,
						  rd_kafka_buf_t *rkbuf,
						  rd_kafka_buf_t *request,
						  void *opaque) {
	struct _query_wmark_offsets_state *state = opaque;
        rd_kafka_topic_partition_list_t *offsets;
        rd_kafka_topic_partition_t *rktpar;

        offsets = rd_kafka_topic_partition_list_new(1);
        err = rd_kafka_handle_Offset(rk, rkb, err, rkbuf, request, offsets);
        if (err == RD_KAFKA_RESP_ERR__IN_PROGRESS) {
                rd_kafka_topic_partition_list_destroy(offsets);
                return; /* Retrying */
        }

	/* Retry if no broker connection is available yet. */
	if ((err == RD_KAFKA_RESP_ERR__WAIT_COORD ||
	     err == RD_KAFKA_RESP_ERR__TRANSPORT) &&
	    rkb &&
	    rd_kafka_brokers_wait_state_change(
		    rkb->rkb_rk, state->state_version,
		    rd_timeout_remains(state->ts_end))) {
		/* Retry */
		state->state_version = rd_kafka_brokers_get_state_version(rk);
		request->rkbuf_retries = 0;
		if (rd_kafka_buf_retry(rkb, request)) {
                        rd_kafka_topic_partition_list_destroy(offsets);
                        return; /* Retry in progress */
                }
		/* FALLTHRU */
	}

        /* Partition not seen in response. */
        if (!(rktpar = rd_kafka_topic_partition_list_find(offsets,
                                                          state->topic,
                                                          state->partition)))
                err = RD_KAFKA_RESP_ERR__BAD_MSG;
        else if (rktpar->err)
                err = rktpar->err;
        else
                state->offsets[state->offidx] = rktpar->offset;

        state->offidx++;

        if (err || state->offidx == 2) /* Error or Done */
                state->err = err;

        rd_kafka_topic_partition_list_destroy(offsets);
}


rd_kafka_resp_err_t
rd_kafka_query_watermark_offsets (rd_kafka_t *rk, const char *topic,
                                  int32_t partition,
                                  int64_t *low, int64_t *high, int timeout_ms) {
        rd_kafka_q_t *rkq;
        struct _query_wmark_offsets_state state;
        rd_ts_t ts_end = rd_timeout_init(timeout_ms);
        rd_kafka_topic_partition_list_t *partitions;
        rd_kafka_topic_partition_t *rktpar;
        struct rd_kafka_partition_leader *leader;
        rd_list_t leaders;
        rd_kafka_resp_err_t err;

        partitions = rd_kafka_topic_partition_list_new(1);
        rktpar = rd_kafka_topic_partition_list_add(partitions,
                                                   topic, partition);

        rd_list_init(&leaders, partitions->cnt,
                     (void *)rd_kafka_partition_leader_destroy);

        err = rd_kafka_topic_partition_list_query_leaders(rk, partitions,
                                                          &leaders, timeout_ms);
        if (err) {
                         rd_list_destroy(&leaders);
                         rd_kafka_topic_partition_list_destroy(partitions);
                         return err;
        }

        leader = rd_list_elem(&leaders, 0);

        rkq = rd_kafka_q_new(rk);

        /* Due to KAFKA-1588 we need to send a request for each wanted offset,
         * in this case one for the low watermark and one for the high. */
        state.topic = topic;
        state.partition = partition;
        state.offsets[0] = RD_KAFKA_OFFSET_BEGINNING;
        state.offsets[1] = RD_KAFKA_OFFSET_END;
        state.offidx = 0;
        state.err = RD_KAFKA_RESP_ERR__IN_PROGRESS;
        state.ts_end = ts_end;
        state.state_version = rd_kafka_brokers_get_state_version(rk);


        rktpar->offset =  RD_KAFKA_OFFSET_BEGINNING;
        rd_kafka_OffsetRequest(leader->rkb, partitions, 0,
                               RD_KAFKA_REPLYQ(rkq, 0),
                               rd_kafka_query_wmark_offsets_resp_cb,
                               &state);

        rktpar->offset =  RD_KAFKA_OFFSET_END;
        rd_kafka_OffsetRequest(leader->rkb, partitions, 0,
                               RD_KAFKA_REPLYQ(rkq, 0),
                               rd_kafka_query_wmark_offsets_resp_cb,
                               &state);

        rd_kafka_topic_partition_list_destroy(partitions);
        rd_list_destroy(&leaders);

        /* Wait for reply (or timeout) */
        while (state.err == RD_KAFKA_RESP_ERR__IN_PROGRESS &&
               rd_kafka_q_serve(rkq, 100, 0, RD_KAFKA_Q_CB_CALLBACK,
                                rd_kafka_poll_cb, NULL) !=
               RD_KAFKA_OP_RES_YIELD)
                ;

        rd_kafka_q_destroy(rkq);

        if (state.err)
                return state.err;
        else if (state.offidx != 2)
                return RD_KAFKA_RESP_ERR__FAIL;

        /* We are not certain about the returned order. */
        if (state.offsets[0] < state.offsets[1]) {
                *low = state.offsets[0];
                *high  = state.offsets[1];
        } else {
                *low = state.offsets[1];
                *high = state.offsets[0];
        }

        /* If partition is empty only one offset (the last) will be returned. */
        if (*low < 0 && *high >= 0)
                *low = *high;

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


rd_kafka_resp_err_t
rd_kafka_get_watermark_offsets (rd_kafka_t *rk, const char *topic,
				int32_t partition,
				int64_t *low, int64_t *high) {
	shptr_rd_kafka_toppar_t *s_rktp;
	rd_kafka_toppar_t *rktp;

	s_rktp = rd_kafka_toppar_get2(rk, topic, partition, 0, 1);
	if (!s_rktp)
		return RD_KAFKA_RESP_ERR__UNKNOWN_PARTITION;
	rktp = rd_kafka_toppar_s2i(s_rktp);

	rd_kafka_toppar_lock(rktp);
	*low = rktp->rktp_lo_offset;
	*high = rktp->rktp_hi_offset;
	rd_kafka_toppar_unlock(rktp);

	rd_kafka_toppar_destroy(s_rktp);

	return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * @brief get_offsets_for_times() state
 */
struct _get_offsets_for_times {
        rd_kafka_topic_partition_list_t *results;
        rd_kafka_resp_err_t err;
        int wait_reply;
        int state_version;
        rd_ts_t ts_end;
};

/**
 * @brief Handle OffsetRequest responses
 */
static void rd_kafka_get_offsets_for_times_resp_cb (rd_kafka_t *rk,
                                                  rd_kafka_broker_t *rkb,
                                                  rd_kafka_resp_err_t err,
                                                  rd_kafka_buf_t *rkbuf,
                                                  rd_kafka_buf_t *request,
                                                  void *opaque) {
        struct _get_offsets_for_times *state = opaque;

        err = rd_kafka_handle_Offset(rk, rkb, err, rkbuf, request,
                                     state->results);
        if (err == RD_KAFKA_RESP_ERR__IN_PROGRESS)
                return; /* Retrying */

        /* Retry if no broker connection is available yet. */
        if ((err == RD_KAFKA_RESP_ERR__WAIT_COORD ||
             err == RD_KAFKA_RESP_ERR__TRANSPORT) &&
            rkb &&
            rd_kafka_brokers_wait_state_change(
                    rkb->rkb_rk, state->state_version,
                    rd_timeout_remains(state->ts_end))) {
                /* Retry */
                state->state_version = rd_kafka_brokers_get_state_version(rk);
                request->rkbuf_retries = 0;
                if (rd_kafka_buf_retry(rkb, request))
                        return; /* Retry in progress */
                /* FALLTHRU */
        }

        if (err && !state->err)
                state->err = err;

        state->wait_reply--;
}


rd_kafka_resp_err_t
rd_kafka_offsets_for_times (rd_kafka_t *rk,
                            rd_kafka_topic_partition_list_t *offsets,
                            int timeout_ms) {
        rd_kafka_q_t *rkq;
        struct _get_offsets_for_times state = RD_ZERO_INIT;
        rd_ts_t ts_end = rd_timeout_init(timeout_ms);
        rd_list_t leaders;
        int i;
        rd_kafka_resp_err_t err;
        struct rd_kafka_partition_leader *leader;

        if (offsets->cnt == 0)
                return RD_KAFKA_RESP_ERR__INVALID_ARG;

        rd_list_init(&leaders, offsets->cnt,
                     (void *)rd_kafka_partition_leader_destroy);

        err = rd_kafka_topic_partition_list_query_leaders(rk, offsets, &leaders,
                                                          timeout_ms);
        if (err) {
                rd_list_destroy(&leaders);
                return err;
        }


        rkq = rd_kafka_q_new(rk);

        state.wait_reply = 0;
        state.results = rd_kafka_topic_partition_list_new(offsets->cnt);

        /* For each leader send a request for its partitions */
        RD_LIST_FOREACH(leader, &leaders, i) {
                state.wait_reply++;
                rd_kafka_OffsetRequest(leader->rkb, leader->partitions, 1,
                                       RD_KAFKA_REPLYQ(rkq, 0),
                                       rd_kafka_get_offsets_for_times_resp_cb,
                                       &state);
        }

        rd_list_destroy(&leaders);

        /* Wait for reply (or timeout) */
        while (state.wait_reply > 0 && rd_timeout_remains(ts_end) > 0)
                rd_kafka_q_serve(rkq, rd_timeout_remains(ts_end),
                                0, RD_KAFKA_Q_CB_CALLBACK,
                                 rd_kafka_poll_cb, NULL);

        rd_kafka_q_destroy(rkq);

        /* Then update the queried partitions. */
        if (!state.err)
                rd_kafka_topic_partition_list_update(offsets, state.results);

        rd_kafka_topic_partition_list_destroy(state.results);

        return state.err;
}


/**
 * rd_kafka_poll() (and similar) op callback handler.
 * Will either call registered callback depending on cb_type and op type
 * or return op to application, if applicable (e.g., fetch message).
 *
 * Returns 1 if op was handled, else 0.
 *
 * Locality: application thread
 */
rd_kafka_op_res_t
rd_kafka_poll_cb (rd_kafka_t *rk, rd_kafka_q_t *rkq, rd_kafka_op_t *rko,
                  rd_kafka_q_cb_type_t cb_type, void *opaque) {
	rd_kafka_msg_t *rkm;

	/* Return-as-event requested, see if op can be converted to event,
	 * otherwise fall through and trigger callbacks. */
	if (cb_type == RD_KAFKA_Q_CB_EVENT && rd_kafka_event_setup(rk, rko))
		return 0; /* Return as event */

        switch ((int)rko->rko_type)
        {
        case RD_KAFKA_OP_FETCH:
                if (!rk->rk_conf.consume_cb ||
                    cb_type == RD_KAFKA_Q_CB_RETURN ||
                    cb_type == RD_KAFKA_Q_CB_FORCE_RETURN)
                        return RD_KAFKA_OP_RES_PASS; /* Dont handle here */
                else {
                        struct consume_ctx ctx = {
                                .consume_cb = rk->rk_conf.consume_cb,
                                .opaque = rk->rk_conf.opaque };

                        return rd_kafka_consume_cb(rk, rkq, rko, cb_type, &ctx);
                }
                break;

        case RD_KAFKA_OP_REBALANCE:
                /* If EVENT_REBALANCE is enabled but rebalance_cb isnt
                 * we need to perform a dummy assign for the application.
                 * This might happen during termination with consumer_close() */
                if (rk->rk_conf.rebalance_cb)
                        rk->rk_conf.rebalance_cb(
                                rk, rko->rko_err,
                                rko->rko_u.rebalance.partitions,
                                rk->rk_conf.opaque);
                else {
                        rd_kafka_dbg(rk, CGRP, "UNASSIGN",
                                     "Forcing unassign of %d partition(s)",
                                     rko->rko_u.rebalance.partitions ?
                                     rko->rko_u.rebalance.partitions->cnt : 0);
                        rd_kafka_assign(rk, NULL);
                }
                break;

        case RD_KAFKA_OP_OFFSET_COMMIT | RD_KAFKA_OP_REPLY:
		if (!rko->rko_u.offset_commit.cb)
			return RD_KAFKA_OP_RES_PASS; /* Dont handle here */
		rko->rko_u.offset_commit.cb(
                        rk, rko->rko_err,
			rko->rko_u.offset_commit.partitions,
			rko->rko_u.offset_commit.opaque);
                break;

        case RD_KAFKA_OP_CONSUMER_ERR:
                /* rd_kafka_consumer_poll() (_Q_CB_CONSUMER):
                 *   Consumer errors are returned to the application
                 *   as rkmessages, not error callbacks.
                 *
                 * rd_kafka_poll() (_Q_CB_GLOBAL):
                 *   convert to ERR op (fallthru)
                 */
                if (cb_type == RD_KAFKA_Q_CB_RETURN ||
                    cb_type == RD_KAFKA_Q_CB_FORCE_RETURN) {
                        /* return as message_t to application */
                        return RD_KAFKA_OP_RES_PASS;
                }
		/* FALLTHRU */

	case RD_KAFKA_OP_ERR:
		if (rk->rk_conf.error_cb)
			rk->rk_conf.error_cb(rk, rko->rko_err,
					     rko->rko_u.err.errstr,
                                             rk->rk_conf.opaque);
		else
			rd_kafka_log(rk, LOG_ERR, "ERROR",
				     "%s: %s: %s",
				     rk->rk_name,
				     rd_kafka_err2str(rko->rko_err),
				     rko->rko_u.err.errstr);
		break;

	case RD_KAFKA_OP_DR:
		/* Delivery report:
		 * call application DR callback for each message. */
		while ((rkm = TAILQ_FIRST(&rko->rko_u.dr.msgq.rkmq_msgs))) {
                        rd_kafka_message_t *rkmessage;

			TAILQ_REMOVE(&rko->rko_u.dr.msgq.rkmq_msgs,
				     rkm, rkm_link);

                        rkmessage = rd_kafka_message_get_from_rkm(rko, rkm);

                        if (rk->rk_conf.dr_msg_cb) {
                                rk->rk_conf.dr_msg_cb(rk, rkmessage,
                                                      rk->rk_conf.opaque);

                        } else {

                                rk->rk_conf.dr_cb(rk,
                                                  rkmessage->payload,
                                                  rkmessage->len,
                                                  rkmessage->err,
                                                  rk->rk_conf.opaque,
                                                  rkmessage->_private);
                        }

                        rd_kafka_msg_destroy(rk, rkm);

                        if (unlikely(rd_kafka_yield_thread)) {
                                /* Callback called yield(),
                                 * re-enqueue the op (if there are any
                                 * remaining messages). */
                                if (!TAILQ_EMPTY(&rko->rko_u.dr.msgq.
                                                 rkmq_msgs))
                                        rd_kafka_q_reenq(rkq, rko);
                                else
                                        rd_kafka_op_destroy(rko);
                                return RD_KAFKA_OP_RES_YIELD;
                        }
		}

		rd_kafka_msgq_init(&rko->rko_u.dr.msgq);

		break;

	case RD_KAFKA_OP_THROTTLE:
		if (rk->rk_conf.throttle_cb)
			rk->rk_conf.throttle_cb(rk, rko->rko_u.throttle.nodename,
						rko->rko_u.throttle.nodeid,
						rko->rko_u.throttle.
						throttle_time,
						rk->rk_conf.opaque);
		break;

	case RD_KAFKA_OP_STATS:
		/* Statistics */
		if (rk->rk_conf.stats_cb &&
		    rk->rk_conf.stats_cb(rk, rko->rko_u.stats.json,
                                         rko->rko_u.stats.json_len,
					 rk->rk_conf.opaque) == 1)
			rko->rko_u.stats.json = NULL; /* Application wanted json ptr */
		break;

        case RD_KAFKA_OP_LOG:
                if (likely(rk->rk_conf.log_cb &&
                           rk->rk_conf.log_level >= rko->rko_u.log.level))
                        rk->rk_conf.log_cb(rk,
                                           rko->rko_u.log.level,
                                           rko->rko_u.log.fac,
                                           rko->rko_u.log.str);
                break;

        case RD_KAFKA_OP_TERMINATE:
                /* nop: just a wake-up */
                break;

        default:
                rd_kafka_assert(rk, !*"cant handle op type");
                break;
        }

        rd_kafka_op_destroy(rko);

        return 1; /* op was handled */
}

int rd_kafka_poll (rd_kafka_t *rk, int timeout_ms) {
        return rd_kafka_q_serve(rk->rk_rep, timeout_ms, 0,
                                RD_KAFKA_Q_CB_CALLBACK, rd_kafka_poll_cb, NULL);
}


rd_kafka_event_t *rd_kafka_queue_poll (rd_kafka_queue_t *rkqu, int timeout_ms) {
        rd_kafka_op_t *rko;
        rko = rd_kafka_q_pop_serve(rkqu->rkqu_q, timeout_ms, 0,
                                   RD_KAFKA_Q_CB_EVENT, rd_kafka_poll_cb, NULL);
        if (!rko)
                return NULL;

        return rko;
}

int rd_kafka_queue_poll_callback (rd_kafka_queue_t *rkqu, int timeout_ms) {
        return rd_kafka_q_serve(rkqu->rkqu_q, timeout_ms, 0,
                                RD_KAFKA_Q_CB_CALLBACK, rd_kafka_poll_cb, NULL);
}



static void rd_kafka_toppar_dump (FILE *fp, const char *indent,
				  rd_kafka_toppar_t *rktp) {

	fprintf(fp, "%s%.*s [%"PRId32"] leader %s\n",
		indent,
		RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
		rktp->rktp_partition,
		rktp->rktp_leader ?
		rktp->rktp_leader->rkb_name : "none");
	fprintf(fp,
		"%s refcnt %i\n"
		"%s msgq:      %i messages\n"
		"%s xmit_msgq: %i messages\n"
		"%s total:     %"PRIu64" messages, %"PRIu64" bytes\n",
		indent, rd_refcnt_get(&rktp->rktp_refcnt),
		indent, rd_atomic32_get(&rktp->rktp_msgq.rkmq_msg_cnt),
		indent, rd_atomic32_get(&rktp->rktp_xmit_msgq.rkmq_msg_cnt),
		indent, rd_atomic64_get(&rktp->rktp_c.tx_msgs), rd_atomic64_get(&rktp->rktp_c.tx_bytes));
}

static void rd_kafka_broker_dump (FILE *fp, rd_kafka_broker_t *rkb, int locks) {
	rd_kafka_toppar_t *rktp;

        if (locks)
                rd_kafka_broker_lock(rkb);
        fprintf(fp, " rd_kafka_broker_t %p: %s NodeId %"PRId32
                " in state %s (for %.3fs)\n",
                rkb, rkb->rkb_name, rkb->rkb_nodeid,
                rd_kafka_broker_state_names[rkb->rkb_state],
                rkb->rkb_ts_state ?
                (float)(rd_clock() - rkb->rkb_ts_state) / 1000000.0f :
                0.0f);
        fprintf(fp, "  refcnt %i\n", rd_refcnt_get(&rkb->rkb_refcnt));
        fprintf(fp, "  outbuf_cnt: %i waitresp_cnt: %i\n",
                rd_atomic32_get(&rkb->rkb_outbufs.rkbq_cnt),
                rd_atomic32_get(&rkb->rkb_waitresps.rkbq_cnt));
        fprintf(fp,
                "  %"PRIu64 " messages sent, %"PRIu64" bytes, "
                "%"PRIu64" errors, %"PRIu64" timeouts\n"
                "  %"PRIu64 " messages received, %"PRIu64" bytes, "
                "%"PRIu64" errors\n"
                "  %"PRIu64 " messageset transmissions were retried\n",
                rd_atomic64_get(&rkb->rkb_c.tx), rd_atomic64_get(&rkb->rkb_c.tx_bytes),
                rd_atomic64_get(&rkb->rkb_c.tx_err), rd_atomic64_get(&rkb->rkb_c.req_timeouts),
                rd_atomic64_get(&rkb->rkb_c.rx), rd_atomic64_get(&rkb->rkb_c.rx_bytes),
                rd_atomic64_get(&rkb->rkb_c.rx_err),
                rd_atomic64_get(&rkb->rkb_c.tx_retries));

        fprintf(fp, "  %i toppars:\n", rkb->rkb_toppar_cnt);
        TAILQ_FOREACH(rktp, &rkb->rkb_toppars, rktp_rkblink)
                rd_kafka_toppar_dump(fp, "   ", rktp);
        if (locks) {
                rd_kafka_broker_unlock(rkb);
        }
}


static void rd_kafka_dump0 (FILE *fp, rd_kafka_t *rk, int locks) {
	rd_kafka_broker_t *rkb;
	rd_kafka_itopic_t *rkt;
	rd_kafka_toppar_t *rktp;
        shptr_rd_kafka_toppar_t *s_rktp;
        int i;
	unsigned int tot_cnt;
	size_t tot_size;

	rd_kafka_curr_msgs_get(rk, &tot_cnt, &tot_size);

	if (locks)
                rd_kafka_rdlock(rk);
#if ENABLE_DEVEL
        fprintf(fp, "rd_kafka_op_cnt: %d\n", rd_atomic32_get(&rd_kafka_op_cnt));
#endif
	fprintf(fp, "rd_kafka_t %p: %s\n", rk, rk->rk_name);

	fprintf(fp, " producer.msg_cnt %u (%"PRIusz" bytes)\n",
		tot_cnt, tot_size);
	fprintf(fp, " rk_rep reply queue: %i ops\n",
		rd_kafka_q_len(rk->rk_rep));

	fprintf(fp, " brokers:\n");
        if (locks)
                mtx_lock(&rk->rk_internal_rkb_lock);
        if (rk->rk_internal_rkb)
                rd_kafka_broker_dump(fp, rk->rk_internal_rkb, locks);
        if (locks)
                mtx_unlock(&rk->rk_internal_rkb_lock);

	TAILQ_FOREACH(rkb, &rk->rk_brokers, rkb_link) {
                rd_kafka_broker_dump(fp, rkb, locks);
	}

        fprintf(fp, " cgrp:\n");
        if (rk->rk_cgrp) {
                rd_kafka_cgrp_t *rkcg = rk->rk_cgrp;
                fprintf(fp, "  %.*s in state %s, flags 0x%x\n",
                        RD_KAFKAP_STR_PR(rkcg->rkcg_group_id),
                        rd_kafka_cgrp_state_names[rkcg->rkcg_state],
                        rkcg->rkcg_flags);
                fprintf(fp, "   coord_id %"PRId32", managing broker %s\n",
                        rkcg->rkcg_coord_id,
                        rkcg->rkcg_rkb ?
                        rd_kafka_broker_name(rkcg->rkcg_rkb) : "(none)");

                fprintf(fp, "  toppars:\n");
                RD_LIST_FOREACH(s_rktp, &rkcg->rkcg_toppars, i) {
                        rktp = rd_kafka_toppar_s2i(s_rktp);
                        fprintf(fp, "   %.*s [%"PRId32"] in state %s\n",
                                RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                                rktp->rktp_partition,
                                rd_kafka_fetch_states[rktp->rktp_fetch_state]);
                }
        }

	fprintf(fp, " topics:\n");
	TAILQ_FOREACH(rkt, &rk->rk_topics, rkt_link) {
		fprintf(fp, "  %.*s with %"PRId32" partitions, state %s, "
                        "refcnt %i\n",
			RD_KAFKAP_STR_PR(rkt->rkt_topic),
			rkt->rkt_partition_cnt,
                        rd_kafka_topic_state_names[rkt->rkt_state],
                        rd_refcnt_get(&rkt->rkt_refcnt));
		if (rkt->rkt_ua)
			rd_kafka_toppar_dump(fp, "   ",
                                             rd_kafka_toppar_s2i(rkt->rkt_ua));
                if (rd_list_empty(&rkt->rkt_desp)) {
                        fprintf(fp, "   desired partitions:");
                        RD_LIST_FOREACH(s_rktp, &rkt->rkt_desp,  i)
                                fprintf(fp, " %"PRId32,
                                        rd_kafka_toppar_s2i(s_rktp)->
                                        rktp_partition);
                        fprintf(fp, "\n");
                }
	}

        fprintf(fp, "\n");
        rd_kafka_metadata_cache_dump(fp, rk);

        if (locks)
                rd_kafka_rdunlock(rk);
}

void rd_kafka_dump (FILE *fp, rd_kafka_t *rk) {

        if (rk)
                rd_kafka_dump0(fp, rk, 1/*locks*/);

#if ENABLE_SHAREDPTR_DEBUG
        rd_shared_ptrs_dump();
#endif
}



const char *rd_kafka_name (const rd_kafka_t *rk) {
	return rk->rk_name;
}

rd_kafka_type_t rd_kafka_type(const rd_kafka_t *rk) {
        return rk->rk_type;
}


char *rd_kafka_memberid (const rd_kafka_t *rk) {
	rd_kafka_op_t *rko;
	rd_kafka_cgrp_t *rkcg;
	char *memberid;

	if (!(rkcg = rd_kafka_cgrp_get(rk)))
		return NULL;

	rko = rd_kafka_op_req2(rkcg->rkcg_ops, RD_KAFKA_OP_NAME);
	if (!rko)
		return NULL;
	memberid = rko->rko_u.name.str;
	rko->rko_u.name.str = NULL;
	rd_kafka_op_destroy(rko);

	return memberid;
}


char *rd_kafka_clusterid (rd_kafka_t *rk, int timeout_ms) {
        rd_ts_t abs_timeout = rd_timeout_init(timeout_ms);

        /* ClusterId is returned in Metadata >=V2 responses and
         * cached on the rk. If no cached value is available
         * it means no metadata has been received yet, or we're
         * using a lower protocol version
         * (e.g., lack of api.version.request=true). */

        while (1) {
                int remains_ms;

                rd_kafka_rdlock(rk);

                if (rk->rk_clusterid) {
                        /* Cached clusterid available. */
                        char *ret = rd_strdup(rk->rk_clusterid);
                        rd_kafka_rdunlock(rk);
                        return ret;
                } else if (rk->rk_ts_metadata > 0) {
                        /* Metadata received but no clusterid,
                         * this probably means the broker is too old
                         * or api.version.request=false. */
                        rd_kafka_rdunlock(rk);
                        return NULL;
                }

                rd_kafka_rdunlock(rk);

                /* Wait for up to timeout_ms for a metadata refresh,
                 * if permitted by application. */
                remains_ms = rd_timeout_remains(abs_timeout);
                if (remains_ms <= 0)
                        return NULL;

                rd_kafka_metadata_cache_wait_change(
                        rk, rd_timeout_remains(abs_timeout));
        }

        return NULL;
}


void *rd_kafka_opaque (const rd_kafka_t *rk) {
        return rk->rk_conf.opaque;
}


int rd_kafka_outq_len (rd_kafka_t *rk) {
	return rd_kafka_curr_msgs_cnt(rk) + rd_kafka_q_len(rk->rk_rep);
}


rd_kafka_resp_err_t rd_kafka_flush (rd_kafka_t *rk, int timeout_ms) {
        unsigned int msg_cnt = 0;
	int qlen;
	rd_ts_t ts_end = rd_timeout_init(timeout_ms);
        int tmout;

	if (rk->rk_type != RD_KAFKA_PRODUCER)
		return RD_KAFKA_RESP_ERR__NOT_IMPLEMENTED;

        rd_kafka_yield_thread = 0;
        while (((qlen = rd_kafka_q_len(rk->rk_rep)) > 0 ||
                (msg_cnt = rd_kafka_curr_msgs_cnt(rk)) > 0) &&
               !rd_kafka_yield_thread &&
               (tmout = rd_timeout_remains_limit(ts_end, 100))!=RD_POLL_NOWAIT)
                rd_kafka_poll(rk, tmout);

	return qlen + msg_cnt > 0 ? RD_KAFKA_RESP_ERR__TIMED_OUT :
		RD_KAFKA_RESP_ERR_NO_ERROR;
}



int rd_kafka_version (void) {
	return RD_KAFKA_VERSION;
}

const char *rd_kafka_version_str (void) {
	static char ret[128];
	size_t of = 0, r;

	if (*ret)
		return ret;

#ifdef LIBRDKAFKA_GIT_VERSION
	if (*LIBRDKAFKA_GIT_VERSION) {
		of = rd_snprintf(ret, sizeof(ret), "%s",
				 *LIBRDKAFKA_GIT_VERSION == 'v' ?
                                 LIBRDKAFKA_GIT_VERSION+1 :
                                 LIBRDKAFKA_GIT_VERSION);
		if (of > sizeof(ret))
			of = sizeof(ret);
	}
#endif

#define _my_sprintf(...) do {						\
		r = rd_snprintf(ret+of, sizeof(ret)-of, __VA_ARGS__);	\
		if (r > sizeof(ret)-of)					\
			r = sizeof(ret)-of;				\
		of += r;						\
	} while(0)

	if (of == 0) {
		int ver = rd_kafka_version();
		int prel = (ver & 0xff);
		_my_sprintf("%i.%i.%i",
			    (ver >> 24) & 0xff,
			    (ver >> 16) & 0xff,
			    (ver >> 8) & 0xff);
		if (prel != 0xff) {
			/* pre-builds below 200 are just running numbers,
			 * above 200 are RC numbers. */
			if (prel <= 200)
				_my_sprintf("-pre%d", prel);
			else
				_my_sprintf("-RC%d", prel - 200);
		}
	}

#if ENABLE_DEVEL
	_my_sprintf("-devel");
#endif

#if ENABLE_SHAREDPTR_DEBUG
	_my_sprintf("-shptr");
#endif

#if WITHOUT_OPTIMIZATION
	_my_sprintf("-O0");
#endif

	return ret;
}


/**
 * Assert trampoline to print some debugging information on crash.
 */
void
RD_NORETURN
rd_kafka_crash (const char *file, int line, const char *function,
                rd_kafka_t *rk, const char *reason) {
        fprintf(stderr, "*** %s:%i:%s: %s ***\n",
                file, line, function, reason);
        if (rk)
                rd_kafka_dump0(stderr, rk, 0/*no locks*/);
        abort();
}





struct list_groups_state {
        rd_kafka_q_t *q;
        rd_kafka_resp_err_t err;
        int wait_cnt;
        const char *desired_group;
        struct rd_kafka_group_list *grplist;
        int grplist_size;
};

static void rd_kafka_DescribeGroups_resp_cb (rd_kafka_t *rk,
					     rd_kafka_broker_t *rkb,
                                             rd_kafka_resp_err_t err,
                                             rd_kafka_buf_t *reply,
                                             rd_kafka_buf_t *request,
                                             void *opaque) {
        struct list_groups_state *state = opaque;
        const int log_decode_errors = LOG_ERR;
        int cnt;

        state->wait_cnt--;

        if (err)
                goto err;

        rd_kafka_buf_read_i32(reply, &cnt);

        while (cnt-- > 0) {
                int16_t ErrorCode;
                rd_kafkap_str_t Group, GroupState, ProtoType, Proto;
                int MemberCnt;
                struct rd_kafka_group_info *gi;

                if (state->grplist->group_cnt == state->grplist_size) {
                        /* Grow group array */
                        state->grplist_size *= 2;
                        state->grplist->groups =
                                rd_realloc(state->grplist->groups,
                                           state->grplist_size *
                                           sizeof(*state->grplist->groups));
                }

                gi = &state->grplist->groups[state->grplist->group_cnt++];
                memset(gi, 0, sizeof(*gi));

                rd_kafka_buf_read_i16(reply, &ErrorCode);
                rd_kafka_buf_read_str(reply, &Group);
                rd_kafka_buf_read_str(reply, &GroupState);
                rd_kafka_buf_read_str(reply, &ProtoType);
                rd_kafka_buf_read_str(reply, &Proto);
                rd_kafka_buf_read_i32(reply, &MemberCnt);

                if (MemberCnt > 100000) {
                        err = RD_KAFKA_RESP_ERR__BAD_MSG;
                        goto err;
                }

                rd_kafka_broker_lock(rkb);
                gi->broker.id = rkb->rkb_nodeid;
                gi->broker.host = rd_strdup(rkb->rkb_origname);
                gi->broker.port = rkb->rkb_port;
                rd_kafka_broker_unlock(rkb);

                gi->err = ErrorCode;
                gi->group = RD_KAFKAP_STR_DUP(&Group);
                gi->state = RD_KAFKAP_STR_DUP(&GroupState);
                gi->protocol_type = RD_KAFKAP_STR_DUP(&ProtoType);
                gi->protocol = RD_KAFKAP_STR_DUP(&Proto);

                if (MemberCnt > 0)
                        gi->members =
                                rd_malloc(MemberCnt * sizeof(*gi->members));

                while (MemberCnt-- > 0) {
                        rd_kafkap_str_t MemberId, ClientId, ClientHost;
                        rd_kafkap_bytes_t Meta, Assignment;
                        struct rd_kafka_group_member_info *mi;

                        mi = &gi->members[gi->member_cnt++];
                        memset(mi, 0, sizeof(*mi));

                        rd_kafka_buf_read_str(reply, &MemberId);
                        rd_kafka_buf_read_str(reply, &ClientId);
                        rd_kafka_buf_read_str(reply, &ClientHost);
                        rd_kafka_buf_read_bytes(reply, &Meta);
                        rd_kafka_buf_read_bytes(reply, &Assignment);

                        mi->member_id = RD_KAFKAP_STR_DUP(&MemberId);
                        mi->client_id = RD_KAFKAP_STR_DUP(&ClientId);
                        mi->client_host = RD_KAFKAP_STR_DUP(&ClientHost);

                        if (RD_KAFKAP_BYTES_LEN(&Meta) == 0) {
                                mi->member_metadata_size = 0;
                                mi->member_metadata = NULL;
                        } else {
                                mi->member_metadata_size =
                                        RD_KAFKAP_BYTES_LEN(&Meta);
                                mi->member_metadata =
                                        rd_memdup(Meta.data,
                                                  mi->member_metadata_size);
                        }

                        if (RD_KAFKAP_BYTES_LEN(&Assignment) == 0) {
                                mi->member_assignment_size = 0;
                                mi->member_assignment = NULL;
                        } else {
                                mi->member_assignment_size =
                                        RD_KAFKAP_BYTES_LEN(&Assignment);
                                mi->member_assignment =
                                        rd_memdup(Assignment.data,
                                                  mi->member_assignment_size);
                        }
                }
        }

err:
        state->err = err;
        return;

 err_parse:
        state->err = reply->rkbuf_err;
}

static void rd_kafka_ListGroups_resp_cb (rd_kafka_t *rk,
					 rd_kafka_broker_t *rkb,
                                         rd_kafka_resp_err_t err,
                                         rd_kafka_buf_t *reply,
                                         rd_kafka_buf_t *request,
                                         void *opaque) {
        struct list_groups_state *state = opaque;
        const int log_decode_errors = LOG_ERR;
        int16_t ErrorCode;
        char **grps;
        int cnt, grpcnt, i = 0;

        state->wait_cnt--;

        if (err)
                goto err;

        rd_kafka_buf_read_i16(reply, &ErrorCode);
        if (ErrorCode) {
                err = ErrorCode;
                goto err;
        }

        rd_kafka_buf_read_i32(reply, &cnt);

        if (state->desired_group)
                grpcnt = 1;
        else
                grpcnt = cnt;

        if (cnt == 0 || grpcnt == 0)
                return;

        grps = rd_malloc(sizeof(*grps) * grpcnt);

        while (cnt-- > 0) {
                rd_kafkap_str_t grp, proto;

                rd_kafka_buf_read_str(reply, &grp);
                rd_kafka_buf_read_str(reply, &proto);

                if (state->desired_group &&
                    rd_kafkap_str_cmp_str(&grp, state->desired_group))
                        continue;

                grps[i++] = RD_KAFKAP_STR_DUP(&grp);

                if (i == grpcnt)
                        break;
        }

        if (i > 0) {
                state->wait_cnt++;
                rd_kafka_DescribeGroupsRequest(rkb,
                                               (const char **)grps, i,
                                               RD_KAFKA_REPLYQ(state->q, 0),
                                               rd_kafka_DescribeGroups_resp_cb,
                                               state);

                while (i-- > 0)
                        rd_free(grps[i]);
        }


        rd_free(grps);

err:
        state->err = err;
        return;

 err_parse:
        state->err = reply->rkbuf_err;
}

rd_kafka_resp_err_t
rd_kafka_list_groups (rd_kafka_t *rk, const char *group,
                      const struct rd_kafka_group_list **grplistp,
                      int timeout_ms) {
        rd_kafka_broker_t *rkb;
        int rkb_cnt = 0;
        struct list_groups_state state = RD_ZERO_INIT;
        rd_ts_t ts_end = rd_timeout_init(timeout_ms);
	int state_version = rd_kafka_brokers_get_state_version(rk);

        /* Wait until metadata has been fetched from cluster so
         * that we have a full broker list.
	 * This state only happens during initial client setup, after that
	 * there'll always be a cached metadata copy. */
        rd_kafka_rdlock(rk);
        while (!rk->rk_ts_metadata) {
                rd_kafka_rdunlock(rk);

		if (!rd_kafka_brokers_wait_state_change(
			    rk, state_version, rd_timeout_remains(ts_end)))
                        return RD_KAFKA_RESP_ERR__TIMED_OUT;

                rd_kafka_rdlock(rk);
        }

        state.q = rd_kafka_q_new(rk);
        state.desired_group = group;
        state.grplist = rd_calloc(1, sizeof(*state.grplist));
        state.grplist_size = group ? 1 : 32;

        state.grplist->groups = rd_malloc(state.grplist_size *
                                          sizeof(*state.grplist->groups));

        /* Query each broker for its list of groups */
        TAILQ_FOREACH(rkb, &rk->rk_brokers, rkb_link) {
                rd_kafka_broker_lock(rkb);
                if (rkb->rkb_nodeid == -1) {
                        rd_kafka_broker_unlock(rkb);
                        continue;
                }

                state.wait_cnt++;
                rd_kafka_ListGroupsRequest(rkb,
                                           RD_KAFKA_REPLYQ(state.q, 0),
					   rd_kafka_ListGroups_resp_cb,
                                           &state);

                rkb_cnt++;

                rd_kafka_broker_unlock(rkb);

        }
        rd_kafka_rdunlock(rk);

        if (rkb_cnt == 0) {
                state.err = RD_KAFKA_RESP_ERR__TRANSPORT;

        } else {
                while (state.wait_cnt > 0) {
                        rd_kafka_q_serve(state.q, 100, 0,
                                         RD_KAFKA_Q_CB_CALLBACK,
                                         rd_kafka_poll_cb, NULL);
                        /* Ignore yields */
                }
        }

        rd_kafka_q_destroy(state.q);

        if (state.err)
                rd_kafka_group_list_destroy(state.grplist);
        else
                *grplistp = state.grplist;

        return state.err;
}


void rd_kafka_group_list_destroy (const struct rd_kafka_group_list *grplist0) {
        struct rd_kafka_group_list *grplist =
                (struct rd_kafka_group_list *)grplist0;

        while (grplist->group_cnt-- > 0) {
                struct rd_kafka_group_info *gi;
                gi = &grplist->groups[grplist->group_cnt];

                if (gi->broker.host)
                        rd_free(gi->broker.host);
                if (gi->group)
                        rd_free(gi->group);
                if (gi->state)
                        rd_free(gi->state);
                if (gi->protocol_type)
                        rd_free(gi->protocol_type);
                if (gi->protocol)
                        rd_free(gi->protocol);

                while (gi->member_cnt-- > 0) {
                        struct rd_kafka_group_member_info *mi;
                        mi = &gi->members[gi->member_cnt];

                        if (mi->member_id)
                                rd_free(mi->member_id);
                        if (mi->client_id)
                                rd_free(mi->client_id);
                        if (mi->client_host)
                                rd_free(mi->client_host);
                        if (mi->member_metadata)
                                rd_free(mi->member_metadata);
                        if (mi->member_assignment)
                                rd_free(mi->member_assignment);
                }

                if (gi->members)
                        rd_free(gi->members);
        }

        if (grplist->groups)
                rd_free(grplist->groups);

        rd_free(grplist);
}



const char *rd_kafka_get_debug_contexts(void) {
	return RD_KAFKA_DEBUG_CONTEXTS;
}


int rd_kafka_path_is_dir (const char *path) {
#ifdef _MSC_VER
	struct _stat st;
	return (_stat(path, &st) == 0 && st.st_mode & S_IFDIR);
#else
	struct stat st;
	return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
#endif
}


void rd_kafka_mem_free (rd_kafka_t *rk, void *ptr) {
        free(ptr);
}


int rd_kafka_errno (void) {
        return errno;
}

int rd_kafka_unittest (void) {
        return rd_unittest();
}


#if ENABLE_SHAREDPTR_DEBUG
struct rd_shptr0_head rd_shared_ptr_debug_list;
mtx_t rd_shared_ptr_debug_mtx;

void rd_shared_ptrs_dump (void) {
        rd_shptr0_t *sptr;

        printf("################ Current shared pointers ################\n");
        printf("### op_cnt: %d\n", rd_atomic32_get(&rd_kafka_op_cnt));
        mtx_lock(&rd_shared_ptr_debug_mtx);
        LIST_FOREACH(sptr, &rd_shared_ptr_debug_list, link)
                printf("# shptr ((%s*)%p): object %p refcnt %d: at %s:%d\n",
                       sptr->typename, sptr, sptr->obj,
                       rd_refcnt_get(sptr->ref), sptr->func, sptr->line);
        mtx_unlock(&rd_shared_ptr_debug_mtx);
        printf("#########################################################\n");
}
#endif
