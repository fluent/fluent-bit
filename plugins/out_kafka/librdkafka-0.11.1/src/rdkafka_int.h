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

#pragma once


#ifndef _MSC_VER
#define _GNU_SOURCE  /* for strndup() */
#include <syslog.h>
#else
typedef int mode_t;
#endif
#include <fcntl.h>


#include "rdsysqueue.h"

#include "rdkafka.h"
#include "rd.h"
#include "rdlog.h"
#include "rdtime.h"
#include "rdaddr.h"
#include "rdinterval.h"
#include "rdavg.h"
#include "rdlist.h"

#if WITH_SSL
#include <openssl/ssl.h>
#endif




typedef struct rd_kafka_itopic_s rd_kafka_itopic_t;
typedef struct rd_ikafka_s rd_ikafka_t;


#define rd_kafka_assert(rk, cond) do {                                  \
                if (unlikely(!(cond)))                                  \
                        rd_kafka_crash(__FILE__,__LINE__, __FUNCTION__, \
                                       (rk), "assert: " # cond);        \
        } while (0)


void
RD_NORETURN
rd_kafka_crash (const char *file, int line, const char *function,
                rd_kafka_t *rk, const char *reason);


/* Forward declarations */
struct rd_kafka_s;
struct rd_kafka_itopic_s;
struct rd_kafka_msg_s;
struct rd_kafka_broker_s;

typedef RD_SHARED_PTR_TYPE(, struct rd_kafka_toppar_s) shptr_rd_kafka_toppar_t;
typedef RD_SHARED_PTR_TYPE(, struct rd_kafka_itopic_s) shptr_rd_kafka_itopic_t;



#include "rdkafka_op.h"
#include "rdkafka_queue.h"
#include "rdkafka_msg.h"
#include "rdkafka_proto.h"
#include "rdkafka_buf.h"
#include "rdkafka_pattern.h"
#include "rdkafka_conf.h"
#include "rdkafka_transport.h"
#include "rdkafka_timer.h"
#include "rdkafka_assignor.h"
#include "rdkafka_metadata.h"


/**
 * Protocol level sanity
 */
#define RD_KAFKAP_BROKERS_MAX     1000
#define RD_KAFKAP_TOPICS_MAX      1000000
#define RD_KAFKAP_PARTITIONS_MAX  10000


#define RD_KAFKA_OFFSET_IS_LOGICAL(OFF)  ((OFF) < 0)







/**
 * Kafka handle, internal representation of the application's rd_kafka_t.
 */

typedef RD_SHARED_PTR_TYPE(shptr_rd_ikafka_s, rd_ikafka_t) shptr_rd_ikafka_t;

struct rd_kafka_s {
	rd_kafka_q_t *rk_rep;   /* kafka -> application reply queue */
	rd_kafka_q_t *rk_ops;   /* any -> rdkafka main thread ops */

	TAILQ_HEAD(, rd_kafka_broker_s) rk_brokers;
        rd_list_t                  rk_broker_by_id; /* Fast id lookups. */
	rd_atomic32_t              rk_broker_cnt;
	rd_atomic32_t              rk_broker_down_cnt;
        mtx_t                      rk_internal_rkb_lock;
	rd_kafka_broker_t         *rk_internal_rkb;

	/* Broadcasting of broker state changes to wake up
	 * functions waiting for a state change. */
	cnd_t                      rk_broker_state_change_cnd;
	mtx_t                      rk_broker_state_change_lock;
	int                        rk_broker_state_change_version;


	TAILQ_HEAD(, rd_kafka_itopic_s)  rk_topics;
	int              rk_topic_cnt;

        struct rd_kafka_cgrp_s *rk_cgrp;

        rd_kafka_conf_t  rk_conf;
        rd_kafka_q_t    *rk_logq;          /* Log queue if `log.queue` set */
        char             rk_name[128];
	rd_kafkap_str_t *rk_client_id;
        rd_kafkap_str_t *rk_group_id;    /* Consumer group id */

	int              rk_flags;
	rd_atomic32_t    rk_terminate;
	rwlock_t         rk_lock;
	rd_kafka_type_t  rk_type;
	struct timeval   rk_tv_state_change;

	rd_atomic32_t    rk_last_throttle;  /* Last throttle_time_ms value
					     * from broker. */

        /* Locks: rd_kafka_*lock() */
        rd_ts_t          rk_ts_metadata;    /* Timestamp of most recent
                                             * metadata. */

	struct rd_kafka_metadata *rk_full_metadata; /* Last full metadata. */
	rd_ts_t          rk_ts_full_metadata;       /* Timesstamp of .. */
        struct rd_kafka_metadata_cache rk_metadata_cache; /* Metadata cache */

        char            *rk_clusterid;      /* ClusterId from metadata */

        /* Simple consumer count:
         *  >0: Running in legacy / Simple Consumer mode,
         *   0: No consumers running
         *  <0: Running in High level consumer mode */
        rd_atomic32_t    rk_simple_cnt;

        /**
         * Exactly Once Semantics
         */
        struct {
                rd_kafkap_str_t *TransactionalId;
                int64_t          PID;
                int16_t          ProducerEpoch;
        } rk_eos;

	const rd_kafkap_bytes_t *rk_null_bytes;

	struct {
		mtx_t lock;       /* Protects acces to this struct */
		cnd_t cnd;        /* For waking up blocking injectors */
		unsigned int cnt; /* Current message count */
		size_t size;      /* Current message size sum */
	        unsigned int max_cnt; /* Max limit */
		size_t max_size; /* Max limit */
	} rk_curr_msgs;

        rd_kafka_timers_t rk_timers;
	thrd_t rk_thread;

        int rk_initialized;
};

#define rd_kafka_wrlock(rk)    rwlock_wrlock(&(rk)->rk_lock)
#define rd_kafka_rdlock(rk)    rwlock_rdlock(&(rk)->rk_lock)
#define rd_kafka_rdunlock(rk)    rwlock_rdunlock(&(rk)->rk_lock)
#define rd_kafka_wrunlock(rk)    rwlock_wrunlock(&(rk)->rk_lock)

/**
 * @brief Add \p cnt messages and of total size \p size bytes to the
 *        internal bookkeeping of current message counts.
 *        If the total message count or size after add would exceed the
 *        configured limits \c queue.buffering.max.messages and
 *        \c queue.buffering.max.kbytes then depending on the value of
 *        \p block the function either blocks until enough space is available
 *        if \p block is 1, else immediately returns
 *        RD_KAFKA_RESP_ERR__QUEUE_FULL.
 */
static RD_INLINE RD_UNUSED rd_kafka_resp_err_t
rd_kafka_curr_msgs_add (rd_kafka_t *rk, unsigned int cnt, size_t size,
			int block) {

	if (rk->rk_type != RD_KAFKA_PRODUCER)
		return RD_KAFKA_RESP_ERR_NO_ERROR;

	mtx_lock(&rk->rk_curr_msgs.lock);
	while (unlikely(rk->rk_curr_msgs.cnt + cnt >
			rk->rk_curr_msgs.max_cnt ||
			(unsigned long long)(rk->rk_curr_msgs.size + size) >
			(unsigned long long)rk->rk_curr_msgs.max_size)) {
		if (!block) {
			mtx_unlock(&rk->rk_curr_msgs.lock);
			return RD_KAFKA_RESP_ERR__QUEUE_FULL;
		}

		cnd_wait(&rk->rk_curr_msgs.cnd, &rk->rk_curr_msgs.lock);
	}

	rk->rk_curr_msgs.cnt  += cnt;
	rk->rk_curr_msgs.size += size;
	mtx_unlock(&rk->rk_curr_msgs.lock);

	return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * @brief Subtract \p cnt messages of total size \p size from the
 *        current bookkeeping and broadcast a wakeup on the condvar
 *        for any waiting & blocking threads.
 */
static RD_INLINE RD_UNUSED void
rd_kafka_curr_msgs_sub (rd_kafka_t *rk, unsigned int cnt, size_t size) {
        int broadcast = 0;

	if (rk->rk_type != RD_KAFKA_PRODUCER)
		return;

	mtx_lock(&rk->rk_curr_msgs.lock);
	rd_kafka_assert(NULL,
			rk->rk_curr_msgs.cnt >= cnt &&
			rk->rk_curr_msgs.size >= size);

        /* If the subtraction would pass one of the thresholds
         * broadcast a wake-up to any waiting listeners. */
        if ((rk->rk_curr_msgs.cnt >= rk->rk_curr_msgs.max_cnt &&
             rk->rk_curr_msgs.cnt - cnt < rk->rk_curr_msgs.max_cnt) ||
            (rk->rk_curr_msgs.size >= rk->rk_curr_msgs.max_size &&
             rk->rk_curr_msgs.size - size < rk->rk_curr_msgs.max_size))
                broadcast = 1;

	rk->rk_curr_msgs.cnt  -= cnt;
	rk->rk_curr_msgs.size -= size;

        if (unlikely(broadcast))
                cnd_broadcast(&rk->rk_curr_msgs.cnd);

	mtx_unlock(&rk->rk_curr_msgs.lock);
}

static RD_INLINE RD_UNUSED void
rd_kafka_curr_msgs_get (rd_kafka_t *rk, unsigned int *cntp, size_t *sizep) {
	if (rk->rk_type != RD_KAFKA_PRODUCER) {
		*cntp = 0;
		*sizep = 0;
		return;
	}

	mtx_lock(&rk->rk_curr_msgs.lock);
	*cntp = rk->rk_curr_msgs.cnt;
	*sizep = rk->rk_curr_msgs.size;
	mtx_unlock(&rk->rk_curr_msgs.lock);
}

static RD_INLINE RD_UNUSED int
rd_kafka_curr_msgs_cnt (rd_kafka_t *rk) {
	int cnt;
	if (rk->rk_type != RD_KAFKA_PRODUCER)
		return 0;

	mtx_lock(&rk->rk_curr_msgs.lock);
	cnt = rk->rk_curr_msgs.cnt;
	mtx_unlock(&rk->rk_curr_msgs.lock);

	return cnt;
}


void rd_kafka_destroy_final (rd_kafka_t *rk);


/**
 * Returns true if 'rk' handle is terminating.
 */
#define rd_kafka_terminating(rk) (rd_atomic32_get(&(rk)->rk_terminate))

#define rd_kafka_is_simple_consumer(rk) \
        (rd_atomic32_get(&(rk)->rk_simple_cnt) > 0)
int rd_kafka_simple_consumer_add (rd_kafka_t *rk);


#include "rdkafka_topic.h"
#include "rdkafka_partition.h"














/**
 * Debug contexts
 */
#define RD_KAFKA_DBG_GENERIC        0x1
#define RD_KAFKA_DBG_BROKER         0x2
#define RD_KAFKA_DBG_TOPIC          0x4
#define RD_KAFKA_DBG_METADATA       0x8
#define RD_KAFKA_DBG_FEATURE        0x10
#define RD_KAFKA_DBG_QUEUE          0x20
#define RD_KAFKA_DBG_MSG            0x40
#define RD_KAFKA_DBG_PROTOCOL       0x80
#define RD_KAFKA_DBG_CGRP           0x100
#define RD_KAFKA_DBG_SECURITY       0x200
#define RD_KAFKA_DBG_FETCH          0x400
#define RD_KAFKA_DBG_INTERCEPTOR    0x800
#define RD_KAFKA_DBG_PLUGIN         0x1000
#define RD_KAFKA_DBG_ALL            0xffff


void rd_kafka_log0(const rd_kafka_conf_t *conf,
                   const rd_kafka_t *rk, const char *extra, int level,
                   const char *fac, const char *fmt, ...) RD_FORMAT(printf,
                                                                    6, 7);

#define rd_kafka_log(rk,level,fac,...) \
        rd_kafka_log0(&rk->rk_conf, rk, NULL, level, fac, __VA_ARGS__)
#define rd_kafka_dbg(rk,ctx,fac,...) do {                               \
                if (unlikely((rk)->rk_conf.debug & (RD_KAFKA_DBG_ ## ctx))) \
                        rd_kafka_log0(&rk->rk_conf,rk,NULL,             \
                                      LOG_DEBUG,fac,__VA_ARGS__);       \
        } while (0)

/* dbg() not requiring an rk, just the conf object, for early logging */
#define rd_kafka_dbg0(conf,ctx,fac,...) do {                            \
                if (unlikely((conf)->debug & (RD_KAFKA_DBG_ ## ctx)))   \
                        rd_kafka_log0(conf,NULL,NULL,                   \
                                      LOG_DEBUG,fac,__VA_ARGS__);       \
        } while (0)

/* NOTE: The local copy of _logname is needed due rkb_logname_lock lock-ordering
 *       when logging another broker's name in the message. */
#define rd_rkb_log(rkb,level,fac,...) do {				\
		char _logname[RD_KAFKA_NODENAME_SIZE];			\
                mtx_lock(&(rkb)->rkb_logname_lock);                     \
		strncpy(_logname, rkb->rkb_logname, sizeof(_logname)-1); \
		_logname[RD_KAFKA_NODENAME_SIZE-1] = '\0';		\
                mtx_unlock(&(rkb)->rkb_logname_lock);                   \
		rd_kafka_log0(&(rkb)->rkb_rk->rk_conf, \
                              (rkb)->rkb_rk, _logname,                  \
                              level, fac, __VA_ARGS__);                 \
        } while (0)

#define rd_rkb_dbg(rkb,ctx,fac,...) do {				\
		if (unlikely((rkb)->rkb_rk->rk_conf.debug &		\
			     (RD_KAFKA_DBG_ ## ctx))) {			\
			rd_rkb_log(rkb, LOG_DEBUG, fac, __VA_ARGS__);	\
                }                                                       \
	} while (0)



extern rd_kafka_resp_err_t RD_TLS rd_kafka_last_error_code;

static RD_UNUSED RD_INLINE
rd_kafka_resp_err_t rd_kafka_set_last_error (rd_kafka_resp_err_t err,
					     int errnox) {
        if (errnox) {
#ifdef _MSC_VER
                /* This is the correct way to set errno on Windows,
                 * but it is still pointless due to different errnos in
                 * in different runtimes:
                 * https://social.msdn.microsoft.com/Forums/vstudio/en-US/b4500c0d-1b69-40c7-9ef5-08da1025b5bf/setting-errno-from-within-a-dll?forum=vclanguage/
                 * errno is thus highly deprecated, and buggy, on Windows
                 * when using librdkafka as a dynamically loaded DLL. */
                _set_errno(errnox);
#else
                errno = errnox;
#endif
        }
	rd_kafka_last_error_code = err;
	return err;
}


extern rd_atomic32_t rd_kafka_thread_cnt_curr;

extern char RD_TLS rd_kafka_thread_name[64];





int rd_kafka_path_is_dir (const char *path);

rd_kafka_op_res_t
rd_kafka_poll_cb (rd_kafka_t *rk, rd_kafka_q_t *rkq, rd_kafka_op_t *rko,
                  rd_kafka_q_cb_type_t cb_type, void *opaque);

rd_kafka_resp_err_t rd_kafka_subscribe_rkt (rd_kafka_itopic_t *rkt);

