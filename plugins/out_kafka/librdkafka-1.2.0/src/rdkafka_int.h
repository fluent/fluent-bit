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

#ifndef _RDKAFKA_INT_H_
#define _RDKAFKA_INT_H_

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
struct rd_kafka_toppar_s;

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
#define RD_KAFKAP_BROKERS_MAX     10000
#define RD_KAFKAP_TOPICS_MAX      1000000
#define RD_KAFKAP_PARTITIONS_MAX  100000


#define RD_KAFKA_OFFSET_IS_LOGICAL(OFF)  ((OFF) < 0)




/**
 * @enum Idempotent Producer state
 */
typedef enum {
        RD_KAFKA_IDEMP_STATE_INIT,      /**< Initial state */
        RD_KAFKA_IDEMP_STATE_TERM,      /**< Instance is terminating */
        RD_KAFKA_IDEMP_STATE_REQ_PID,   /**< Request new PID */
        RD_KAFKA_IDEMP_STATE_WAIT_PID,  /**< PID requested, waiting for reply */
        RD_KAFKA_IDEMP_STATE_ASSIGNED,  /**< New PID assigned */
        RD_KAFKA_IDEMP_STATE_DRAIN_RESET, /**< Wait for outstanding
                                           *   ProduceRequests to finish
                                           *   before resetting and
                                           *   re-requesting a new PID. */
        RD_KAFKA_IDEMP_STATE_DRAIN_BUMP, /**< Wait for outstanding
                                          *   ProduceRequests to finish
                                          *   before bumping the current
                                          *   epoch. */
} rd_kafka_idemp_state_t;

/**
 * @returns the idemp_state_t string representation
 */
static RD_UNUSED const char *
rd_kafka_idemp_state2str (rd_kafka_idemp_state_t state) {
        static const char *names[] = {
                "Init",
                "Terminate",
                "RequestPID",
                "WaitPID",
                "Assigned",
                "DrainReset",
                "DrainBump"
        };
        return names[state];
}




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
        /**< Number of brokers in state >= UP */
        rd_atomic32_t              rk_broker_up_cnt;
        /**< Number of logical brokers in state >= UP, this is a sub-set
         *   of rk_broker_up_cnt. */
        rd_atomic32_t              rk_logical_broker_up_cnt;
        /**< Number of brokers that are down, only includes brokers
         *   that have had at least one connection attempt. */
	rd_atomic32_t              rk_broker_down_cnt;
        /**< Logical brokers currently without an address.
         *   Used for calculating ERR__ALL_BROKERS_DOWN. */
        rd_atomic32_t              rk_broker_addrless_cnt;

        mtx_t                      rk_internal_rkb_lock;
	rd_kafka_broker_t         *rk_internal_rkb;

	/* Broadcasting of broker state changes to wake up
	 * functions waiting for a state change. */
	cnd_t                      rk_broker_state_change_cnd;
	mtx_t                      rk_broker_state_change_lock;
	int                        rk_broker_state_change_version;
        /* List of (rd_kafka_enq_once_t*) objects waiting for broker
         * state changes. Protected by rk_broker_state_change_lock. */
        rd_list_t rk_broker_state_change_waiters; /**< (rd_kafka_enq_once_t*) */

	TAILQ_HEAD(, rd_kafka_itopic_s)  rk_topics;
	int              rk_topic_cnt;

        struct rd_kafka_cgrp_s *rk_cgrp;

        rd_kafka_conf_t  rk_conf;
        rd_kafka_q_t    *rk_logq;          /* Log queue if `log.queue` set */
        char             rk_name[128];
	rd_kafkap_str_t *rk_client_id;
        rd_kafkap_str_t *rk_group_id;    /* Consumer group id */

	int              rk_flags;
	rd_atomic32_t    rk_terminate;   /**< Set to RD_KAFKA_DESTROY_F_..
                                          *   flags instance
                                          *   is being destroyed.
                                          *   The value set is the
                                          *   destroy flags from
                                          *   rd_kafka_destroy*() and
                                          *   the two internal flags shown
                                          *   below.
                                          *
                                          * Order:
                                          * 1. user_flags | .._F_DESTROY_CALLED
                                          *    is set in rd_kafka_destroy*().
                                          * 2. consumer_close() is called
                                          *    for consumers.
                                          * 3. .._F_TERMINATE is set to
                                          *    signal all background threads
                                          *    to terminate.
                                          */

#define RD_KAFKA_DESTROY_F_TERMINATE 0x1 /**< Internal flag to make sure
                                          *   rk_terminate is set to non-zero
                                          *   value even if user passed
                                          *   no destroy flags. */
#define RD_KAFKA_DESTROY_F_DESTROY_CALLED 0x2 /**< Application has called
                                               *  ..destroy*() and we've
                                               * begun the termination
                                               * process.
                                               * This flag is needed to avoid
                                               * rk_terminate from being
                                               * 0 when destroy_flags()
                                               * is called with flags=0
                                               * and prior to _F_TERMINATE
                                               * has been set. */
#define RD_KAFKA_DESTROY_F_IMMEDIATE 0x4     /**< Immediate non-blocking
                                              *   destruction without waiting
                                              *   for all resources
                                              *   to be cleaned up.
                                              *   WARNING: Memory and resource
                                              *            leaks possible.
                                              *   This flag automatically sets
                                              *   .._NO_CONSUMER_CLOSE. */


	rwlock_t         rk_lock;
	rd_kafka_type_t  rk_type;
	struct timeval   rk_tv_state_change;

        rd_atomic64_t    rk_ts_last_poll;   /**< Timestamp of last application
                                             *   consumer_poll() call
                                             *   (or equivalent).
                                             *   Used to enforce
                                             *   max.poll.interval.ms.
                                             *   Only relevant for consumer. */
        /* First fatal error. */
        struct {
                rd_atomic32_t err; /**< rd_kafka_resp_err_t */
                char *errstr;      /**< Protected by rk_lock */
                int cnt;           /**< Number of errors raised, only
                                    *   the first one is stored. */
        } rk_fatal;

	rd_atomic32_t    rk_last_throttle;  /* Last throttle_time_ms value
					     * from broker. */

        /* Locks: rd_kafka_*lock() */
        rd_ts_t          rk_ts_metadata;    /* Timestamp of most recent
                                             * metadata. */

	struct rd_kafka_metadata *rk_full_metadata; /* Last full metadata. */
	rd_ts_t          rk_ts_full_metadata;       /* Timesstamp of .. */
        struct rd_kafka_metadata_cache rk_metadata_cache; /* Metadata cache */

        char            *rk_clusterid;      /* ClusterId from metadata */
        int32_t          rk_controllerid;   /* ControllerId from metadata */

        /* Simple consumer count:
         *  >0: Running in legacy / Simple Consumer mode,
         *   0: No consumers running
         *  <0: Running in High level consumer mode */
        rd_atomic32_t    rk_simple_cnt;

        /**
         * Exactly Once Semantics and Idempotent Producer
         *
         * @locks rk_lock
         */
        struct {
                rd_kafka_idemp_state_t idemp_state; /**< Idempotent Producer
                                                     *   state */
                rd_ts_t ts_idemp_state;/**< Last state change */
                rd_kafka_pid_t pid;    /**< Current Producer ID and Epoch */
                int epoch_cnt;         /**< Number of times pid/epoch changed */
                rd_atomic32_t inflight_toppar_cnt; /**< Current number of
                                                    *   toppars with inflight
                                                    *   requests. */
                rd_kafka_timer_t request_pid_tmr; /**< Timer for pid retrieval*/

                rd_kafkap_str_t *transactional_id; /**< Transactional Id,
                                                    *   a null string. */
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

        int rk_initialized;       /**< Will be > 0 when the rd_kafka_t
                                   *   instance has been fully initialized. */

        int   rk_init_wait_cnt;   /**< Number of background threads that
                                   *   need to finish initialization. */
        cnd_t rk_init_cnd;        /**< Cond-var used to wait for main thread
                                   *   to finish its initialization before
                                   *   before rd_kafka_new() returns. */
        mtx_t rk_init_lock;       /**< Lock for rk_init_wait and _cmd */

        /**
         * Background thread and queue,
         * enabled by setting `background_event_cb()`.
         */
        struct {
                rd_kafka_q_t *q;  /**< Queue served by background thread. */
                thrd_t thread;    /**< Background thread. */
                int calling;      /**< Indicates whether the event callback
                                   *   is being called, reset back to 0
                                   *   when the callback returns.
                                   *   This can be used for troubleshooting
                                   *   purposes. */
        } rk_background;


        /*
         * Logs, events or actions to rate limit / suppress
         */
        struct {
                /**< Log: No brokers support Idempotent Producer */
                rd_interval_t no_idemp_brokers;

                /**< Sparse connections: randomly select broker
                 *   to bring up. This interval should allow
                 *   for a previous connection to be established,
                 *   which varies between different environments:
                 *   Use 10 < reconnect.backoff.jitter.ms / 2 < 1000.
                 */
                rd_interval_t sparse_connect_random;
                /**< Lock for sparse_connect_random */
                mtx_t         sparse_connect_lock;

                /**< Broker metadata refresh interval:
                 *   this is rate-limiting the number of topic-less
                 *   broker/cluster metadata refreshes when there are no
                 *   topics to refresh.
                 *   Will be refreshed every topic.metadata.refresh.interval.ms
                 *   but no more often than every 10s.
                 *   No locks: only accessed by rdkafka main thread. */
                rd_interval_t broker_metadata_refresh;
        } rk_suppress;

        struct {
                void *handle; /**< Provider-specific handle struct pointer.
                               *   Typically assigned in provider's .init() */
        } rk_sasl;
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
 *
 * @param rdmtx If non-null and \p block is set and blocking is to ensue,
 *              then unlock this mutex for the duration of the blocking
 *              and then reacquire with a read-lock.
 */
static RD_INLINE RD_UNUSED rd_kafka_resp_err_t
rd_kafka_curr_msgs_add (rd_kafka_t *rk, unsigned int cnt, size_t size,
			int block, rwlock_t *rdlock) {

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

                if (rdlock)
                        rwlock_rdunlock(rdlock);

		cnd_wait(&rk->rk_curr_msgs.cnd, &rk->rk_curr_msgs.lock);

                if (rdlock)
                        rwlock_rdlock(rdlock);

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

void rd_kafka_global_init (void);

/**
 * @returns true if \p rk handle is terminating.
 *
 * @remark If consumer_close() is called from destroy*() it will be
 *         called prior to _F_TERMINATE being set and will thus not
 *         be able to use rd_kafka_terminating() to know it is shutting down.
 *         That code should instead just check that rk_terminate is non-zero
 *         (the _F_DESTROY_CALLED flag will be set).
 */
#define rd_kafka_terminating(rk) (rd_atomic32_get(&(rk)->rk_terminate) & \
                                  RD_KAFKA_DESTROY_F_TERMINATE)

/**
 * @returns the destroy flags set matching \p flags, which might be
 *          a subset of the flags.
 */
#define rd_kafka_destroy_flags_check(rk,flags) \
        (rd_atomic32_get(&(rk)->rk_terminate) & (flags))

/**
 * @returns true if no consumer callbacks, or standard consumer_close
 *          behaviour, should be triggered. */
#define rd_kafka_destroy_flags_no_consumer_close(rk) \
        rd_kafka_destroy_flags_check(rk, RD_KAFKA_DESTROY_F_NO_CONSUMER_CLOSE)

#define rd_kafka_is_simple_consumer(rk) \
        (rd_atomic32_get(&(rk)->rk_simple_cnt) > 0)
int rd_kafka_simple_consumer_add (rd_kafka_t *rk);


/**
 * @returns true if idempotency is enabled (producer only).
 */
#define rd_kafka_is_idempotent(rk) ((rk)->rk_conf.eos.idempotence)

#define RD_KAFKA_PURGE_F_MASK 0x7
const char *rd_kafka_purge_flags2str (int flags);


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
#define RD_KAFKA_DBG_CONSUMER       0x2000
#define RD_KAFKA_DBG_ADMIN          0x4000
#define RD_KAFKA_DBG_EOS            0x8000
#define RD_KAFKA_DBG_ALL            0xffff
#define RD_KAFKA_DBG_NONE           0x0

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
                /* MSVC:
                 * This is the correct way to set errno on Windows,
                 * but it is still pointless due to different errnos in
                 * in different runtimes:
                 * https://social.msdn.microsoft.com/Forums/vstudio/en-US/b4500c0d-1b69-40c7-9ef5-08da1025b5bf/setting-errno-from-within-a-dll?forum=vclanguage/
                 * errno is thus highly deprecated, and buggy, on Windows
                 * when using librdkafka as a dynamically loaded DLL. */
                rd_set_errno(errnox);
        }
	rd_kafka_last_error_code = err;
	return err;
}


int rd_kafka_set_fatal_error (rd_kafka_t *rk, rd_kafka_resp_err_t err,
                              const char *fmt, ...) RD_FORMAT(printf, 3, 4);

static RD_INLINE RD_UNUSED rd_kafka_resp_err_t
rd_kafka_fatal_error_code (rd_kafka_t *rk) {
        return rk->rk_conf.eos.idempotence &&
                rd_atomic32_get(&rk->rk_fatal.err);
}


extern rd_atomic32_t rd_kafka_thread_cnt_curr;
extern char RD_TLS rd_kafka_thread_name[64];

void rd_kafka_set_thread_name (const char *fmt, ...);
void rd_kafka_set_thread_sysname (const char *fmt, ...);

int rd_kafka_path_is_dir (const char *path);

rd_kafka_op_res_t
rd_kafka_poll_cb (rd_kafka_t *rk, rd_kafka_q_t *rkq, rd_kafka_op_t *rko,
                  rd_kafka_q_cb_type_t cb_type, void *opaque);

rd_kafka_resp_err_t rd_kafka_subscribe_rkt (rd_kafka_itopic_t *rkt);


/**
 * @returns the number of milliseconds the maximum poll interval
 *          was exceeded, or 0 if not exceeded.
 *
 * @remark Only relevant for high-level consumer.
 *
 * @locality any
 * @locks none
 */
static RD_INLINE RD_UNUSED int
rd_kafka_max_poll_exceeded (rd_kafka_t *rk) {
        rd_ts_t last_poll;
        int exceeded;

        if (rk->rk_type != RD_KAFKA_CONSUMER)
                return 0;

        last_poll = rd_atomic64_get(&rk->rk_ts_last_poll);

        /* Application is blocked in librdkafka function, see
         * rd_kafka_app_poll_blocking(). */
        if (last_poll == INT64_MAX)
                return 0;

        exceeded = (int)((rd_clock() - last_poll) / 1000ll) -
                rk->rk_conf.max_poll_interval_ms;

        if (unlikely(exceeded > 0))
                return exceeded;

        return 0;
}

/**
 * @brief Call on entry to blocking polling function to indicate
 *        that the application is blocked waiting for librdkafka
 *        and that max.poll.interval.ms should not be enforced.
 *
 *        Call app_polled() Upon return from the function calling
 *        this function to register the application's last time of poll.
 *
 * @remark Only relevant for high-level consumer.
 *
 * @locality any
 * @locks none
 */
static RD_INLINE RD_UNUSED void
rd_kafka_app_poll_blocking (rd_kafka_t *rk) {
        if (rk->rk_type == RD_KAFKA_CONSUMER)
                rd_atomic64_set(&rk->rk_ts_last_poll, INT64_MAX);
}

/**
 * @brief Set the last application poll time to now.
 *
 * @remark Only relevant for high-level consumer.
 *
 * @locality any
 * @locks none
 */
static RD_INLINE RD_UNUSED void
rd_kafka_app_polled (rd_kafka_t *rk) {
        if (rk->rk_type == RD_KAFKA_CONSUMER)
                rd_atomic64_set(&rk->rk_ts_last_poll, rd_clock());
}


/**
 * rdkafka_background.c
 */
int rd_kafka_background_thread_main (void *arg);

#endif /* _RDKAFKA_INT_H_ */
