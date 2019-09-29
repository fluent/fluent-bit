/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2018 Magnus Edenhill
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
#include "rdkafka_request.h"

#include <stdarg.h>

/**
 * @name Idempotent Producer logic
 *
 *
 *
 */

static void rd_kafka_idemp_restart_request_pid_tmr (rd_kafka_t *rk,
                                                    rd_bool_t immediate);


/**
 * @brief Set the producer's idempotence state.
 * @locks rd_kafka_wrlock() MUST be held
 */
void rd_kafka_idemp_set_state (rd_kafka_t *rk,
                               rd_kafka_idemp_state_t new_state) {

        if (rk->rk_eos.idemp_state == new_state)
                return;

        rd_kafka_dbg(rk, EOS, "IDEMPSTATE",
                     "Idempotent producer state change %s -> %s",
                     rd_kafka_idemp_state2str(rk->rk_eos.
                                              idemp_state),
                     rd_kafka_idemp_state2str(new_state));

        rk->rk_eos.idemp_state = new_state;
        rk->rk_eos.ts_idemp_state = rd_clock();
}







/**
 * @brief Acquire Pid by looking up a suitable broker and then
 *        sending an InitProducerIdRequest to it.
 *
 * @param rkb may be set to specify a broker to use, otherwise a suitable
 *            one is looked up.
 *
 * @returns 1 if a request was enqueued, or 0 if no broker was available,
 *          incorrect state, or other error.
 *
 * @locality rdkafka main thread
 * @locks none
 */
int rd_kafka_idemp_request_pid (rd_kafka_t *rk, rd_kafka_broker_t *rkb,
                                const char *reason) {

        rd_kafka_resp_err_t err;
        char errstr[128];

        rd_assert(thrd_is_current(rk->rk_thread));

        if (unlikely(rd_kafka_fatal_error_code(rk))) {
                /* If a fatal error has been raised we do not
                 * attempt to acquire a new PID. */
                return 0;
        }

        rd_kafka_wrlock(rk);
        if (rk->rk_eos.idemp_state != RD_KAFKA_IDEMP_STATE_REQ_PID) {
                rd_kafka_wrunlock(rk);
                return 0;
        }

        if (!rkb) {
                rkb = rd_kafka_broker_any(rk, RD_KAFKA_BROKER_STATE_UP,
                                          rd_kafka_broker_filter_non_idempotent,
                                          NULL, "acquire ProducerID");
                if (!rkb) {
                        int up_cnt = rd_atomic32_get(&rk->rk_broker_up_cnt);
                        int all_cnt = rd_atomic32_get(&rk->rk_broker_cnt);
                        int err_unsupported =
                                up_cnt > 0 &&
                                rd_interval(&rk->rk_suppress.no_idemp_brokers,
                                            5*60*1000000/*5 minutes*/, 0) > 0;

                        rd_kafka_wrunlock(rk);
                        rd_kafka_idemp_restart_request_pid_tmr(rk, rd_false);

                        if (err_unsupported)
                                rd_kafka_op_err(
                                        rk,
                                        RD_KAFKA_RESP_ERR__UNSUPPORTED_FEATURE,
                                        "Idempotent Producer not supported by "
                                        "any of the %d broker(s) in state UP: "
                                        "requires broker version >= 0.11.0",
                                        up_cnt);
                        else if (up_cnt == 0)
                                rd_kafka_dbg(rk, EOS, "PIDBROKER",
                                             "No brokers available for "
                                             "acquiring Producer ID: "
                                             "no brokers are up");
                        else
                                rd_kafka_dbg(rk, EOS, "PIDBROKER",
                                             "None of the %d/%d brokers in "
                                             "state UP supports "
                                             "the Idempotent Producer: "
                                             "requires broker "
                                             "version >= 0.11.0",
                                             up_cnt, all_cnt);
                        return 0;
                }
        } else {
                /* Increase passed broker's refcount so we don't
                 * have to check if rkb should be destroyed or not below
                 * (broker_any() returns a new reference). */
                rd_kafka_broker_keep(rkb);
        }

        rd_rkb_dbg(rkb, EOS, "GETPID", "Acquiring ProducerId: %s", reason);

        err = rd_kafka_InitProducerIdRequest(
                rkb, NULL, -1,
                errstr, sizeof(errstr),
                RD_KAFKA_REPLYQ(rk->rk_ops, 0),
                rd_kafka_handle_InitProducerId, NULL);

        if (!err) {
                rd_kafka_idemp_set_state(rkb->rkb_rk,
                                         RD_KAFKA_IDEMP_STATE_WAIT_PID);
                rd_kafka_wrunlock(rkb->rkb_rk);
                rd_kafka_broker_destroy(rkb);
                return 1;
        }

        rd_kafka_wrunlock(rkb->rkb_rk);

        rd_rkb_dbg(rkb, EOS, "GETPID",
                   "Can't acquire ProducerId from this broker: %s", errstr);
        rd_kafka_idemp_restart_request_pid_tmr(rk, rd_false);

        rd_kafka_broker_destroy(rkb);

        return 0;
}


/**
 * @brief Timed PID retrieval timer callback.
 */
static void rd_kafka_idemp_request_pid_tmr_cb (rd_kafka_timers_t *rkts,
                                               void *arg) {
        rd_kafka_t *rk = arg;

        rd_kafka_idemp_request_pid(rk, NULL, "retry timer");
}


/**
 * @brief Restart the pid retrieval timer.
 *
 * @param immediate If true, request a pid as soon as possible,
 *                  else use the default interval (500ms).
 * @locality any
 * @locks none
 */
static void rd_kafka_idemp_restart_request_pid_tmr (rd_kafka_t *rk,
                                                    rd_bool_t immediate) {
        rd_kafka_timer_start_oneshot(&rk->rk_timers,
                                     &rk->rk_eos.request_pid_tmr,
                                     1000 * (immediate ? 1 : 500/*500ms*/),
                                     rd_kafka_idemp_request_pid_tmr_cb, rk);
}


/**
 * @brief Handle failure to acquire a PID from broker.
 *
 * @locality rdkafka main thread
 * @locks none
 */
void rd_kafka_idemp_request_pid_failed (rd_kafka_broker_t *rkb,
                                    rd_kafka_resp_err_t err) {
        rd_kafka_t *rk = rkb->rkb_rk;

        rd_rkb_dbg(rkb, EOS, "GETPID",
                   "Failed to acquire PID: %s", rd_kafka_err2str(err));

        if (err == RD_KAFKA_RESP_ERR__DESTROY)
                return; /* Ignore */

        rd_assert(thrd_is_current(rk->rk_thread));

        /* FIXME: Handle special errors, maybe raise certain errors
         *        to the application (such as UNSUPPORTED_FEATURE) */

        /* Retry request after a short wait. */
        rd_kafka_idemp_restart_request_pid_tmr(rk, rd_false);
}


/**
 * @brief Update Producer ID from InitProducerId response.
 *
 * @remark If we've already have a PID the new one is ignored.
 *
 * @locality rdkafka main thread
 * @locks none
 */
void rd_kafka_idemp_pid_update (rd_kafka_broker_t *rkb,
                                const rd_kafka_pid_t pid) {
        rd_kafka_t *rk = rkb->rkb_rk;

        rd_kafka_wrlock(rk);
        if (rk->rk_eos.idemp_state != RD_KAFKA_IDEMP_STATE_WAIT_PID) {
                rd_rkb_dbg(rkb, EOS, "GETPID",
                           "Ignoring InitProduceId response (%s) "
                           "in state %s",
                           rd_kafka_pid2str(pid),
                           rd_kafka_idemp_state2str(rk->rk_eos.idemp_state));
                rd_kafka_wrunlock(rk);
                return;
        }

        if (!rd_kafka_pid_valid(pid)) {
                rd_kafka_wrunlock(rk);
                rd_rkb_log(rkb, LOG_WARNING, "GETPID",
                           "Acquired invalid PID{%"PRId64",%hd}: ignoring",
                           pid.id, pid.epoch);
                rd_kafka_idemp_request_pid_failed(rkb,
                                                  RD_KAFKA_RESP_ERR__BAD_MSG);
                return;
        }

        if (rd_kafka_pid_valid(rk->rk_eos.pid))
                rd_kafka_dbg(rk, EOS, "GETPID",
                             "Acquired %s (previous %s)",
                             rd_kafka_pid2str(pid),
                             rd_kafka_pid2str(rk->rk_eos.pid));
        else
                rd_kafka_dbg(rk, EOS, "GETPID",
                             "Acquired %s", rd_kafka_pid2str(pid));
        rk->rk_eos.pid = pid;
        rk->rk_eos.epoch_cnt++;

        rd_kafka_idemp_set_state(rk, RD_KAFKA_IDEMP_STATE_ASSIGNED);

        rd_kafka_wrunlock(rk);

        /* Wake up all broker threads (that may have messages to send
         * that were waiting for a Producer ID). */
        rd_kafka_all_brokers_wakeup(rk, RD_KAFKA_BROKER_STATE_INIT);
}


/**
 * @brief Call when all partition request queues
 *        are drained to reset and re-request a new PID.
 *
 * @locality any
 * @locks none
 */
static void rd_kafka_idemp_drain_done (rd_kafka_t *rk) {
        rd_bool_t restart_tmr = rd_false;
        rd_bool_t wakeup_brokers = rd_false;

        rd_kafka_wrlock(rk);
        if (rk->rk_eos.idemp_state == RD_KAFKA_IDEMP_STATE_DRAIN_RESET) {
                rd_kafka_dbg(rk, EOS, "DRAIN", "All partitions drained");
                rd_kafka_idemp_set_state(rk, RD_KAFKA_IDEMP_STATE_REQ_PID);
                restart_tmr = rd_true;

        } else if (rk->rk_eos.idemp_state == RD_KAFKA_IDEMP_STATE_DRAIN_BUMP &&
                   rd_kafka_pid_valid(rk->rk_eos.pid)) {
                rk->rk_eos.pid = rd_kafka_pid_bump(rk->rk_eos.pid);
                rd_kafka_dbg(rk, EOS, "DRAIN",
                             "All partitions drained, bumped epoch to %s",
                             rd_kafka_pid2str(rk->rk_eos.pid));
                rd_kafka_idemp_set_state(rk, RD_KAFKA_IDEMP_STATE_ASSIGNED);
                wakeup_brokers = rd_true;
        }
        rd_kafka_wrunlock(rk);

        /* Restart timer to eventually trigger a re-request */
        if (restart_tmr)
                rd_kafka_idemp_restart_request_pid_tmr(rk, rd_true);

        /* Wake up all broker threads (that may have messages to send
         * that were waiting for a Producer ID). */
        if (wakeup_brokers)
                rd_kafka_all_brokers_wakeup(rk, RD_KAFKA_BROKER_STATE_INIT);

}

/**
 * @brief Check if in-flight toppars drain is done, if so transition to
 *        next state.
 *
 * @locality any
 * @locks none
 */
static RD_INLINE void rd_kafka_idemp_check_drain_done (rd_kafka_t *rk) {
        if (rd_atomic32_get(&rk->rk_eos.inflight_toppar_cnt) == 0)
                rd_kafka_idemp_drain_done(rk);
}


/**
 * @brief Schedule a reset and re-request of PID when the
 *        local ProduceRequest queues have been fully drained.
 *
 * The PID is not reset until the queues are fully drained.
 *
 * @locality any
 * @locks none
 */
void rd_kafka_idemp_drain_reset (rd_kafka_t *rk) {
        rd_kafka_wrlock(rk);
        rd_kafka_dbg(rk, EOS, "DRAIN",
                     "Beginning partition drain for %s reset "
                     "for %d partition(s) with in-flight requests",
                     rd_kafka_pid2str(rk->rk_eos.pid),
                     rd_atomic32_get(&rk->rk_eos.inflight_toppar_cnt));
        rd_kafka_idemp_set_state(rk, RD_KAFKA_IDEMP_STATE_DRAIN_RESET);
        rd_kafka_wrunlock(rk);

        /* Check right away if the drain could be done. */
        rd_kafka_idemp_check_drain_done(rk);
}


/**
 * @brief Schedule an epoch bump when the local ProduceRequest queues
 *        have been fully drained.
 *
 * The PID is not bumped until the queues are fully drained.
 *
 * @param fmt is a human-readable reason for the bump
 *
 *
 * @locality any
 * @locks none
 */
void rd_kafka_idemp_drain_epoch_bump (rd_kafka_t *rk, const char *fmt, ...) {
        va_list ap;
        char buf[256];

        va_start(ap, fmt);
        rd_vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);

        rd_kafka_wrlock(rk);
        rd_kafka_dbg(rk, EOS, "DRAIN",
                     "Beginning partition drain for %s epoch bump "
                     "for %d partition(s) with in-flight requests: %s",
                     rd_kafka_pid2str(rk->rk_eos.pid),
                     rd_atomic32_get(&rk->rk_eos.inflight_toppar_cnt), buf);
        rd_kafka_idemp_set_state(rk, RD_KAFKA_IDEMP_STATE_DRAIN_BUMP);
        rd_kafka_wrunlock(rk);

        /* Check right away if the drain could be done. */
        rd_kafka_idemp_check_drain_done(rk);
}

/**
 * @brief Mark partition as waiting-to-drain.
 *
 * @locks toppar_lock MUST be held
 * @locality broker thread (leader or not)
 */
void rd_kafka_idemp_drain_toppar (rd_kafka_toppar_t *rktp,
                                  const char *reason) {
        if (rktp->rktp_eos.wait_drain)
                return;

        rd_kafka_dbg(rktp->rktp_rkt->rkt_rk, EOS|RD_KAFKA_DBG_TOPIC, "DRAIN",
                     "%.*s [%"PRId32"] beginning partition drain: %s",
                     RD_KAFKAP_STR_PR(rktp->rktp_rkt->rkt_topic),
                     rktp->rktp_partition, reason);
        rktp->rktp_eos.wait_drain = rd_true;
}


/**
 * @brief Mark partition as no longer having a ProduceRequest in-flight.
 *
 * @locality any
 * @locks none
 */
void rd_kafka_idemp_inflight_toppar_sub (rd_kafka_t *rk,
                                         rd_kafka_toppar_t *rktp) {
        int r = rd_atomic32_sub(&rk->rk_eos.inflight_toppar_cnt, 1);

        if (r == 0) {
                /* Check if we're waiting for the partitions to drain
                 * before resetting the PID, and if so trigger a reset
                 * since this was the last drained one. */
                rd_kafka_idemp_drain_done(rk);
        } else {
                rd_assert(r >= 0);
        }
}


/**
 * @brief Mark partition as having a ProduceRequest in-flight.
 *
 * @locality toppar handler thread
 * @locks none
 */
void rd_kafka_idemp_inflight_toppar_add (rd_kafka_t *rk,
                                         rd_kafka_toppar_t *rktp) {
        rd_atomic32_add(&rk->rk_eos.inflight_toppar_cnt, 1);
}


/**
 * @brief Initialize the idempotent producer.
 *
 * @remark Must be called from rd_kafka_new() and only once.
 * @locality application thread
 * @locks none / not needed from rd_kafka_new()
 */
void rd_kafka_idemp_init (rd_kafka_t *rk) {
        rd_assert(thrd_is_current(rk->rk_thread));

        rd_atomic32_init(&rk->rk_eos.inflight_toppar_cnt, 0);

        rd_kafka_wrlock(rk);
        rd_kafka_pid_reset(&rk->rk_eos.pid);

        /* There are no available brokers this early, so just set
         * the state to indicate that we want to acquire a PID as soon
         * as possible and start the timer. */
        rd_kafka_idemp_set_state(rk, RD_KAFKA_IDEMP_STATE_REQ_PID);
        rd_kafka_wrunlock(rk);

        rd_kafka_idemp_restart_request_pid_tmr(rk, rd_false);
}


/**
 * @brief Terminate and clean up idempotent producer
 *
 * @locality rdkafka main thread
 * @locks rd_kafka_wrlock() MUST be held
 */
void rd_kafka_idemp_term (rd_kafka_t *rk) {
        rd_assert(thrd_is_current(rk->rk_thread));

        rd_kafka_wrlock(rk);
        rd_kafka_idemp_set_state(rk, RD_KAFKA_IDEMP_STATE_TERM);
        rd_kafka_wrunlock(rk);
        rd_kafka_timer_stop(&rk->rk_timers, &rk->rk_eos.request_pid_tmr, 1);
}


