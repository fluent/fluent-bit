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


#ifndef _RD_KAFKA_IDEMPOTENCE_H_
#define _RD_KAFKA_IDEMPOTENCE_H_


/**
 * @define The broker maintains a window of the 5 last Produce requests
 *         for a partition to be able to de-deduplicate resends.
 */
#define RD_KAFKA_IDEMP_MAX_INFLIGHT      5
#define RD_KAFKA_IDEMP_MAX_INFLIGHT_STR "5" /* For printouts */

/**
 * @brief Get the current PID if state permits.
 *
 * @returns If there is no valid PID or the state
 *          does not permit further PID usage (such as when draining)
 *          then an invalid PID is returned.
 *
 * @locality any
 * @locks none
 */

static RD_UNUSED RD_INLINE rd_kafka_pid_t
rd_kafka_idemp_get_pid (rd_kafka_t *rk) {
        rd_kafka_pid_t pid;

        rd_kafka_rdlock(rk);
        if (likely(rk->rk_eos.idemp_state == RD_KAFKA_IDEMP_STATE_ASSIGNED))
                pid = rk->rk_eos.pid;
        else
                rd_kafka_pid_reset(&pid);
        rd_kafka_rdunlock(rk);

        return pid;
}

void rd_kafka_idemp_set_state (rd_kafka_t *rk,
                               rd_kafka_idemp_state_t new_state);
void rd_kafka_idemp_request_pid_failed (rd_kafka_broker_t *rkb,
                                        rd_kafka_resp_err_t err);
void rd_kafka_idemp_pid_update (rd_kafka_broker_t *rkb,
                                const rd_kafka_pid_t pid);
int rd_kafka_idemp_request_pid (rd_kafka_t *rk, rd_kafka_broker_t *rkb,
                                const char *reason);
void rd_kafka_idemp_drain_reset (rd_kafka_t *rk);
void rd_kafka_idemp_drain_epoch_bump (rd_kafka_t *rk, const char *fmt, ...);
void rd_kafka_idemp_drain_toppar (rd_kafka_toppar_t *rktp, const char *reason);
void rd_kafka_idemp_check_drain_done (rd_kafka_t *rk);
void rd_kafka_idemp_inflight_toppar_sub (rd_kafka_t *rk,
                                         rd_kafka_toppar_t *rktp);
void rd_kafka_idemp_inflight_toppar_add (rd_kafka_t *rk,
                                         rd_kafka_toppar_t *rktp);

void rd_kafka_idemp_init (rd_kafka_t *rk);
void rd_kafka_idemp_term (rd_kafka_t *rk);


#endif /* _RD_KAFKA_IDEMPOTENCE_H_ */
