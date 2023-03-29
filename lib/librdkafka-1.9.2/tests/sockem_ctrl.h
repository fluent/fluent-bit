/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2018, Magnus Edenhill
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

#ifndef _SOCKEM_CTRL_H_
#define _SOCKEM_CTRL_H_

#include <sys/queue.h>

struct sockem_cmd {
        TAILQ_ENTRY(sockem_cmd) link;
        int64_t ts_at; /**< to ctrl thread: at this time, set delay*/
        int delay;
};


typedef struct sockem_ctrl_s {
        mtx_t lock;
        cnd_t cnd;
        thrd_t thrd;

        int cmd_seq; /**< Command sequence id */
        int cmd_ack; /**< Last acked (seen) command sequence id */

        TAILQ_HEAD(, sockem_cmd) cmds; /**< Queue of commands. */

        int term; /**< Terminate */

        struct test *test;
} sockem_ctrl_t;


void sockem_ctrl_set_delay(sockem_ctrl_t *ctrl, int after, int delay);
void sockem_ctrl_init(sockem_ctrl_t *ctrl);
void sockem_ctrl_term(sockem_ctrl_t *ctrl);

#endif /* _SOCKEM_CTRL_H_ */
