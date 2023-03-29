/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2017, Magnus Edenhill
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

#include "test.h"
#include "rdkafka.h"
#include <ctype.h>

/**
 * Verify interceptor functionality.
 *
 * Producer MO:
 *  - create a chain of N interceptors
 *  - allocate a state struct with unique id for each message produced,
 *    provide as msg_opaque and reference from payload.
 *  - in on_send: verify expected interceptor order by counting number
 *    of consecutive bits.
 *  - in on_acknowledge: same
 *  - produce message to invalid topic which should trigger on_send+on_ack..
 *    from within produce().
 *
 * Consumer MO:
 *  - create a chain of M interceptors
 *  - subscribe to the previously produced topic
 *  - in on_consume: find message by id, verify expected order by bit counting.
 *  - on on_commit: just count order per on_commit chain run.
 */


#define msgcnt 100
static const int producer_ic_cnt = 5;
static const int consumer_ic_cnt = 10;

/* The base values help differentiating opaque values between interceptors */
static const int on_send_base    = 1 << 24;
static const int on_ack_base     = 1 << 25;
static const int on_consume_base = 1 << 26;
static const int on_commit_base  = 1 << 27;
static const int base_mask       = 0xff << 24;

#define _ON_SEND    0
#define _ON_ACK     1
#define _ON_CONSUME 2
#define _ON_CNT     3
struct msg_state {
        int id;
        int bits[_ON_CNT]; /* Bit field, one bit per interceptor */
        mtx_t lock;
};

/* Per-message state */
static struct msg_state msgs[msgcnt];

/* on_commit bits */
static int on_commit_bits = 0;

/**
 * @brief Verify that \p bits matches the number of expected interceptor
 *        call cnt.
 *
 * Verify interceptor order: the lower bits of ic_id
 * denotes the order in which interceptors were added and it
 * must be reflected here, meaning that all lower bits must be set,
 * and no higher ones.
 */
static void msg_verify_ic_cnt(const struct msg_state *msg,
                              const char *what,
                              int bits,
                              int exp_cnt) {
        int exp_bits = exp_cnt ? (1 << exp_cnt) - 1 : 0;

        TEST_ASSERT(bits == exp_bits,
                    "msg #%d: %s: expected bits 0x%x (%d), got 0x%x", msg->id,
                    what, exp_bits, exp_cnt, bits);
}

/*
 * @brief Same as msg_verify_ic_cnt() without the msg reliance
 */
static void verify_ic_cnt(const char *what, int bits, int exp_cnt) {
        int exp_bits = exp_cnt ? (1 << exp_cnt) - 1 : 0;

        TEST_ASSERT(bits == exp_bits, "%s: expected bits 0x%x (%d), got 0x%x",
                    what, exp_bits, exp_cnt, bits);
}



static void verify_msg(const char *what,
                       int base,
                       int bitid,
                       rd_kafka_message_t *rkmessage,
                       void *ic_opaque) {
        const char *id_str = rkmessage->key;
        struct msg_state *msg;
        int id;
        int ic_id = (int)(intptr_t)ic_opaque;

        /* Verify opaque (base | ic id) */
        TEST_ASSERT((ic_id & base_mask) == base);
        ic_id &= ~base_mask;

        /* Find message by id */
        TEST_ASSERT(rkmessage->key && rkmessage->key_len > 0 &&
                    id_str[(int)rkmessage->key_len - 1] == '\0' &&
                    strlen(id_str) > 0 && isdigit(*id_str));
        id = atoi(id_str);
        TEST_ASSERT(id >= 0 && id < msgcnt, "%s: bad message id %s", what,
                    id_str);
        msg = &msgs[id];

        mtx_lock(&msg->lock);

        TEST_ASSERT(msg->id == id, "expected msg #%d has wrong id %d", id,
                    msg->id);

        /* Verify message opaque */
        if (!strcmp(what, "on_send") || !strncmp(what, "on_ack", 6))
                TEST_ASSERT(rkmessage->_private == (void *)msg);

        TEST_SAYL(3, "%s: interceptor #%d called for message #%d (%d)\n", what,
                  ic_id, id, msg->id);

        msg_verify_ic_cnt(msg, what, msg->bits[bitid], ic_id);

        /* Set this interceptor's bit */
        msg->bits[bitid] |= 1 << ic_id;

        mtx_unlock(&msg->lock);
}


static rd_kafka_resp_err_t
on_send(rd_kafka_t *rk, rd_kafka_message_t *rkmessage, void *ic_opaque) {
        TEST_ASSERT(ic_opaque != NULL);
        verify_msg("on_send", on_send_base, _ON_SEND, rkmessage, ic_opaque);
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}

static rd_kafka_resp_err_t
on_ack(rd_kafka_t *rk, rd_kafka_message_t *rkmessage, void *ic_opaque) {
        TEST_ASSERT(ic_opaque != NULL);
        verify_msg("on_ack", on_ack_base, _ON_ACK, rkmessage, ic_opaque);
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}

static rd_kafka_resp_err_t
on_consume(rd_kafka_t *rk, rd_kafka_message_t *rkmessage, void *ic_opaque) {
        TEST_ASSERT(ic_opaque != NULL);
        verify_msg("on_consume", on_consume_base, _ON_CONSUME, rkmessage,
                   ic_opaque);
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


static rd_kafka_resp_err_t
on_commit(rd_kafka_t *rk,
          const rd_kafka_topic_partition_list_t *offsets,
          rd_kafka_resp_err_t err,
          void *ic_opaque) {
        int ic_id = (int)(intptr_t)ic_opaque;

        /* Since on_commit is triggered a bit randomly and not per
         * message we only try to make sure it gets fully set at least once. */
        TEST_ASSERT(ic_opaque != NULL);

        /* Verify opaque (base | ic id) */
        TEST_ASSERT((ic_id & base_mask) == on_commit_base);
        ic_id &= ~base_mask;

        TEST_ASSERT(ic_opaque != NULL);

        TEST_SAYL(3, "on_commit: interceptor #%d called: %s\n", ic_id,
                  rd_kafka_err2str(err));
        if (test_level >= 4)
                test_print_partition_list(offsets);

        /* Check for rollover where a previous on_commit stint was
         * succesful and it just now started over */
        if (on_commit_bits > 0 && ic_id == 0) {
                /* Verify completeness of previous stint */
                verify_ic_cnt("on_commit", on_commit_bits, consumer_ic_cnt);
                /* Reset */
                on_commit_bits = 0;
        }

        verify_ic_cnt("on_commit", on_commit_bits, ic_id);

        /* Set this interceptor's bit */
        on_commit_bits |= 1 << ic_id;


        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


static void do_test_produce(rd_kafka_t *rk,
                            const char *topic,
                            int32_t partition,
                            int msgid,
                            int exp_fail,
                            int exp_ic_cnt) {
        rd_kafka_resp_err_t err;
        char key[16];
        struct msg_state *msg = &msgs[msgid];
        int i;

        /* Message state should be empty, no interceptors should have
         * been called yet.. */
        for (i = 0; i < _ON_CNT; i++)
                TEST_ASSERT(msg->bits[i] == 0);

        mtx_init(&msg->lock, mtx_plain);
        msg->id = msgid;
        rd_snprintf(key, sizeof(key), "%d", msgid);

        err = rd_kafka_producev(rk, RD_KAFKA_V_TOPIC(topic),
                                RD_KAFKA_V_PARTITION(partition),
                                RD_KAFKA_V_KEY(key, strlen(key) + 1),
                                RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                                RD_KAFKA_V_OPAQUE(msg), RD_KAFKA_V_END);

        mtx_lock(&msg->lock);
        msg_verify_ic_cnt(msg, "on_send", msg->bits[_ON_SEND], exp_ic_cnt);

        if (err) {
                msg_verify_ic_cnt(msg, "on_ack", msg->bits[_ON_ACK],
                                  exp_ic_cnt);
                TEST_ASSERT(exp_fail, "producev() failed: %s",
                            rd_kafka_err2str(err));
        } else {
                msg_verify_ic_cnt(msg, "on_ack", msg->bits[_ON_ACK], 0);
                TEST_ASSERT(!exp_fail,
                            "expected produce failure for msg #%d, not %s",
                            msgid, rd_kafka_err2str(err));
        }
        mtx_unlock(&msg->lock);
}



static rd_kafka_resp_err_t on_new_producer(rd_kafka_t *rk,
                                           const rd_kafka_conf_t *conf,
                                           void *ic_opaque,
                                           char *errstr,
                                           size_t errstr_size) {
        int i;

        for (i = 0; i < producer_ic_cnt; i++) {
                rd_kafka_resp_err_t err;

                err = rd_kafka_interceptor_add_on_send(
                    rk, tsprintf("on_send:%d", i), on_send,
                    (void *)(intptr_t)(on_send_base | i));
                TEST_ASSERT(!err, "add_on_send failed: %s",
                            rd_kafka_err2str(err));

                err = rd_kafka_interceptor_add_on_acknowledgement(
                    rk, tsprintf("on_acknowledgement:%d", i), on_ack,
                    (void *)(intptr_t)(on_ack_base | i));
                TEST_ASSERT(!err, "add_on_ack.. failed: %s",
                            rd_kafka_err2str(err));


                /* Add consumer interceptors as well to make sure
                 * they are not called. */
                err = rd_kafka_interceptor_add_on_consume(
                    rk, tsprintf("on_consume:%d", i), on_consume, NULL);
                TEST_ASSERT(!err, "add_on_consume failed: %s",
                            rd_kafka_err2str(err));


                err = rd_kafka_interceptor_add_on_commit(
                    rk, tsprintf("on_commit:%d", i), on_commit, NULL);
                TEST_ASSERT(!err, "add_on_commit failed: %s",
                            rd_kafka_err2str(err));
        }

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}

static void do_test_producer(const char *topic) {
        rd_kafka_conf_t *conf;
        int i;
        rd_kafka_t *rk;

        TEST_SAY(_C_MAG "[ %s ]\n" _C_CLR, __FUNCTION__);

        test_conf_init(&conf, NULL, 0);

        rd_kafka_conf_interceptor_add_on_new(conf, "on_new_prodcer",
                                             on_new_producer, NULL);

        /* Create producer */
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        for (i = 0; i < msgcnt - 1; i++)
                do_test_produce(rk, topic, RD_KAFKA_PARTITION_UA, i, 0,
                                producer_ic_cnt);

        /* Wait for messages to be delivered */
        test_flush(rk, -1);

        /* Now send a message that will fail in produce()
         * due to bad partition */
        do_test_produce(rk, topic, 1234, i, 1, producer_ic_cnt);


        /* Verify acks */
        for (i = 0; i < msgcnt; i++) {
                struct msg_state *msg = &msgs[i];
                mtx_lock(&msg->lock);
                msg_verify_ic_cnt(msg, "on_ack", msg->bits[_ON_ACK],
                                  producer_ic_cnt);
                mtx_unlock(&msg->lock);
        }

        rd_kafka_destroy(rk);
}


static rd_kafka_resp_err_t on_new_consumer(rd_kafka_t *rk,
                                           const rd_kafka_conf_t *conf,
                                           void *ic_opaque,
                                           char *errstr,
                                           size_t errstr_size) {
        int i;

        for (i = 0; i < consumer_ic_cnt; i++) {
                rd_kafka_interceptor_add_on_consume(
                    rk, tsprintf("on_consume:%d", i), on_consume,
                    (void *)(intptr_t)(on_consume_base | i));

                rd_kafka_interceptor_add_on_commit(
                    rk, tsprintf("on_commit:%d", i), on_commit,
                    (void *)(intptr_t)(on_commit_base | i));

                /* Add producer interceptors as well to make sure they
                 * are not called. */
                rd_kafka_interceptor_add_on_send(rk, tsprintf("on_send:%d", i),
                                                 on_send, NULL);

                rd_kafka_interceptor_add_on_acknowledgement(
                    rk, tsprintf("on_acknowledgement:%d", i), on_ack, NULL);
        }


        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


static void do_test_consumer(const char *topic) {

        rd_kafka_conf_t *conf;
        int i;
        rd_kafka_t *rk;

        TEST_SAY(_C_MAG "[ %s ]\n" _C_CLR, __FUNCTION__);

        test_conf_init(&conf, NULL, 0);

        rd_kafka_conf_interceptor_add_on_new(conf, "on_new_consumer",
                                             on_new_consumer, NULL);

        test_conf_set(conf, "auto.offset.reset", "earliest");

        /* Create producer */
        rk = test_create_consumer(topic, NULL, conf, NULL);

        test_consumer_subscribe(rk, topic);

        /* Consume messages (-1 for the one that failed producing) */
        test_consumer_poll("interceptors.consume", rk, 0, -1, -1, msgcnt - 1,
                           NULL);

        /* Verify on_consume */
        for (i = 0; i < msgcnt - 1; i++) {
                struct msg_state *msg = &msgs[i];
                mtx_lock(&msg->lock);
                msg_verify_ic_cnt(msg, "on_consume", msg->bits[_ON_CONSUME],
                                  consumer_ic_cnt);
                mtx_unlock(&msg->lock);
        }

        /* Verify that the produce-failed message didnt have
         * interceptors called */
        mtx_lock(&msgs[msgcnt - 1].lock);
        msg_verify_ic_cnt(&msgs[msgcnt - 1], "on_consume",
                          msgs[msgcnt - 1].bits[_ON_CONSUME], 0);
        mtx_unlock(&msgs[msgcnt - 1].lock);

        test_consumer_close(rk);

        verify_ic_cnt("on_commit", on_commit_bits, consumer_ic_cnt);

        rd_kafka_destroy(rk);
}

/**
 * @brief Interceptors must not be copied automatically by conf_dup()
 *        unless the interceptors have added on_conf_dup().
 *        This behaviour makes sure an interceptor's instance
 *        is not duplicated without the interceptor's knowledge or
 *        assistance.
 */
static void do_test_conf_copy(const char *topic) {
        rd_kafka_conf_t *conf, *conf2;
        int i;
        rd_kafka_t *rk;

        TEST_SAY(_C_MAG "[ %s ]\n" _C_CLR, __FUNCTION__);

        memset(&msgs[0], 0, sizeof(msgs));

        test_conf_init(&conf, NULL, 0);

        rd_kafka_conf_interceptor_add_on_new(conf, "on_new_conf_copy",
                                             on_new_producer, NULL);

        /* Now copy the configuration to verify that interceptors are
         * NOT copied. */
        conf2 = conf;
        conf  = rd_kafka_conf_dup(conf2);
        rd_kafka_conf_destroy(conf2);

        /* Create producer */
        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        for (i = 0; i < msgcnt - 1; i++)
                do_test_produce(rk, topic, RD_KAFKA_PARTITION_UA, i, 0, 0);

        /* Wait for messages to be delivered */
        test_flush(rk, -1);

        /* Verify acks */
        for (i = 0; i < msgcnt; i++) {
                struct msg_state *msg = &msgs[i];
                mtx_lock(&msg->lock);
                msg_verify_ic_cnt(msg, "on_ack", msg->bits[_ON_ACK], 0);
                mtx_unlock(&msg->lock);
        }

        rd_kafka_destroy(rk);
}


int main_0064_interceptors(int argc, char **argv) {
        const char *topic = test_mk_topic_name(__FUNCTION__, 1);

        do_test_producer(topic);

        do_test_consumer(topic);

        do_test_conf_copy(topic);

        return 0;
}
