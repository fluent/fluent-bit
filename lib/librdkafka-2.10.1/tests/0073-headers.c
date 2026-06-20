/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2012-2022, Magnus Edenhill
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

/**
 * Message Headers end-to-end tests
 */



static int exp_msgid = 0;

struct expect {
        const char *name;
        const char *value;
};



static void expect_check(const char *what,
                         const struct expect *expected,
                         rd_kafka_message_t *rkmessage,
                         int is_const) {
        const struct expect *exp;
        rd_kafka_resp_err_t err;
        size_t idx = 0;
        const char *name;
        const char *value;
        size_t size;
        rd_kafka_headers_t *hdrs;
        int msgid;

        if (rkmessage->len != sizeof(msgid))
                TEST_FAIL("%s: expected message len %" PRIusz " == sizeof(int)",
                          what, rkmessage->len);

        memcpy(&msgid, rkmessage->payload, rkmessage->len);

        if ((err = rd_kafka_message_headers(rkmessage, &hdrs))) {
                if (msgid == 0) {
                        rd_kafka_resp_err_t err2;
                        TEST_SAYL(3, "%s: Msg #%d: no headers, good\n", what,
                                  msgid);

                        err2 =
                            rd_kafka_message_detach_headers(rkmessage, &hdrs);
                        TEST_ASSERT(err == err2,
                                    "expected detach_headers() error %s "
                                    "to match headers() error %s",
                                    rd_kafka_err2str(err2),
                                    rd_kafka_err2str(err));

                        return; /* No headers expected for first message */
                }

                TEST_FAIL("%s: Expected headers in message %d: %s", what, msgid,
                          rd_kafka_err2str(err));
        } else {
                TEST_ASSERT(msgid != 0,
                            "%s: first message should have no headers", what);
        }

        test_headers_dump(what, 3, hdrs);

        for (idx = 0, exp = expected; !rd_kafka_header_get_all(
                 hdrs, idx, &name, (const void **)&value, &size);
             idx++, exp++) {

                TEST_SAYL(3,
                          "%s: Msg #%d: "
                          "Header #%" PRIusz ": %s='%s' (expecting %s='%s')\n",
                          what, msgid, idx, name, value ? value : "(NULL)",
                          exp->name, exp->value ? exp->value : "(NULL)");

                if (strcmp(name, exp->name))
                        TEST_FAIL(
                            "%s: Msg #%d: "
                            "Expected header %s at idx #%" PRIusz
                            ", not '%s' (%" PRIusz ")",
                            what, msgid, exp->name, idx, name, strlen(name));

                if (!strcmp(name, "msgid")) {
                        int vid;

                        /* Special handling: compare msgid header value
                         * to message body, should be identical */
                        if (size != rkmessage->len || size != sizeof(int))
                                TEST_FAIL(
                                    "%s: "
                                    "Expected msgid/int-sized payload "
                                    "%" PRIusz ", got %" PRIusz,
                                    what, size, rkmessage->len);

                        /* Copy to avoid unaligned access (by cast) */
                        memcpy(&vid, value, size);

                        if (vid != msgid)
                                TEST_FAIL("%s: Header msgid %d != payload %d",
                                          what, vid, msgid);

                        if (exp_msgid != vid)
                                TEST_FAIL("%s: Expected msgid %d, not %d", what,
                                          exp_msgid, vid);
                        continue;
                }

                if (!exp->value) {
                        /* Expected NULL value */
                        TEST_ASSERT(!value,
                                    "%s: Expected NULL value for %s, got %s",
                                    what, exp->name, value);

                } else {
                        TEST_ASSERT(value,
                                    "%s: "
                                    "Expected non-NULL value for %s, got NULL",
                                    what, exp->name);

                        TEST_ASSERT(size == strlen(exp->value),
                                    "%s: Expected size %" PRIusz
                                    " for %s, "
                                    "not %" PRIusz,
                                    what, strlen(exp->value), exp->name, size);

                        TEST_ASSERT(value[size] == '\0',
                                    "%s: "
                                    "Expected implicit null-terminator for %s",
                                    what, exp->name);

                        TEST_ASSERT(!strcmp(exp->value, value),
                                    "%s: "
                                    "Expected value %s for %s, not %s",
                                    what, exp->value, exp->name, value);
                }
        }

        TEST_ASSERT(exp->name == NULL,
                    "%s: Expected the expected, but stuck at %s which was "
                    "unexpected",
                    what, exp->name);

        if (!strcmp(what, "handle_consumed_msg") && !is_const &&
            (msgid % 3) == 0) {
                rd_kafka_headers_t *dhdrs;

                err = rd_kafka_message_detach_headers(rkmessage, &dhdrs);
                TEST_ASSERT(!err, "detach_headers() should not fail, got %s",
                            rd_kafka_err2str(err));
                TEST_ASSERT(hdrs == dhdrs);

                /* Verify that a new headers object can be obtained */
                err = rd_kafka_message_headers(rkmessage, &hdrs);
                TEST_ASSERT(err == RD_KAFKA_RESP_ERR_NO_ERROR);
                TEST_ASSERT(hdrs != dhdrs);
                rd_kafka_headers_destroy(dhdrs);

                expect_check("post_detach_headers", expected, rkmessage,
                             is_const);
        }
}


/**
 * @brief Final (as in no more header modifications) message check.
 */
static void
msg_final_check(const char *what, rd_kafka_message_t *rkmessage, int is_const) {
        const struct expect expected[] = {
            {"msgid", NULL}, /* special handling */
            {"static", "hey"}, {"null", NULL},      {"empty", ""},
            {"send1", "1"},    {"multi", "multi5"}, {NULL}};

        expect_check(what, expected, rkmessage, is_const);

        exp_msgid++;
}

/**
 * @brief Handle consumed message, must be identical to dr_msg_cb
 */
static void handle_consumed_msg(rd_kafka_message_t *rkmessage) {
        msg_final_check(__FUNCTION__, rkmessage, 0);
}

/**
 * @brief Delivery report callback
 */
static void
dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque) {
        TEST_ASSERT(!rkmessage->err, "Message delivery failed: %s",
                    rd_kafka_err2str(rkmessage->err));

        msg_final_check(__FUNCTION__, (rd_kafka_message_t *)rkmessage, 1);
}


/**
 * @brief First on_send() interceptor
 */
static rd_kafka_resp_err_t
on_send1(rd_kafka_t *rk, rd_kafka_message_t *rkmessage, void *ic_opaque) {
        const struct expect expected[] = {
            {"msgid", NULL}, /* special handling */
            {"static", "hey"},
            {"multi", "multi1"},
            {"multi", "multi2"},
            {"multi", "multi3"},
            {"null", NULL},
            {"empty", ""},
            {NULL}};
        rd_kafka_headers_t *hdrs;
        rd_kafka_resp_err_t err;

        expect_check(__FUNCTION__, expected, rkmessage, 0);

        err = rd_kafka_message_headers(rkmessage, &hdrs);
        if (err) /* First message has no headers. */
                return RD_KAFKA_RESP_ERR_NO_ERROR;

        rd_kafka_header_add(hdrs, "multi", -1, "multi4", -1);
        rd_kafka_header_add(hdrs, "send1", -1, "1", -1);
        rd_kafka_header_remove(hdrs, "multi");
        rd_kafka_header_add(hdrs, "multi", -1, "multi5", -1);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


/**
 * @brief Second on_send() interceptor
 */
static rd_kafka_resp_err_t
on_send2(rd_kafka_t *rk, rd_kafka_message_t *rkmessage, void *ic_opaque) {
        const struct expect expected[] = {
            {"msgid", NULL}, /* special handling */
            {"static", "hey"}, {"null", NULL},      {"empty", ""},
            {"send1", "1"},    {"multi", "multi5"}, {NULL}};

        expect_check(__FUNCTION__, expected, rkmessage, 0);

        return RD_KAFKA_RESP_ERR_NO_ERROR;
}

/**
 * @brief on_new() interceptor to set up message interceptors
 *        from rd_kafka_new().
 */
static rd_kafka_resp_err_t on_new(rd_kafka_t *rk,
                                  const rd_kafka_conf_t *conf,
                                  void *ic_opaque,
                                  char *errstr,
                                  size_t errstr_size) {
        rd_kafka_interceptor_add_on_send(rk, __FILE__, on_send1, NULL);
        rd_kafka_interceptor_add_on_send(rk, __FILE__, on_send2, NULL);
        return RD_KAFKA_RESP_ERR_NO_ERROR;
}


static void do_produce(const char *topic, int msgcnt) {
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        int i;
        rd_kafka_resp_err_t err;

        test_conf_init(&conf, NULL, 0);
        test_conf_set(conf, "acks", "all");
        rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

        rd_kafka_conf_interceptor_add_on_new(conf, __FILE__, on_new, NULL);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        /* First message is without headers (negative testing) */
        i   = 0;
        err = rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC(topic), RD_KAFKA_V_PARTITION(0),
            RD_KAFKA_V_VALUE(&i, sizeof(i)),
            RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY), RD_KAFKA_V_END);
        TEST_ASSERT(!err, "producev() failed: %s", rd_kafka_err2str(err));
        exp_msgid++;

        for (i = 1; i < msgcnt; i++, exp_msgid++) {
                err = rd_kafka_producev(
                    rk, RD_KAFKA_V_TOPIC(topic), RD_KAFKA_V_PARTITION(0),
                    RD_KAFKA_V_VALUE(&i, sizeof(i)),
                    RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                    RD_KAFKA_V_HEADER("msgid", &i, sizeof(i)),
                    RD_KAFKA_V_HEADER("static", "hey", -1),
                    RD_KAFKA_V_HEADER("multi", "multi1", -1),
                    RD_KAFKA_V_HEADER("multi", "multi2", 6),
                    RD_KAFKA_V_HEADER("multi", "multi3", strlen("multi3")),
                    RD_KAFKA_V_HEADER("null", NULL, 0),
                    RD_KAFKA_V_HEADER("empty", "", 0), RD_KAFKA_V_END);
                TEST_ASSERT(!err, "producev() failed: %s",
                            rd_kafka_err2str(err));
        }

        /* Reset expected message id for dr */
        exp_msgid = 0;

        /* Wait for timeouts and delivery reports */
        rd_kafka_flush(rk, tmout_multip(5000));

        rd_kafka_destroy(rk);
}

static void do_consume(const char *topic, int msgcnt) {
        rd_kafka_t *rk;
        rd_kafka_topic_partition_list_t *parts;

        rk = test_create_consumer(topic, NULL, NULL, NULL);

        parts = rd_kafka_topic_partition_list_new(1);
        rd_kafka_topic_partition_list_add(parts, topic, 0)->offset =
            RD_KAFKA_OFFSET_BEGINNING;

        test_consumer_assign("assign", rk, parts);

        rd_kafka_topic_partition_list_destroy(parts);

        exp_msgid = 0;

        while (exp_msgid < msgcnt) {
                rd_kafka_message_t *rkm;

                rkm = rd_kafka_consumer_poll(rk, 1000);
                if (!rkm)
                        continue;

                if (rkm->err)
                        TEST_FAIL(
                            "consume error while expecting msgid %d/%d: "
                            "%s",
                            exp_msgid, msgcnt, rd_kafka_message_errstr(rkm));

                handle_consumed_msg(rkm);

                rd_kafka_message_destroy(rkm);
        }

        test_consumer_close(rk);
        rd_kafka_destroy(rk);
}


int main_0073_headers(int argc, char **argv) {
        const char *topic = test_mk_topic_name(__FUNCTION__ + 5, 1);
        const int msgcnt  = 10;

        do_produce(topic, msgcnt);
        do_consume(topic, msgcnt);

        return 0;
}
