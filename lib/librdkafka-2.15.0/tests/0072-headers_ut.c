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
 * Local (no broker) unit-like tests of Message Headers
 */



static int exp_msgid = 0;

struct expect {
        const char *name;
        const char *value;
};

/**
 * @brief returns the message id
 */
static int expect_check(const char *what,
                        const struct expect *expected,
                        const rd_kafka_message_t *rkmessage) {
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
                if (msgid == 0)
                        return 0; /* No headers expected for first message */

                TEST_FAIL("%s: Expected headers in message %d: %s", what, msgid,
                          rd_kafka_err2str(err));
        } else {
                TEST_ASSERT(msgid != 0,
                            "%s: first message should have no headers", what);
        }

        /* msgid should always be first and has a variable value so hard to
         * match with the expect struct. */
        for (idx = 0, exp = expected; !rd_kafka_header_get_all(
                 hdrs, idx, &name, (const void **)&value, &size);
             idx++, exp++) {

                TEST_SAYL(3,
                          "%s: Msg #%d: "
                          "Header #%" PRIusz ": %s='%s' (expecting %s='%s')\n",
                          what, msgid, idx, name, value ? value : "(NULL)",
                          exp->name, exp->value ? exp->value : "(NULL)");

                if (strcmp(name, exp->name))
                        TEST_FAIL("%s: Expected header %s at idx #%" PRIusz
                                  ", not %s",
                                  what, exp->name, idx - 1, name);

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

        return msgid;
}


/**
 * @brief Delivery report callback
 */
static void
dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque) {
        const struct expect expected[] = {
            {"msgid", NULL}, /* special handling */
            {"static", "hey"}, {"null", NULL},      {"empty", ""},
            {"send1", "1"},    {"multi", "multi5"}, {NULL}};
        const struct expect replace_expected[] = {
            {"msgid", NULL},       {"new", "one"},
            {"this is the", NULL}, {"replaced headers\"", ""},
            {"new", "right?"},     {NULL}};
        const struct expect *exp;
        rd_kafka_headers_t *new_hdrs;
        int msgid;

        TEST_ASSERT(rkmessage->err == RD_KAFKA_RESP_ERR__MSG_TIMED_OUT,
                    "Expected message to fail with MSG_TIMED_OUT, not %s",
                    rd_kafka_err2str(rkmessage->err));

        msgid = expect_check(__FUNCTION__, expected, rkmessage);

        /* Replace entire headers list */
        if (msgid > 0) {
                new_hdrs = rd_kafka_headers_new(1);
                rd_kafka_header_add(new_hdrs, "msgid", -1, &msgid,
                                    sizeof(msgid));
                for (exp = &replace_expected[1]; exp->name; exp++)
                        rd_kafka_header_add(new_hdrs, exp->name, -1, exp->value,
                                            -1);

                rd_kafka_message_set_headers((rd_kafka_message_t *)rkmessage,
                                             new_hdrs);

                expect_check(__FUNCTION__, replace_expected, rkmessage);
        }

        exp_msgid++;
}

static void expect_iter(const char *what,
                        const rd_kafka_headers_t *hdrs,
                        const char *name,
                        const char **expected,
                        size_t cnt) {
        size_t idx;
        rd_kafka_resp_err_t err;
        const void *value;
        size_t size;

        for (idx = 0;
             !(err = rd_kafka_header_get(hdrs, idx, name, &value, &size));
             idx++) {
                TEST_ASSERT(idx < cnt,
                            "%s: too many headers matching '%s', "
                            "expected %" PRIusz,
                            what, name, cnt);
                TEST_SAYL(3,
                          "%s: get(%" PRIusz
                          ", '%s') "
                          "expecting '%s' =? '%s'\n",
                          what, idx, name, expected[idx], (const char *)value);


                TEST_ASSERT(
                    !strcmp((const char *)value, expected[idx]),
                    "%s: get(%" PRIusz ", '%s') expected '%s', not '%s'", what,
                    idx, name, expected[idx], (const char *)value);
        }

        TEST_ASSERT(idx == cnt,
                    "%s: expected %" PRIusz
                    " headers matching '%s', not %" PRIusz,
                    what, cnt, name, idx);
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
        const char *expect_iter_multi[4] = {
            "multi1", "multi2", "multi3", "multi4" /* added below */
        };
        const char *expect_iter_static[1] = {"hey"};
        rd_kafka_headers_t *hdrs;
        size_t header_cnt;
        rd_kafka_resp_err_t err;
        const void *value;
        size_t size;

        expect_check(__FUNCTION__, expected, rkmessage);

        err = rd_kafka_message_headers(rkmessage, &hdrs);
        if (err) /* First message has no headers. */
                return RD_KAFKA_RESP_ERR_NO_ERROR;

        header_cnt = rd_kafka_header_cnt(hdrs);
        TEST_ASSERT(header_cnt == 7, "Expected 7 length got %" PRIusz "",
                    header_cnt);

        rd_kafka_header_add(hdrs, "multi", -1, "multi4", -1);

        header_cnt = rd_kafka_header_cnt(hdrs);
        TEST_ASSERT(header_cnt == 8, "Expected 8 length got %" PRIusz "",
                    header_cnt);

        /* test iter() */
        expect_iter(__FUNCTION__, hdrs, "multi", expect_iter_multi, 4);
        expect_iter(__FUNCTION__, hdrs, "static", expect_iter_static, 1);
        expect_iter(__FUNCTION__, hdrs, "notexists", NULL, 0);

        rd_kafka_header_add(hdrs, "send1", -1, "1", -1);

        header_cnt = rd_kafka_header_cnt(hdrs);
        TEST_ASSERT(header_cnt == 9, "Expected 9 length got %" PRIusz "",
                    header_cnt);

        rd_kafka_header_remove(hdrs, "multi");

        header_cnt = rd_kafka_header_cnt(hdrs);
        TEST_ASSERT(header_cnt == 5, "Expected 5 length got %" PRIusz "",
                    header_cnt);

        rd_kafka_header_add(hdrs, "multi", -1, "multi5", -1);

        header_cnt = rd_kafka_header_cnt(hdrs);
        TEST_ASSERT(header_cnt == 6, "Expected 6 length got %" PRIusz "",
                    header_cnt);

        /* test get_last() */
        err = rd_kafka_header_get_last(hdrs, "multi", &value, &size);
        TEST_ASSERT(!err, "%s", rd_kafka_err2str(err));
        TEST_ASSERT(size == strlen("multi5") &&
                        !strcmp((const char *)value, "multi5"),
                    "expected 'multi5', not '%s'", (const char *)value);

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

        expect_check(__FUNCTION__, expected, rkmessage);

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


int main_0072_headers_ut(int argc, char **argv) {
        const char *topic = test_mk_topic_name(__FUNCTION__ + 5, 0);
        rd_kafka_t *rk;
        rd_kafka_conf_t *conf;
        int i;
        size_t header_cnt;
        const int msgcnt = 10;
        rd_kafka_resp_err_t err;

        conf = rd_kafka_conf_new();
        test_conf_set(conf, "message.timeout.ms", "1");
        rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

        rd_kafka_conf_interceptor_add_on_new(conf, __FILE__, on_new, NULL);

        rk = test_create_handle(RD_KAFKA_PRODUCER, conf);

        /* First message is without headers (negative testing) */
        i   = 0;
        err = rd_kafka_producev(
            rk, RD_KAFKA_V_TOPIC(topic), RD_KAFKA_V_VALUE(&i, sizeof(i)),
            RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY), RD_KAFKA_V_END);
        TEST_ASSERT(!err, "producev() failed: %s", rd_kafka_err2str(err));
        exp_msgid++;

        for (i = 1; i < msgcnt; i++, exp_msgid++) {
                /* Use headers list on one message */
                if (i == 3) {
                        rd_kafka_headers_t *hdrs = rd_kafka_headers_new(4);

                        header_cnt = rd_kafka_header_cnt(hdrs);
                        TEST_ASSERT(header_cnt == 0,
                                    "Expected 0 length got %" PRIusz "",
                                    header_cnt);

                        rd_kafka_headers_t *copied;

                        rd_kafka_header_add(hdrs, "msgid", -1, &i, sizeof(i));
                        rd_kafka_header_add(hdrs, "static", -1, "hey", -1);
                        rd_kafka_header_add(hdrs, "multi", -1, "multi1", -1);
                        rd_kafka_header_add(hdrs, "multi", -1, "multi2", 6);
                        rd_kafka_header_add(hdrs, "multi", -1, "multi3",
                                            strlen("multi3"));
                        rd_kafka_header_add(hdrs, "null", -1, NULL, 0);

                        /* Make a copy of the headers to verify copy() */
                        copied = rd_kafka_headers_copy(hdrs);

                        header_cnt = rd_kafka_header_cnt(hdrs);
                        TEST_ASSERT(header_cnt == 6,
                                    "Expected 6 length got %" PRIusz "",
                                    header_cnt);

                        rd_kafka_headers_destroy(hdrs);

                        /* Last header ("empty") is added below */

                        /* Try unsupported _V_HEADER() and _V_HEADERS() mix,
                         * must fail with CONFLICT */
                        err = rd_kafka_producev(
                            rk, RD_KAFKA_V_TOPIC(topic),
                            RD_KAFKA_V_VALUE(&i, sizeof(i)),
                            RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                            RD_KAFKA_V_HEADER("will_be_removed", "yep", -1),
                            RD_KAFKA_V_HEADERS(copied),
                            RD_KAFKA_V_HEADER("empty", "", 0), RD_KAFKA_V_END);
                        TEST_ASSERT(err == RD_KAFKA_RESP_ERR__CONFLICT,
                                    "producev(): expected CONFLICT, got %s",
                                    rd_kafka_err2str(err));

                        /* Proper call using only _V_HEADERS() */
                        rd_kafka_header_add(copied, "empty", -1, "", -1);
                        err = rd_kafka_producev(
                            rk, RD_KAFKA_V_TOPIC(topic),
                            RD_KAFKA_V_VALUE(&i, sizeof(i)),
                            RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                            RD_KAFKA_V_HEADERS(copied), RD_KAFKA_V_END);
                        TEST_ASSERT(!err, "producev() failed: %s",
                                    rd_kafka_err2str(err));

                } else {
                        err = rd_kafka_producev(
                            rk, RD_KAFKA_V_TOPIC(topic),
                            RD_KAFKA_V_VALUE(&i, sizeof(i)),
                            RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
                            RD_KAFKA_V_HEADER("msgid", &i, sizeof(i)),
                            RD_KAFKA_V_HEADER("static", "hey", -1),
                            RD_KAFKA_V_HEADER("multi", "multi1", -1),
                            RD_KAFKA_V_HEADER("multi", "multi2", 6),
                            RD_KAFKA_V_HEADER("multi", "multi3",
                                              strlen("multi3")),
                            RD_KAFKA_V_HEADER("null", NULL, 0),
                            RD_KAFKA_V_HEADER("empty", "", 0), RD_KAFKA_V_END);
                        TEST_ASSERT(!err, "producev() failed: %s",
                                    rd_kafka_err2str(err));
                }
        }

        /* Reset expected message id for dr */
        exp_msgid = 0;

        /* Wait for timeouts and delivery reports */
        rd_kafka_flush(rk, 5000);

        rd_kafka_destroy(rk);

        return 0;
}
