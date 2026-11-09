/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_time.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include "flb_tests_runtime.h"

/* in_mqtt listener used as broker by the end to end tests */
#define BROKER_HOST      "127.0.0.1"
#define BROKER_PORT      "21883"

#define MAX_MESSAGES     32
#define WAIT_TIMEOUT_MS  5000

/* Expected result of a configuration case */
#define CONFIG_OK        1
#define CONFIG_ERROR     0

/* One PUBLISH packet decoded from the formatter output */
struct mqtt_message {
    int qos;
    int retain;
    int dup;
    int packet_id;
    int call;               /* formatter call that produced the packet */
    int index;              /* position in that call */
    int length_bytes;       /* size of the Remaining Length field */
    char *topic;            /* NUL terminated copies */
    size_t topic_len;
    char *payload;
    size_t payload_len;
};

struct formatter_result {
    int calls;
    int ret;
    int errors;
    int count;
    struct mqtt_message msgs[MAX_MESSAGES];
};

/* Records received through in_mqtt by the end to end tests */
struct broker_result {
    int count;
    char records[MAX_MESSAGES][1024];
};

static pthread_mutex_t result_lock = PTHREAD_MUTEX_INITIALIZER;
static struct formatter_result fmt_result;
static struct broker_result brk_result;

/* out_lib reads the callback when the engine starts, it must outlive setup */
static struct flb_lib_out_cb broker_cb;

/* Port of the in_mqtt listener, picked for every end to end test */
static char broker_port[16];

/* Ask the system for a free loopback port, BROKER_PORT is the fallback */
static void broker_port_pick()
{
#ifndef _WIN32
    int fd;
    socklen_t len;
    struct sockaddr_in addr;

    snprintf(broker_port, sizeof(broker_port), "%s", BROKER_PORT);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    len = sizeof(addr);
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == 0 &&
        getsockname(fd, (struct sockaddr *) &addr, &len) == 0) {
        snprintf(broker_port, sizeof(broker_port), "%u",
                 (unsigned int) ntohs(addr.sin_port));
    }
    close(fd);
#else
    snprintf(broker_port, sizeof(broker_port), "%s", BROKER_PORT);
#endif
}

static void results_reset()
{
    int i;

    pthread_mutex_lock(&result_lock);
    for (i = 0; i < fmt_result.count; i++) {
        flb_free(fmt_result.msgs[i].topic);
        flb_free(fmt_result.msgs[i].payload);
    }
    memset(&fmt_result, 0, sizeof(fmt_result));
    memset(&brk_result, 0, sizeof(brk_result));
    pthread_mutex_unlock(&result_lock);
}

static int formatter_calls()
{
    int ret;

    pthread_mutex_lock(&result_lock);
    ret = fmt_result.calls;
    pthread_mutex_unlock(&result_lock);

    return ret;
}

static int formatter_messages()
{
    int ret;

    pthread_mutex_lock(&result_lock);
    ret = fmt_result.count;
    pthread_mutex_unlock(&result_lock);

    return ret;
}

static int broker_records()
{
    int ret;

    pthread_mutex_lock(&result_lock);
    ret = brk_result.count;
    pthread_mutex_unlock(&result_lock);

    return ret;
}

static int wait_for(int (*counter)(), int expected, int timeout_ms)
{
    int elapsed = 0;

    while (elapsed < timeout_ms) {
        if (counter() >= expected) {
            return 0;
        }
        flb_time_msleep(20);
        elapsed += 20;
    }

    return -1;
}

static char *copy_bytes(const unsigned char *buf, size_t len)
{
    char *out;

    out = flb_malloc(len + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, buf, len);
    out[len] = '\0';

    return out;
}

/*
 * Decode a stream of PUBLISH packets. This decoder is written from the
 * MQTT 3.1.1 specification and does not share code with the plugin.
 */
static int publish_stream_parse(const unsigned char *buf, size_t size, int call)
{
    int index;
    size_t off;
    size_t end;
    size_t len;
    size_t mult;
    size_t start;
    size_t topic_len;
    unsigned char byte;
    struct mqtt_message *m;

    off = 0;
    index = 0;
    while (off < size) {
        if ((buf[off] >> 4) != 3 || fmt_result.count >= MAX_MESSAGES) {
            return -1;
        }

        m = &fmt_result.msgs[fmt_result.count];
        memset(m, 0, sizeof(struct mqtt_message));
        m->dup = (buf[off] >> 3) & 0x01;
        m->qos = (buf[off] >> 1) & 0x03;
        m->retain = buf[off] & 0x01;
        m->call = call;
        m->index = index;
        off++;

        /* Remaining Length */
        start = off;
        len = 0;
        mult = 1;
        do {
            if (off >= size || mult > 128 * 128 * 128) {
                return -1;
            }
            byte = buf[off++];
            len += (byte & 0x7f) * mult;
            mult *= 128;
        } while (byte & 0x80);
        m->length_bytes = (int) (off - start);

        if (len > size - off || len < 2) {
            return -1;
        }
        end = off + len;

        topic_len = ((size_t) buf[off] << 8) | buf[off + 1];
        off += 2;
        if (topic_len > end - off) {
            return -1;
        }

        m->packet_id = -1;
        if (m->qos > 0) {
            if (end - off - topic_len < 2) {
                return -1;
            }
            m->packet_id = (buf[off + topic_len] << 8) | buf[off + topic_len + 1];
        }

        m->topic = copy_bytes(buf + off, topic_len);
        m->topic_len = topic_len;
        off += topic_len;
        if (m->qos > 0) {
            off += 2;
        }

        m->payload = copy_bytes(buf + off, end - off);
        m->payload_len = end - off;
        if (!m->topic || !m->payload) {
            flb_free(m->topic);
            flb_free(m->payload);
            m->topic = NULL;
            m->payload = NULL;
            return -1;
        }

        off = end;
        index++;
        fmt_result.count++;
    }

    return 0;
}

static void cb_formatter(void *ctx, int ffd, int res_ret,
                         void *res_data, size_t res_size, void *data)
{
    (void) ctx;
    (void) ffd;
    (void) data;

    pthread_mutex_lock(&result_lock);
    fmt_result.ret = res_ret;
    if (res_data != NULL && res_size > 0) {
        if (publish_stream_parse(res_data, res_size, fmt_result.calls) != 0) {
            fmt_result.errors++;
        }
    }
    fmt_result.calls++;
    pthread_mutex_unlock(&result_lock);

    if (res_data != NULL) {
        flb_free(res_data);
    }
}

static int cb_broker_record(void *record, size_t size, void *data)
{
    (void) data;

    pthread_mutex_lock(&result_lock);
    if (brk_result.count < MAX_MESSAGES && size < sizeof(brk_result.records[0])) {
        memcpy(brk_result.records[brk_result.count], record, size);
        brk_result.records[brk_result.count][size] = '\0';
        brk_result.count++;
    }
    pthread_mutex_unlock(&result_lock);

    flb_free(record);

    return 0;
}

static flb_ctx_t *formatter_ctx_create(const char *tag, int *in_ffd, int *out_ffd)
{
    flb_ctx_t *ctx;

    results_reset();

    ctx = flb_create();
    if (!TEST_CHECK(ctx != NULL)) {
        return NULL;
    }

    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    *in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(*in_ffd >= 0);
    flb_input_set(ctx, *in_ffd, "tag", tag, NULL);

    *out_ffd = flb_output(ctx, (char *) "mqtt", NULL);
    TEST_CHECK(*out_ffd >= 0);
    flb_output_set(ctx, *out_ffd, "match", "*", NULL);

    flb_output_set_test(ctx, *out_ffd, "formatter", cb_formatter, NULL, NULL);

    return ctx;
}

/* Start the pipeline, ingest the records and wait for the formatter */
static void formatter_run(flb_ctx_t *ctx, int in_ffd,
                          const char **records, int count, int expected)
{
    int i;
    int ret;

    ret = flb_start(ctx);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("flb_start failed");
        flb_destroy(ctx);
        return;
    }

    for (i = 0; i < count; i++) {
        ret = flb_lib_push(ctx, in_ffd, (char *) records[i], strlen(records[i]));
        TEST_CHECK(ret >= 0);
    }

    if (expected > 0) {
        ret = wait_for(formatter_messages, expected, WAIT_TIMEOUT_MS);
    }
    else {
        ret = wait_for(formatter_calls, 1, WAIT_TIMEOUT_MS);
    }
    TEST_CHECK(ret == 0);

    /* Give a chance to unexpected extra messages to show up */
    flb_time_msleep(300);

    flb_stop(ctx);
    flb_destroy(ctx);

    pthread_mutex_lock(&result_lock);
    TEST_CHECK(fmt_result.errors == 0);
    if (!TEST_CHECK(fmt_result.count == expected)) {
        TEST_MSG("expected %i messages, got %i", expected, fmt_result.count);
    }
    pthread_mutex_unlock(&result_lock);
}

static struct mqtt_message *message_get(int i)
{
    if (i >= fmt_result.count) {
        return NULL;
    }
    return &fmt_result.msgs[i];
}

/* Find a message by its payload content */
static struct mqtt_message *message_find(const char *needle)
{
    int i;

    for (i = 0; i < fmt_result.count; i++) {
        if (strstr(fmt_result.msgs[i].payload, needle) != NULL) {
            return &fmt_result.msgs[i];
        }
    }

    return NULL;
}

/* A string made of 'len' times 'c' followed by 'suffix' */
static char *string_repeat(const char *prefix, char c, size_t len, const char *suffix)
{
    char *out;
    size_t plen;
    size_t slen;

    plen = strlen(prefix);
    slen = strlen(suffix);

    out = flb_malloc(plen + len + slen + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, prefix, plen);
    memset(out + plen, c, len);
    memcpy(out + plen + len, suffix, slen);
    out[plen + len + slen] = '\0';

    return out;
}

void flb_test_format_json()
{
    int i;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct mqtt_message *m;
    const char *records[] = {
        "[1, {\"msg\":\"hello\", \"val\":1}]",
        "[2, {\"msg\":\"world\", \"nested\":{\"k\":\"v\"}}]"
    };

    ctx = formatter_ctx_create("app.web", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }

    formatter_run(ctx, in_ffd, records, 2, 2);

    m = message_find("hello");
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(strcmp(m->topic, "fluent-bit") == 0);
        TEST_CHECK(m->qos == 1);
        TEST_CHECK(m->retain == 0);
        TEST_CHECK(m->dup == 0);
        TEST_CHECK(m->length_bytes == 1);
        if (!TEST_CHECK(strcmp(m->payload,
                               "{\"date\":1.0,\"msg\":\"hello\",\"val\":1}") == 0)) {
            TEST_MSG("payload: %s", m->payload);
        }
    }

    m = message_find("world");
    if (TEST_CHECK(m != NULL)) {
        if (!TEST_CHECK(strcmp(m->payload, "{\"date\":2.0,\"msg\":\"world\","
                                           "\"nested\":{\"k\":\"v\"}}") == 0)) {
            TEST_MSG("payload: %s", m->payload);
        }
    }

    /* QoS 1 packet identifiers start at 1 in every flush */
    for (i = 0; i < fmt_result.count; i++) {
        m = message_get(i);
        TEST_CHECK(m->packet_id == m->index + 1);
    }

    results_reset();
}

/* Payloads that need two and three bytes for the Remaining Length */
void flb_test_large_payloads()
{
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    char *records[2];
    char *expected[2];
    struct mqtt_message *m;

    records[0] = string_repeat("[1, {\"msg\":\"", 'a', 180, "\"}]");
    records[1] = string_repeat("[2, {\"msg\":\"", 'b', 20000, "\"}]");
    expected[0] = string_repeat("{\"date\":1.0,\"msg\":\"", 'a', 180, "\"}");
    expected[1] = string_repeat("{\"date\":2.0,\"msg\":\"", 'b', 20000, "\"}");
    if (!TEST_CHECK(records[0] && records[1] && expected[0] && expected[1])) {
        goto cleanup;
    }

    ctx = formatter_ctx_create("test", &in_ffd, &out_ffd);
    if (!ctx) {
        goto cleanup;
    }

    formatter_run(ctx, in_ffd, (const char **) records, 2, 2);

    m = message_find("aaaa");
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(m->length_bytes == 2);
        TEST_CHECK(m->payload_len == strlen(expected[0]));
        TEST_CHECK(strcmp(m->payload, expected[0]) == 0);
    }

    m = message_find("bbbb");
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(m->length_bytes == 3);
        TEST_CHECK(m->payload_len == strlen(expected[1]));
        TEST_CHECK(strcmp(m->payload, expected[1]) == 0);
    }

    results_reset();

cleanup:
    flb_free(records[0]);
    flb_free(records[1]);
    flb_free(expected[0]);
    flb_free(expected[1]);
}

void flb_test_topic_tag()
{
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct mqtt_message *m;
    const char *records[] = {
        "[1, {\"msg\":\"hello\"}]"
    };

    ctx = formatter_ctx_create("app.web.access", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }
    flb_output_set(ctx, out_ffd,
                   "topic", "$aws/logs/$TAG/$TAG[1]/$TAG[0]-$TAG[7]",
                   NULL);

    formatter_run(ctx, in_ffd, records, 1, 1);

    m = message_get(0);
    if (TEST_CHECK(m != NULL)) {
        if (!TEST_CHECK(strcmp(m->topic, "$aws/logs/app.web.access/web/app-") == 0)) {
            TEST_MSG("topic: %s", m->topic);
        }
    }

    results_reset();
}

void flb_test_topic_key()
{
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct mqtt_message *m;
    const char *records[] = {
        "[1, {\"msg\":\"one\", \"dest\":\"sensors/kitchen\"}]",
        "[2, {\"msg\":\"two\"}]",
        "[3, {\"msg\":\"three\", \"dest\":\"sensors/#\"}]",
        "[4, {\"msg\":\"four\", \"dest\":12}]",
        "[5, {\"msg\":\"five\", \"meta\":{\"topic\":\"nested/topic\"}}]"
    };

    ctx = formatter_ctx_create("test", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }
    flb_output_set(ctx, out_ffd,
                   "topic", "default/$TAG",
                   "topic_key", "dest",
                   NULL);

    formatter_run(ctx, in_ffd, records, 5, 5);

    m = message_find("one");
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(strcmp(m->topic, "sensors/kitchen") == 0);
    }

    /* No key, wildcard value or not a string: default topic */
    m = message_find("two");
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(strcmp(m->topic, "default/test") == 0);
    }
    m = message_find("three");
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(strcmp(m->topic, "default/test") == 0);
    }
    m = message_find("four");
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(strcmp(m->topic, "default/test") == 0);
    }
    m = message_find("five");
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(strcmp(m->topic, "default/test") == 0);
    }

    results_reset();
}

/*
 * Control characters and Unicode non-characters can make a broker close the
 * connection, such topic_key values fall back to the default topic. Other
 * non-ASCII characters are valid.
 */
void flb_test_topic_key_characters()
{
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct mqtt_message *m;
    const char *records[] = {
        "[1, {\"msg\":\"one\", \"dest\":\"a/\\u0001\"}]",
        "[2, {\"msg\":\"two\", \"dest\":\"a/\\u0085\"}]",
        "[3, {\"msg\":\"three\", \"dest\":\"a/\\uffff\"}]",
        "[4, {\"msg\":\"four\", \"dest\":\"caf\\u00e9/x\"}]"
    };

    ctx = formatter_ctx_create("test", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }
    flb_output_set(ctx, out_ffd,
                   "topic_key", "dest",
                   NULL);

    formatter_run(ctx, in_ffd, records, 4, 4);

    m = message_find("\"one\"");
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(strcmp(m->topic, "fluent-bit") == 0);
    }
    m = message_find("\"two\"");
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(strcmp(m->topic, "fluent-bit") == 0);
    }
    m = message_find("\"three\"");
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(strcmp(m->topic, "fluent-bit") == 0);
    }
    m = message_find("\"four\"");
    if (TEST_CHECK(m != NULL)) {
        if (!TEST_CHECK(strcmp(m->topic, "caf\xc3\xa9/x") == 0)) {
            TEST_MSG("topic: %s", m->topic);
        }
    }

    results_reset();
}

void flb_test_topic_key_nested()
{
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct mqtt_message *m;
    const char *records[] = {
        "[1, {\"msg\":\"one\", \"meta\":{\"topic\":\"nested/topic\"}}]"
    };

    ctx = formatter_ctx_create("test", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }
    flb_output_set(ctx, out_ffd,
                   "topic_key", "$meta['topic']",
                   NULL);

    formatter_run(ctx, in_ffd, records, 1, 1);

    m = message_get(0);
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(strcmp(m->topic, "nested/topic") == 0);
    }

    results_reset();
}

/* A topic longer than the 128 bytes a single length byte can describe */
void flb_test_long_topic()
{
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    char *record;
    char *topic;
    const char *records[1];
    struct mqtt_message *m;

    record = string_repeat("[1, {\"msg\":\"long\", \"dest\":\"t/", 'c', 300, "\"}]");
    topic = string_repeat("t/", 'c', 300, "");
    if (!TEST_CHECK(record != NULL && topic != NULL)) {
        flb_free(record);
        flb_free(topic);
        return;
    }
    records[0] = record;

    ctx = formatter_ctx_create("test", &in_ffd, &out_ffd);
    if (ctx) {
        flb_output_set(ctx, out_ffd,
                       "topic_key", "dest",
                       NULL);

        formatter_run(ctx, in_ffd, records, 1, 1);

        m = message_get(0);
        if (TEST_CHECK(m != NULL)) {
            TEST_CHECK(m->topic_len == 302);
            TEST_CHECK(strcmp(m->topic, topic) == 0);
            TEST_CHECK(m->length_bytes == 2);
        }
        results_reset();
    }

    flb_free(record);
    flb_free(topic);
}

void flb_test_payload_key()
{
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct mqtt_message *m;
    const char *records[] = {
        "[1, {\"id\":1, \"data\":\"on\"}]",
        "[2, {\"id\":2, \"data\":{\"temp\":21.5}}]",
        "[3, {\"id\":3, \"data\":[1,2,3]}]",
        "[4, {\"id\":4}]"
    };

    ctx = formatter_ctx_create("test", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }
    flb_output_set(ctx, out_ffd,
                   "payload_key", "data",
                   NULL);

    /* The record without the key is dropped */
    formatter_run(ctx, in_ffd, records, 4, 3);

    m = message_find("on");
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(strcmp(m->payload, "on") == 0);
    }

    m = message_find("temp");
    if (TEST_CHECK(m != NULL)) {
        if (!TEST_CHECK(strcmp(m->payload, "{\"temp\":21.5}") == 0)) {
            TEST_MSG("payload: %s", m->payload);
        }
    }

    m = message_find("[1,2,3]");
    TEST_CHECK(m != NULL);

    results_reset();
}

void flb_test_payload_key_missing()
{
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    const char *records[] = {
        "[1, {\"msg\":\"no payload key\"}]"
    };

    ctx = formatter_ctx_create("test", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }
    flb_output_set(ctx, out_ffd,
                   "payload_key", "data",
                   NULL);

    formatter_run(ctx, in_ffd, records, 1, 0);

    pthread_mutex_lock(&result_lock);
    TEST_CHECK(fmt_result.ret == FLB_OK);
    pthread_mutex_unlock(&result_lock);

    results_reset();
}

void flb_test_format_msgpack()
{
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct mqtt_message *m;
    const char *records[] = {
        "[1, {\"msg\":\"hello\", \"val\":7}]"
    };
    /* {"date": 1, "msg": "hello", "val": 7}: the date key comes first */
    const char expected[] = "\x83\xa4" "date" "\x01\xa3" "msg" "\xa5" "hello"
                            "\xa3" "val" "\x07";

    ctx = formatter_ctx_create("test", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }
    flb_output_set(ctx, out_ffd,
                   "format", "msgpack",
                   "json_date_format", "epoch",
                   NULL);

    formatter_run(ctx, in_ffd, records, 1, 1);

    m = message_get(0);
    if (TEST_CHECK(m != NULL)) {
        /* Exact bytes: every key once, in order, with its value */
        TEST_CHECK(m->payload_len == sizeof(expected) - 1);
        TEST_CHECK(m->payload_len == sizeof(expected) - 1 &&
                   memcmp(m->payload, expected, m->payload_len) == 0);
    }

    results_reset();
}

#ifdef FLB_HAVE_LUA
/*
 * A record JSON cannot represent is dropped, the other records of the chunk
 * are published and the flush succeeds: a retry would fail the same way. The
 * lua filter packs a table used as a key as a msgpack array.
 */
void flb_test_json_unrepresentable_key()
{
    int in_ffd;
    int out_ffd;
    int filter_ffd;
    flb_ctx_t *ctx;
    struct mqtt_message *m;
    const char *records[] = {
        "[1, {\"msg\":\"kept\"}]",
        "[2, {\"msg\":\"dropped\"}]"
    };
    const char *script =
        "function cb(tag, ts, record)\n"
        "  if record['msg'] == 'dropped' then\n"
        "    record[{1}] = 'x'\n"
        "  end\n"
        "  return 1, ts, record\n"
        "end\n";

    ctx = formatter_ctx_create("test", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }

    filter_ffd = flb_filter(ctx, (char *) "lua", NULL);
    if (filter_ffd < 0) {
        TEST_MSG("lua filter not available, test skipped");
        flb_destroy(ctx);
        return;
    }
    flb_filter_set(ctx, filter_ffd,
                   "match", "*",
                   "call", "cb",
                   "code", script,
                   NULL);

    formatter_run(ctx, in_ffd, records, 2, 1);

    m = message_get(0);
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(strstr(m->payload, "\"kept\"") != NULL);
    }

    pthread_mutex_lock(&result_lock);
    TEST_CHECK(fmt_result.ret == FLB_OK);
    pthread_mutex_unlock(&result_lock);

    results_reset();
}
#endif

void flb_test_qos0_retain()
{
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct mqtt_message *m;
    const char *records[] = {
        "[1, {\"msg\":\"hello\"}]"
    };

    ctx = formatter_ctx_create("test", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }
    flb_output_set(ctx, out_ffd,
                   "qos", "0",
                   "retain", "on",
                   NULL);

    formatter_run(ctx, in_ffd, records, 1, 1);

    m = message_get(0);
    if (TEST_CHECK(m != NULL)) {
        TEST_CHECK(m->qos == 0);
        TEST_CHECK(m->retain == 1);
        TEST_CHECK(m->packet_id == -1);
    }

    results_reset();
}

void flb_test_json_date()
{
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct mqtt_message *m;
    const char *records[] = {
        "[1, {\"msg\":\"hello\"}]"
    };

    ctx = formatter_ctx_create("test", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }
    flb_output_set(ctx, out_ffd,
                   "json_date_key", "@timestamp",
                   "json_date_format", "iso8601",
                   NULL);

    formatter_run(ctx, in_ffd, records, 1, 1);

    m = message_get(0);
    if (TEST_CHECK(m != NULL)) {
        if (!TEST_CHECK(strcmp(m->payload, "{\"@timestamp\":\"1970-01-01T00:00:01."
                                           "000000Z\",\"msg\":\"hello\"}") == 0)) {
            TEST_MSG("payload: %s", m->payload);
        }
    }

    results_reset();
}

void flb_test_json_date_key_off()
{
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct mqtt_message *m;
    const char *records[] = {
        "[1, {\"msg\":\"hello\"}]"
    };

    ctx = formatter_ctx_create("test", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }
    flb_output_set(ctx, out_ffd,
                   "json_date_key", "false",
                   NULL);

    formatter_run(ctx, in_ffd, records, 1, 1);

    m = message_get(0);
    if (TEST_CHECK(m != NULL)) {
        if (!TEST_CHECK(strcmp(m->payload, "{\"msg\":\"hello\"}") == 0)) {
            TEST_MSG("payload: %s", m->payload);
        }
    }

    results_reset();
}

/* A tag that produces an invalid topic name drops the records */
void flb_test_invalid_tag_topic()
{
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    const char *records[] = {
        "[1, {\"msg\":\"hello\"}]"
    };

    ctx = formatter_ctx_create("bad+tag", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }
    flb_output_set(ctx, out_ffd,
                   "topic", "logs/$TAG",
                   NULL);

    formatter_run(ctx, in_ffd, records, 1, 0);

    pthread_mutex_lock(&result_lock);
    TEST_CHECK(fmt_result.ret == FLB_OK);
    pthread_mutex_unlock(&result_lock);

    results_reset();
}

/* $TAG[n] beyond the last part of the tag expands to an empty topic */
void flb_test_empty_tag_topic()
{
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    const char *records[] = {
        "[1, {\"msg\":\"hello\"}]"
    };

    ctx = formatter_ctx_create("app.web", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }
    flb_output_set(ctx, out_ffd,
                   "topic", "$TAG[5]",
                   NULL);

    formatter_run(ctx, in_ffd, records, 1, 0);

    pthread_mutex_lock(&result_lock);
    TEST_CHECK(fmt_result.ret == FLB_OK);
    pthread_mutex_unlock(&result_lock);

    results_reset();
}

/*
 * With max_inflight the packet identifiers keep growing across windows. The
 * records are pushed at once (in_lib reads concatenated JSON messages) so
 * they are in a single chunk.
 */
void flb_test_max_inflight()
{
    int i;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    struct mqtt_message *m;
    const char *records[] = {
        "[1, {\"n\":1}][2, {\"n\":2}][3, {\"n\":3}][4, {\"n\":4}][5, {\"n\":5}]"
    };

    ctx = formatter_ctx_create("test", &in_ffd, &out_ffd);
    if (!ctx) {
        return;
    }
    flb_output_set(ctx, out_ffd,
                   "max_inflight", "2",
                   NULL);

    formatter_run(ctx, in_ffd, records, 1, 5);

    pthread_mutex_lock(&result_lock);
    TEST_CHECK(fmt_result.calls == 1);
    pthread_mutex_unlock(&result_lock);

    for (i = 0; i < fmt_result.count; i++) {
        m = message_get(i);
        TEST_CHECK(m->call == 0);
        TEST_CHECK(m->packet_id == i + 1);
    }

    results_reset();
}

/*
 * Start an output configured with the NULL terminated key/value pairs and
 * check that it starts or fails as expected.
 */
static void config_case(int expected, const char *reason, ...)
{
    int ret;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;
    va_list va;
    const char *key;
    const char *val;

    ctx = flb_create();
    if (!TEST_CHECK(ctx != NULL)) {
        return;
    }

    flb_service_set(ctx, "Flush", "0.200000000", "Grace", "1",
                    "Log_Level", "off", NULL);

    in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(in_ffd >= 0);
    flb_input_set(ctx, in_ffd, "tag", "test", NULL);

    out_ffd = flb_output(ctx, (char *) "mqtt", NULL);
    TEST_CHECK(out_ffd >= 0);
    flb_output_set(ctx, out_ffd, "match", "test", NULL);

    va_start(va, reason);
    while ((key = va_arg(va, const char *)) != NULL) {
        val = va_arg(va, const char *);
        flb_output_set(ctx, out_ffd, key, val, NULL);
    }
    va_end(va);

    ret = flb_start(ctx);
    if (expected == CONFIG_OK) {
        if (!TEST_CHECK(ret == 0)) {
            TEST_MSG("configuration rejected: %s", reason);
        }
    }
    else if (!TEST_CHECK(ret != 0)) {
        TEST_MSG("configuration accepted: %s", reason);
    }

    if (ret == 0) {
        flb_stop(ctx);
    }
    flb_destroy(ctx);
}

/*
 * Every rejected value is paired with an accepted value for the same keys,
 * so a misspelled property cannot make a case pass.
 */
void flb_test_config_validation()
{
    char *topic_max;
    char *topic_over;

    config_case(CONFIG_OK, "qos 0", "qos", "0", NULL);
    config_case(CONFIG_OK, "qos 1", "qos", "1", NULL);
    config_case(CONFIG_ERROR, "qos 2", "qos", "2", NULL);
    config_case(CONFIG_ERROR, "qos 3", "qos", "3", NULL);

    config_case(CONFIG_OK, "credentials", "username", "user", "password", "secret", NULL);
    config_case(CONFIG_ERROR, "password without username", "password", "secret", NULL);
    config_case(CONFIG_ERROR, "username with a control character",
                "username", "us\x01" "er", "password", "secret", NULL);

    config_case(CONFIG_OK, "fixed client_id, one worker",
                "client_id", "sensor-1", "workers", "1", NULL);
    config_case(CONFIG_OK, "fixed client_id, no workers",
                "client_id", "sensor-1", "workers", "0", NULL);
    config_case(CONFIG_ERROR, "fixed client_id, two workers",
                "client_id", "sensor-1", "workers", "2", NULL);
    config_case(CONFIG_ERROR, "client_id with a control character",
                "client_id", "sensor\x01", NULL);
    config_case(CONFIG_ERROR, "client_id with U+FFFE",
                "client_id", "sensor\xef\xbf\xbe", NULL);

    config_case(CONFIG_OK, "topic", "topic", "logs/a", NULL);
    config_case(CONFIG_ERROR, "multi level wildcard", "topic", "logs/#", NULL);
    config_case(CONFIG_ERROR, "single level wildcard", "topic", "logs/+/x", NULL);
    config_case(CONFIG_OK, "largest tag part index", "topic", "a/$TAG[1024]", NULL);
    config_case(CONFIG_ERROR, "tag part index too large", "topic", "a/$TAG[1025]", NULL);
    config_case(CONFIG_ERROR, "tag part without index", "topic", "logs/$TAG[]", NULL);
    config_case(CONFIG_ERROR, "unterminated tag part", "topic", "logs/$TAG[1", NULL);

    topic_max = string_repeat("", 't', 65535, "");
    topic_over = string_repeat("", 't', 65536, "");
    if (TEST_CHECK(topic_max != NULL && topic_over != NULL)) {
        config_case(CONFIG_OK, "65535 bytes topic", "topic", topic_max, NULL);
        config_case(CONFIG_ERROR, "65536 bytes topic", "topic", topic_over, NULL);
    }
    flb_free(topic_max);
    flb_free(topic_over);

    config_case(CONFIG_OK, "msgpack format", "format", "msgpack", NULL);
    config_case(CONFIG_ERROR, "unknown format", "format", "xml", NULL);
    config_case(CONFIG_OK, "date format", "json_date_format", "iso8601", NULL);
    config_case(CONFIG_ERROR, "unknown date format", "json_date_format", "weekday", NULL);

    config_case(CONFIG_OK, "keep_alive 0", "keep_alive", "0", NULL);
    config_case(CONFIG_OK, "keep_alive 65535", "keep_alive", "65535", NULL);
    config_case(CONFIG_ERROR, "keep_alive 65536", "keep_alive", "65536", NULL);

    config_case(CONFIG_OK, "max_inflight 1", "max_inflight", "1", NULL);
    config_case(CONFIG_OK, "max_inflight 65535", "max_inflight", "65535", NULL);
    config_case(CONFIG_ERROR, "max_inflight 0", "max_inflight", "0", NULL);
    config_case(CONFIG_ERROR, "max_inflight 65536", "max_inflight", "65536", NULL);

    config_case(CONFIG_OK, "topic_key", "topic_key", "dest", NULL);
    config_case(CONFIG_OK, "nested topic_key", "topic_key", "$meta['topic']", NULL);
    config_case(CONFIG_ERROR, "topic_key template", "topic_key", "a b", NULL);
    config_case(CONFIG_ERROR, "topic_key $TAG", "topic_key", "$TAG", NULL);
    config_case(CONFIG_OK, "payload_key", "payload_key", "body", NULL);
    config_case(CONFIG_ERROR, "empty payload_key", "payload_key", "$", NULL);
}

/*
 * End to end tests: records are published to an in_mqtt listener of the same
 * pipeline, which ingests them again under the 'from_mqtt' tag.
 */
static flb_ctx_t *broker_ctx_create(int *in_ffd, int *out_ffd)
{
    int ret;
    int mqtt_ffd;
    int lib_ffd;
    flb_ctx_t *ctx;

    results_reset();

    ctx = flb_create();
    if (!TEST_CHECK(ctx != NULL)) {
        return NULL;
    }

    flb_service_set(ctx,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    /* The end to end tests need the in_mqtt plugin, skip them without it */
    mqtt_ffd = flb_input(ctx, (char *) "mqtt", NULL);
    if (mqtt_ffd < 0) {
        fprintf(stderr, "[out_mqtt test] in_mqtt is not available, the end to "
                "end test is skipped\n");
        flb_destroy(ctx);
        return NULL;
    }

    broker_port_pick();
    ret = flb_input_set(ctx, mqtt_ffd,
                        "tag", "from_mqtt",
                        "listen", BROKER_HOST,
                        "port", broker_port,
                        NULL);
    TEST_CHECK(ret == 0);

    *in_ffd = flb_input(ctx, (char *) "lib", NULL);
    TEST_CHECK(*in_ffd >= 0);
    flb_input_set(ctx, *in_ffd, "tag", "test", NULL);

    *out_ffd = flb_output(ctx, (char *) "mqtt", NULL);
    TEST_CHECK(*out_ffd >= 0);
    ret = flb_output_set(ctx, *out_ffd,
                         "match", "test",
                         "host", BROKER_HOST,
                         "port", broker_port,
                         "topic", "sensors/$TAG",
                         "retry_limit", "5",
                         NULL);
    TEST_CHECK(ret == 0);

    broker_cb.cb = cb_broker_record;
    broker_cb.data = NULL;
    lib_ffd = flb_output(ctx, (char *) "lib", &broker_cb);
    TEST_CHECK(lib_ffd >= 0);
    ret = flb_output_set(ctx, lib_ffd,
                         "match", "from_mqtt",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    return ctx;
}

static int broker_record_find(const char *a, const char *b)
{
    int i;
    int found = 0;

    pthread_mutex_lock(&result_lock);
    for (i = 0; i < brk_result.count; i++) {
        if (strstr(brk_result.records[i], a) != NULL &&
            (b == NULL || strstr(brk_result.records[i], b) != NULL)) {
            found++;
        }
    }
    pthread_mutex_unlock(&result_lock);

    return found;
}

/* Ingest the records in a started pipeline and check what in_mqtt received */
static void broker_run(flb_ctx_t *ctx, int in_ffd, int records, int pause_ms)
{
    int i;
    int ret;
    char buf[128];

    for (i = 0; i < records; i++) {
        snprintf(buf, sizeof(buf), "[%i, {\"msg\":\"message-%i\"}]", i + 1, i);
        ret = flb_lib_push(ctx, in_ffd, buf, strlen(buf));
        TEST_CHECK(ret >= 0);

        if (pause_ms > 0) {
            flb_time_msleep(pause_ms);
        }
    }

    ret = wait_for(broker_records, records, WAIT_TIMEOUT_MS);
    if (!TEST_CHECK(ret == 0)) {
        TEST_MSG("received %i records, expected %i", broker_records(), records);
    }

    flb_stop(ctx);
    flb_destroy(ctx);

    for (i = 0; i < records; i++) {
        snprintf(buf, sizeof(buf), "\"msg\":\"message-%i\"", i);
        if (!TEST_CHECK(broker_record_find(buf, "\"topic\":\"sensors/test\"") == 1)) {
            TEST_MSG("record %i not received once with the expected topic", i);
        }
    }
}

/*
 * Run an end to end test with the NULL terminated output properties 'props'.
 * The listener port is picked before in_mqtt binds it and another process
 * can take it in between, so a failed startup is tried again on a new port.
 */
static void broker_test(const char **props, int records, int pause_ms)
{
    int i;
    int ret;
    int attempt;
    int in_ffd;
    int out_ffd;
    flb_ctx_t *ctx;

    ctx = NULL;
    for (attempt = 0; attempt < 3; attempt++) {
        ctx = broker_ctx_create(&in_ffd, &out_ffd);
        if (!ctx) {
            /* in_mqtt is not available, the test is skipped */
            return;
        }

        for (i = 0; props[i] != NULL; i += 2) {
            flb_output_set(ctx, out_ffd, props[i], props[i + 1], NULL);
        }

        ret = flb_start(ctx);
        if (ret == 0) {
            break;
        }

        flb_destroy(ctx);
        ctx = NULL;
    }

    if (!TEST_CHECK(ctx != NULL)) {
        TEST_MSG("flb_start failed");
        return;
    }

    broker_run(ctx, in_ffd, records, pause_ms);
}

void flb_test_broker_qos1()
{
    /* Small windows: several PUBACK rounds in one flush */
    const char *props[] = {"qos", "1", "max_inflight", "2", NULL};

    broker_test(props, 5, 0);
}

void flb_test_broker_qos0()
{
    const char *props[] = {"qos", "0", NULL};

    broker_test(props, 3, 0);
}

/* Several flushes reuse the session of a fixed client identifier */
void flb_test_broker_fixed_client_id()
{
    const char *props[] = {
        "client_id", "fluent-bit-test",
        "username", "user",
        "password", "secret",
        NULL
    };

    broker_test(props, 4, 300);
}

/* Every flush opens and closes its own session */
void flb_test_broker_no_keepalive()
{
    const char *props[] = {"net.keepalive", "off", "workers", "0", NULL};

    broker_test(props, 3, 300);
}

/* Test list */
TEST_LIST = {
    {"format_json",            flb_test_format_json},
    {"large_payloads",         flb_test_large_payloads},
    {"topic_tag",              flb_test_topic_tag},
    {"topic_key",              flb_test_topic_key},
    {"topic_key_characters",   flb_test_topic_key_characters},
    {"topic_key_nested",       flb_test_topic_key_nested},
    {"long_topic",             flb_test_long_topic},
    {"payload_key",            flb_test_payload_key},
    {"payload_key_missing",    flb_test_payload_key_missing},
    {"format_msgpack",         flb_test_format_msgpack},
#ifdef FLB_HAVE_LUA
    {"json_unrepresentable_key", flb_test_json_unrepresentable_key},
#endif
    {"qos0_retain",            flb_test_qos0_retain},
    {"json_date",              flb_test_json_date},
    {"json_date_key_off",      flb_test_json_date_key_off},
    {"invalid_tag_topic",      flb_test_invalid_tag_topic},
    {"empty_tag_topic",        flb_test_empty_tag_topic},
    {"max_inflight",           flb_test_max_inflight},
    {"config_validation",      flb_test_config_validation},
    {"broker_qos1",            flb_test_broker_qos1},
    {"broker_qos0",            flb_test_broker_qos0},
    {"broker_fixed_client_id", flb_test_broker_fixed_client_id},
    {"broker_no_keepalive",    flb_test_broker_no_keepalive},
    {NULL, NULL}
};
