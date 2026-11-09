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
#include <fluent-bit/flb_time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include "flb_tests_runtime.h"

/*
 * These tests exercise the in_aegisbpf plugin without a real AegisBPF agent:
 * a dummy Unix-domain socket server plays the agent, serving a scripted event
 * stream (a handshake line the plugin skips, valid single-object OCSF events,
 * and malformed lines that must be rejected). We then assert, through the lib
 * output callback, that exactly the valid events are forwarded as records.
 */

/* Scripted stream the dummy agent serves once the plugin connects. The first
 * line is the streaming ack (skipped by the plugin); [1,2,3] and "scalar" are
 * not single JSON objects and must be dropped; the three objects are records. */
#define AEGIS_ACK        "{\"ok\":true}\n"
#define AEGIS_EVENT_1    "{\"class_uid\":1001,\"activity_name\":\"Open\"}\n"
#define AEGIS_BAD_ARRAY  "[1,2,3]\n"
#define AEGIS_BAD_SCALAR "\"scalar\"\n"
#define AEGIS_EVENT_2    "{\"class_uid\":4001,\"activity_name\":\"Connect\"}\n"
#define AEGIS_EVENT_3    "{\"class_uid\":1001,\"disposition\":\"Blocked\"}\n"

#define AEGIS_STREAM \
    AEGIS_ACK AEGIS_EVENT_1 AEGIS_BAD_ARRAY AEGIS_BAD_SCALAR \
    AEGIS_EVENT_2 AEGIS_EVENT_3

#define AEGIS_EXPECTED_RECORDS 3

struct test_ctx {
    flb_ctx_t *flb;
    int i_ffd;
    int o_ffd;
};

/* dummy-agent server state */
struct dummy_agent {
    char path[108];
    int listen_fd;
    pthread_t thread;
    pthread_mutex_t lock;
    int stop;             /* protected by lock; signals the server to exit */
};

static int agent_should_stop(struct dummy_agent *agent)
{
    int s;
    pthread_mutex_lock(&agent->lock);
    s = agent->stop;
    pthread_mutex_unlock(&agent->lock);
    return s;
}

/* result accounting, shared with the output callback */
pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;
int num_output = 0;

static int get_output_num()
{
    int ret;
    pthread_mutex_lock(&result_mutex);
    ret = num_output;
    pthread_mutex_unlock(&result_mutex);
    return ret;
}

static void set_output_num(int num)
{
    pthread_mutex_lock(&result_mutex);
    num_output = num;
    pthread_mutex_unlock(&result_mutex);
}

/* Each forwarded record must be a JSON object carrying a class_uid; arrays and
 * scalars from the stream must never reach here. */
static int cb_check_record(void *record, size_t size, void *data)
{
    char *result = (char *) record;

    set_output_num(get_output_num() + 1);

    if (!TEST_CHECK(strstr(result, "\"class_uid\"") != NULL)) {
        TEST_MSG("record missing class_uid: %s", result);
    }
    if (!TEST_CHECK(result[0] == '[')) {
        /* lib/json output wraps each record as [timestamp, {...}] */
        TEST_MSG("unexpected record framing: %s", result);
    }

    flb_free(record);
    return 0;
}

/* Serve the scripted stream to the first client, then keep the connection open
 * until the test tears the server down. accept() is driven through poll() with
 * a stop flag so the thread always exits (and pthread_join never stalls) even
 * if the plugin never connects. */
static void *dummy_agent_run(void *arg)
{
    struct dummy_agent *agent = (struct dummy_agent *) arg;
    struct pollfd pfd;
    struct timespec ts;
    char reqbuf[64];
    const char *p = AEGIS_STREAM;
    size_t remaining = sizeof(AEGIS_STREAM) - 1;
    ssize_t w;
    ssize_t r;
    int fd = -1;
    int ret;

    ts.tv_sec = 0;
    ts.tv_nsec = 20 * 1000 * 1000; /* 20ms */

    /* Wait for the plugin to connect without blocking accept() indefinitely. */
    pfd.fd = agent->listen_fd;
    pfd.events = POLLIN;
    while (!agent_should_stop(agent)) {
        ret = poll(&pfd, 1, 100);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            fd = accept(agent->listen_fd, NULL, NULL);
            break;
        }
    }
    if (fd < 0) {
        return NULL;
    }

    /* The plugin turns the connection into an event stream with a
     * "GET /events\n" request; validate it before serving the stream. Read it
     * through poll() so a client that connects but never sends can't wedge the
     * thread (and hence pthread_join) at teardown. */
    pfd.fd = fd;
    pfd.events = POLLIN;
    r = 0;
    while (!agent_should_stop(agent)) {
        ret = poll(&pfd, 1, 100);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            r = read(fd, reqbuf, sizeof(reqbuf) - 1);
            break;
        }
    }
    if (r > 0) {
        reqbuf[r] = '\0';
        if (!TEST_CHECK(strstr(reqbuf, "GET /events") != NULL)) {
            TEST_MSG("unexpected request from plugin: %s", reqbuf);
        }
    }

    while (remaining > 0) {
        w = write(fd, p, remaining);
        if (w <= 0) {
            break;
        }
        p += w;
        remaining -= (size_t) w;
    }

    /* Hold the connection open so the plugin drains what we sent rather than
     * seeing an immediate EOF/reconnect; exit once teardown sets the stop flag. */
    while (!agent_should_stop(agent)) {
        nanosleep(&ts, NULL);
    }

    close(fd);
    return NULL;
}

static int dummy_agent_start(struct dummy_agent *agent)
{
    struct sockaddr_un addr;
    int fd;

    agent->stop = 0;
    pthread_mutex_init(&agent->lock, NULL);

    /* Unique, short socket path under the runtime temp dir. */
    snprintf(agent->path, sizeof(agent->path),
             "/tmp/flb-aegisbpf-test-%d.sock", (int) getpid());
    unlink(agent->path);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (!TEST_CHECK(fd >= 0)) {
        pthread_mutex_destroy(&agent->lock);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, agent->path, sizeof(addr.sun_path) - 1);

    if (!TEST_CHECK(bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == 0)) {
        close(fd);
        pthread_mutex_destroy(&agent->lock);
        return -1;
    }
    if (!TEST_CHECK(listen(fd, 1) == 0)) {
        close(fd);
        unlink(agent->path);
        pthread_mutex_destroy(&agent->lock);
        return -1;
    }

    agent->listen_fd = fd;
    if (!TEST_CHECK(pthread_create(&agent->thread, NULL,
                                   dummy_agent_run, agent) == 0)) {
        close(fd);
        agent->listen_fd = -1;
        unlink(agent->path);
        pthread_mutex_destroy(&agent->lock);
        return -1;
    }

    return 0;
}

static void dummy_agent_stop(struct dummy_agent *agent)
{
    /* Signal the server thread, wait for it to exit, then close the listener.
     * Closing only after the join keeps listen_fd valid for the poll() loop and
     * avoids a data race on it. */
    pthread_mutex_lock(&agent->lock);
    agent->stop = 1;
    pthread_mutex_unlock(&agent->lock);

    pthread_join(agent->thread, NULL);

    if (agent->listen_fd >= 0) {
        close(agent->listen_fd);
        agent->listen_fd = -1;
    }
    unlink(agent->path);
    pthread_mutex_destroy(&agent->lock);
}

static struct test_ctx *test_ctx_create(struct dummy_agent *agent,
                                         struct flb_lib_out_cb *data)
{
    struct test_ctx *ctx;
    int ret;

    ctx = flb_malloc(sizeof(struct test_ctx));
    if (!TEST_CHECK(ctx != NULL)) {
        return NULL;
    }

    ctx->flb = flb_create();
    TEST_CHECK(ctx->flb != NULL);

    flb_service_set(ctx->flb,
                    "Flush", "0.200000000",
                    "Grace", "1",
                    "Log_Level", "error",
                    NULL);

    ctx->i_ffd = flb_input(ctx->flb, (char *) "aegisbpf", NULL);
    TEST_CHECK(ctx->i_ffd >= 0);
    ret = flb_input_set(ctx->flb, ctx->i_ffd,
                        "socket_path", agent->path,
                        "reconnect_sec", "1",
                        NULL);
    TEST_CHECK(ret == 0);

    ctx->o_ffd = flb_output(ctx->flb, (char *) "lib", (void *) data);
    TEST_CHECK(ctx->o_ffd >= 0);
    ret = flb_output_set(ctx->flb, ctx->o_ffd,
                         "match", "*",
                         "format", "json",
                         NULL);
    TEST_CHECK(ret == 0);

    return ctx;
}

static void test_ctx_destroy(struct test_ctx *ctx)
{
    TEST_CHECK(ctx != NULL);
    flb_stop(ctx->flb);
    flb_destroy(ctx->flb);
    flb_free(ctx);
}

/* End-to-end: the plugin connects to the dummy agent, skips the handshake,
 * forwards the three valid OCSF objects, and drops the array and scalar. */
static void flb_test_aegisbpf_stream()
{
    struct dummy_agent agent;
    struct test_ctx *ctx;
    struct flb_lib_out_cb cb;
    int ret;
    int i;

    set_output_num(0);
    memset(&agent, 0, sizeof(agent));
    agent.listen_fd = -1;

    if (!TEST_CHECK(dummy_agent_start(&agent) == 0)) {
        return;
    }

    cb.cb = cb_check_record;
    cb.data = NULL;

    ctx = test_ctx_create(&agent, &cb);
    if (!TEST_CHECK(ctx != NULL)) {
        dummy_agent_stop(&agent);
        return;
    }

    ret = flb_start(ctx->flb);
    TEST_CHECK(ret == 0);

    /* Wait (bounded) for the three records to be forwarded. */
    for (i = 0; i < 50; i++) {
        if (get_output_num() >= AEGIS_EXPECTED_RECORDS) {
            break;
        }
        flb_time_msleep(100);
    }

    if (!TEST_CHECK(get_output_num() == AEGIS_EXPECTED_RECORDS)) {
        TEST_MSG("expected %d records, got %d",
                 AEGIS_EXPECTED_RECORDS, get_output_num());
    }

    test_ctx_destroy(ctx);
    dummy_agent_stop(&agent);
}

TEST_LIST = {
    {"stream", flb_test_aegisbpf_stream},
    {NULL, NULL}
};
