/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

#include <monkey/mk_lib.h>
#include <monkey/monkey.h>

#include "mk_tests.h"

#define TEST_NOT_RUN 0
#define TEST_SUCCESS 1
#define TEST_FAIL_START 2
#define TEST_FAIL_CB 3
#define TEST_FAIL_STOP 4
#define TEST_TIMEOUT 5

#define WORKER_SIGNAL_COMPLETE 0
#define TIMEOUT_SIGNAL_COMPLETE 1

typedef int (*test_cb_t) (mk_ctx_t*);

struct test_worker_ctx {
    mk_ctx_t* srv_ctx;
    test_cb_t test_cb;
    int8_t result;
    int evl_w_fd;
};

struct test_timeout_ctx {
    int timeout_sec;
    int evl_w_fd;
};

struct test_worker_ctx *test_worker_ctx_init(mk_ctx_t *srv_ctx,
                                             test_cb_t test_cb,
                                             int evl_w_fd)
{
    struct test_worker_ctx *ctx = mk_mem_alloc_z(sizeof(struct test_worker_ctx));
    ctx->srv_ctx = srv_ctx;
    ctx->test_cb = test_cb;
    ctx->result = TEST_NOT_RUN;
    ctx->evl_w_fd = evl_w_fd;
    return ctx;
}

void test_worker_ctx_free(struct test_worker_ctx *ctx)
{
    mk_mem_free(ctx);
}

struct test_timeout_ctx *test_timeout_ctx_init(int timeout_sec,
                                               int evl_w_fd)
{
    struct test_timeout_ctx *ctx = mk_mem_alloc_z(sizeof(struct test_timeout_ctx));
    ctx->timeout_sec = timeout_sec;
    ctx->evl_w_fd = evl_w_fd;
    return ctx;
}

void test_timeout_ctx_free(struct test_timeout_ctx *ctx)
{
    mk_mem_free(ctx);
}

int fd_write_signal(int fd, uint64_t val) 
{
#ifdef _WIN32
    return send(fd, &val, sizeof(uint64_t), 0);
#else
    return write(fd, &val, sizeof(uint64_t));
#endif
}

int fd_read_signal(int fd, uint64_t *val) 
{
#ifdef _WIN32
    return recv(fd, val, sizeof(uint64_t), MSG_WAITALL);
#else
    return read(fd, val, sizeof(uint64_t));
#endif
}


static void server_test_worker(void *data) 
{
    int start, stop;
    int cb_success;
    struct test_worker_ctx *ctx = data;
    mk_ctx_t *srv = ctx->srv_ctx;

    start = mk_start(srv);
    if (start == -1) {
        ctx->result = TEST_FAIL_START;
        fd_write_signal(ctx->evl_w_fd, WORKER_SIGNAL_COMPLETE);
        pthread_exit(NULL);
        return;
    }
    
    cb_success = ctx->test_cb(srv);

    stop = mk_stop(srv);
    if (stop == -1) {
        ctx->result = TEST_FAIL_STOP;
        fd_write_signal(ctx->evl_w_fd, WORKER_SIGNAL_COMPLETE);
        pthread_exit(NULL);
        return;
    }

    if (cb_success == -1) {
        ctx->result = TEST_FAIL_CB;
        fd_write_signal(ctx->evl_w_fd, WORKER_SIGNAL_COMPLETE);
        pthread_exit(NULL);
        return;
    }

    ctx->result = TEST_SUCCESS; 
    fd_write_signal(ctx->evl_w_fd, WORKER_SIGNAL_COMPLETE);
    pthread_exit(NULL);
    return;
}

static void timeout_worker(void *data) 
{
    struct test_timeout_ctx *ctx = data;
    sleep(ctx->timeout_sec);
    fd_write_signal(ctx->evl_w_fd, TIMEOUT_SIGNAL_COMPLETE);
    pthread_exit(NULL);
    return;
}

uint8_t run_server_test(mk_ctx_t *srv, int timeout_sec, test_cb_t cb) 
{
    int ret, bytes, fd;
    pthread_t timeout_tid, test_tid;
    int8_t timeout, result;
    struct test_timeout_ctx *timeout_ctx;
    struct test_worker_ctx *test_ctx;
    struct mk_event_loop *complete_evl;
    int complete_ch[2];
    struct mk_event complete_ch_event;
    struct mk_event* worker_event;
    uint64_t worker_signal;

    complete_evl = mk_event_loop_create(1);
    memset(&complete_ch_event, 0, sizeof(struct mk_event));
    ret = mk_event_channel_create(complete_evl,
                                  &complete_ch[0],
                                  &complete_ch[1],
                                  &complete_ch_event);

    timeout_ctx = test_timeout_ctx_init(timeout_sec, complete_ch[1]);
    test_ctx = test_worker_ctx_init(srv, cb, complete_ch[1]);
    ret = mk_utils_worker_spawn(timeout_worker, timeout_ctx, &timeout_tid);
    if (ret == -1) {
        mk_event_loop_destroy(complete_evl);
        test_timeout_ctx_free(timeout_ctx);
        test_worker_ctx_free(test_ctx);
        return TEST_NOT_RUN;
    }
    ret = mk_utils_worker_spawn(server_test_worker, test_ctx, &test_tid);
    if (ret == -1) {
        mk_event_loop_destroy(complete_evl);
        test_timeout_ctx_free(timeout_ctx);
        test_worker_ctx_free(test_ctx);
        return TEST_NOT_RUN;
    }

    timeout = MK_FALSE;
    mk_event_wait(complete_evl);
    mk_event_foreach(worker_event, complete_evl) {
        fd = worker_event->fd;
        bytes = fd_read_signal(fd, &worker_signal);

        if (bytes <= 0) {
            mk_event_loop_destroy(complete_evl);
            test_timeout_ctx_free(timeout_ctx);
            test_worker_ctx_free(test_ctx);
            pthread_cancel(test_tid);
            pthread_cancel(timeout_tid);
            pthread_join(timeout_tid, NULL);
            pthread_join(test_tid, NULL);
            return TEST_NOT_RUN;
        }

        if (worker_signal != WORKER_SIGNAL_COMPLETE) {
            timeout = MK_TRUE;
        }
        break;
    }

    mk_event_loop_destroy(complete_evl);

    result = test_ctx->result;
    if (timeout == MK_TRUE) {
        result = TEST_TIMEOUT;
        pthread_cancel(test_tid);
    } else {
        pthread_cancel(timeout_tid);
    }

    pthread_join(timeout_tid, NULL);
    pthread_join(test_tid, NULL);

    test_timeout_ctx_free(timeout_ctx);
    test_worker_ctx_free(test_ctx);

    return result;
}

int test_cb_sleep() 
{
    sleep(1);
    return 0;
}

void test_server_start_stop_single_worker(void) 
{
    mk_ctx_t *srv = mk_create();
    mk_config_set(
        srv,
        "Listen", "127.0.0.1:27456",
        "Workers", "1",
        NULL
    );
    uint8_t result = run_server_test(srv, 5, test_cb_sleep); 
    mk_destroy(srv);
    TEST_CHECK(result == TEST_SUCCESS);
}

void test_server_start_stop_more_workers(void) 
{
    mk_ctx_t *srv = mk_create();
    mk_config_set(
        srv,
        "Listen", "127.0.0.1:27456",
        "Workers", "8",
        NULL
    );
    uint8_t result = run_server_test(srv, 5, test_cb_sleep); 
    mk_destroy(srv);
    TEST_CHECK(result == TEST_SUCCESS);
}

void test_server_start_stop_force_fair_balancing(void) 
{
    mk_ctx_t *srv = mk_create();
    mk_config_set(
        srv,
        "Listen", "127.0.0.1:27456",
        "Workers", "1",
        NULL
    );
    srv->server->scheduler_mode = MK_SCHEDULER_FAIR_BALANCING;
    uint8_t result = run_server_test(srv, 5, test_cb_sleep); 
    mk_destroy(srv);
    TEST_CHECK(result == TEST_SUCCESS);
}

TEST_LIST = {
    { 
        "server_start_stop", 
        test_server_start_stop_single_worker 
    },
    { 
        "server_start_stop_multi_worker", 
        test_server_start_stop_more_workers 
    },
    { 
        "server_start_stop_force_fair_balancing", 
        test_server_start_stop_force_fair_balancing 
    },
    {NULL, NULL}
};
