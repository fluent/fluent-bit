/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <monkey/mk_lib.h>
#include <mk_core/mk_unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#define API_ADDR   "127.0.0.1"
#define API_PORT   "9080"

/* Main context set as global so the signal handler can use it */
mk_ctx_t *ctx;

void cb_worker(void *data)
{
    mk_info("[api test] test worker callback; data=%p", data);
}


void cb_sp_test_task_detail(mk_request_t *request, void *data)
{
    (void) data;

    mk_http_status(request, 200);
    mk_http_send(request, "CB_SP_TEST_TASK_DETAIL", strlen("CB_SP_TEST_TASK_DETAIL"), NULL);
    mk_http_done(request);
}

void cb_sp_test_task_main(mk_request_t *request, void *data)
{
    (void) data;

    mk_http_status(request, 200);
    mk_http_send(request, "CB_SP_TEST_TASK_MAIN", strlen("CB_SP_TEST_TASK_MAIN"), NULL);
    mk_http_done(request);
}

void cb_main(mk_request_t *request, void *data)
{
    int i;
    (void) data;

    mk_http_status(request, 200);

    for (i = 0; i < 20; i++) {
        mk_http_send(request, "first", 5, NULL);
        mk_http_send(request, "second", 6, NULL);
        mk_http_send(request, "third", 5, NULL);
    }
    mk_http_done(request);
}

void cb_test_chunks(mk_request_t *request, void *data)
{
    int i = 0;
    int len;
    char tmp[32];
    (void) data;

    mk_http_status(request, 200);
    mk_http_header(request, "X-Monkey", 8, "OK", 2);

    for (i = 0; i < 4; i++) {
        len = snprintf(tmp, sizeof(tmp) -1, "test-chunk %6i\n ", i);
        mk_http_send(request, tmp, len, NULL);
    }
    mk_http_done(request);
}

void cb_test_big_chunk(mk_request_t *request, void *data)
{
    size_t chunk_size = 1024000000;
    char *chunk;
    (void) data;

    mk_http_status(request, 200);
    mk_http_header(request, "X-Monkey", 8, "OK", 2);

    chunk = calloc(1, chunk_size);
    mk_http_send(request, chunk, chunk_size, NULL);
    free(chunk);
    mk_http_done(request);
}


static void signal_handler(int signal)
{
    write(STDERR_FILENO, "[engine] caught signal\n", 23);

    switch (signal) {
    case SIGTERM:
    case SIGINT:
        mk_stop(ctx);
        mk_destroy(ctx);
        _exit(EXIT_SUCCESS);
    default:
        break;
    }
}

static void signal_init()
{
    signal(SIGINT,  &signal_handler);
    signal(SIGTERM, &signal_handler);
}

static void cb_queue_message(mk_mq_t *queue, void *data, size_t size, void *ctx)
{
    size_t i;
    char *buf;
    (void) ctx;
    (void) queue;

    printf("=== cb queue message === \n");
    printf(" => %zu bytes\n", size);
    printf(" => ");

    buf = data;
    for (i = 0; i < size; i++) {
        printf("%c", buf[i]);
    }
    printf("\n\n");
}


int main()
{
    int i = 0;
    int len;
    int vid;
    int qid;
    char msg[800000];

    signal_init();

    ctx = mk_create();
    if (!ctx) {
        return -1;
    }

    /* Create a message queue and a callback for each message */
    qid = mk_mq_create(ctx, "/data", cb_queue_message, NULL);

    mk_config_set(ctx,
                  "Listen", API_PORT,
                  //"Timeout", "1",
                  NULL);

    vid = mk_vhost_create(ctx, NULL);
    mk_vhost_set(ctx, vid,
                 "Name", "monotop",
                 NULL);

    mk_vhost_handler(ctx, vid, "/api/v1/stream_processor/task/[A-Za-z_][0-9A-Za-z_\\-]*",
                     cb_sp_test_task_detail, NULL);

    mk_vhost_handler(ctx, vid, "/api/v1/stream_processor/task",
                     cb_sp_test_task_main, NULL);

    mk_vhost_handler(ctx, vid, "/test_chunks", cb_test_chunks, NULL);
    mk_vhost_handler(ctx, vid, "/test_big_chunk", cb_test_big_chunk, NULL);
    mk_vhost_handler(ctx, vid, "/", cb_main, NULL);


    mk_worker_callback(ctx,
                       cb_worker,
                       ctx);

    mk_info("Service: http://%s:%s/test_chunks",  API_ADDR, API_PORT);
    mk_start(ctx);

    for (i = 0; i < 5; i++) {
        len = snprintf(msg, sizeof(msg) - 1, "[...] message ID: %i\n", i);
        mk_mq_send(ctx, qid, &msg, len);
    }

    sleep(3600);

    mk_stop(ctx);
    mk_destroy(ctx);


    return 0;
}
