/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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

#define _GNU_SOURCE
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#include <monkey/mk_lib.h>
#include <monkey/monkey.h>
#include <monkey/mk_stream.h>
#include <monkey/mk_thread.h>

#define config_eq(a, b) strcasecmp(a, b)

static inline int bool_val(char *v)
{
    if (strcasecmp(v, "On") == 0 || strcasecmp(v, "Yes") == 0) {
        return MK_TRUE;
    }
    else if (strcasecmp(v, "Off") == 0 || strcasecmp(v, "No") == 0) {
        return MK_FALSE;
    }

    return -1;
}

mk_ctx_t *mk_create()
{
    mk_ctx_t *ctx;

    ctx = mk_mem_alloc(sizeof(mk_ctx_t));
    if (!ctx) {
        return NULL;
    }

    /* Create Monkey server instance */
    ctx->server = mk_server_create();
    return ctx;
}

int mk_destroy(mk_ctx_t *ctx)
{
    mk_mem_free(ctx);

    return 0;
}

static inline int mk_lib_yield(mk_request_t *req)
{
    int ret;
    struct mk_thread *th;
    struct mk_channel *channel;
    struct mk_sched_worker *sched;

    sched = mk_sched_get_thread_conf();
    if (!sched) {
        return -1;
    }

    th = pthread_getspecific(mk_thread_key);
    channel = req->session->channel;

    channel->thread = th;

    ret = mk_event_add(sched->loop,
                       channel->fd,
                       MK_EVENT_THREAD,
                       MK_EVENT_WRITE, channel->event);
    if (ret == -1) {
        return -1;
    }

    /* Just wait */
    mk_thread_yield(th);

    if (channel->event->status & MK_EVENT_REGISTERED) {
        /* We got a notification, remove the event registered
        ret = mk_event_add(sched->loop,
                           channel->fd,
                           MK_EVENT_CONNECTION,
                           MK_EVENT_READ, channel->event);
                           mk_thread_yield(th);
        */

        ret = mk_event_del(sched->loop, channel->event);
    }

    return 0;
}

static void mk_lib_worker(void *data)
{
    int fd;
    int bytes;
    uint64_t val;
    struct mk_server *server;
    struct mk_event *event;

    mk_ctx_t *ctx = data;
    server = ctx->server;

    /* Start the service */
    mk_server_setup(server);
    mk_server_loop(server);

    /*
     * Give a second to the parent context to avoid consume an event
     * we should not read at the moment (SIGNAL_START).
     */
    sleep(1);

    /* Wait for events */
    mk_event_wait(server->lib_evl);
    mk_event_foreach(event, server->lib_evl) {
        fd = event->fd;
        bytes = read(fd, &val, sizeof(uint64_t));
        if (bytes <= 0) {
            return;
        }

        if (val == MK_SERVER_SIGNAL_STOP) {
            break;
        }
    }

    mk_event_loop_destroy(server->lib_evl);
    mk_exit_all(server);
    pthread_kill(pthread_self(), 0);

    return;
}

int mk_start(mk_ctx_t *ctx)
{
    int fd;
    int bytes;
    int ret;
    uint64_t val;
    pthread_t tid;
    struct mk_event *event;
    struct mk_server *server;

    ret = mk_utils_worker_spawn(mk_lib_worker, ctx, &tid);
    if (ret == -1) {
        return -1;
    }
    ctx->worker_tid = tid;

    /* Wait for the started signal so we can return to the caller */
    server = ctx->server;
    mk_event_wait(server->lib_evl);
    mk_event_foreach(event, server->lib_evl) {
        fd = event->fd;
        bytes = read(fd, &val, sizeof(uint64_t));
        if (bytes <= 0) {
            return -1;
        }

        if (val == MK_SERVER_SIGNAL_START) {
            return 0;
        }
        else {
            mk_stop(ctx);
            return -1;
        }
    }

    return 0;
}

int mk_stop(mk_ctx_t *ctx)
{
    int n;
    uint64_t val;
    struct mk_server *server = ctx->server;

    val = MK_SERVER_SIGNAL_STOP;
    n = write(server->lib_ch_manager[1], &val, sizeof(val));
    if (n <= 0) {
        perror("write");
        return -1;
    }

    /* Wait for the child thread to exit */
    pthread_join(ctx->worker_tid, NULL);
    return 0;
}

/*
 * Instruct Monkey core to invoke a callback function inside each worker
 * started by the scheduler.
 */
int mk_worker_callback(mk_ctx_t *ctx,
                       void (*cb_func) (void *),
                       void *data)
{
    return mk_sched_worker_cb_add(ctx->server, cb_func, data);
}

int mk_config_set_property(struct mk_server *server, char *k, char *v)
{
    int b;
    int ret;
    int num;
    unsigned long len;

    if (config_eq(k, "Listen") == 0) {
        ret = mk_config_listen_parse(v, server);
        if (ret != 0) {
            return -1;
        }
    }
    else if (config_eq(k, "Workers") == 0) {
        num = atoi(v);
        if (num <= 0) {
            server->workers = sysconf(_SC_NPROCESSORS_ONLN);
        }
        else {
            server->workers = num;
        }
    }
    else if (config_eq(k, "Timeout") == 0) {
        num = atoi(v);
        if (num <= 0) {
            return -1;
        }
        server->timeout = num;
    }
    else if (config_eq(k, "KeepAlive") == 0) {
        b = bool_val(v);
        if (b == -1) {
            return -1;
        }
        server->keep_alive = b;
    }
    else if (config_eq(k, "MaxKeepAliveRequest") == 0) {
        num = atoi(v);
        if (num <= 0) {
            return -1;
        }
        server->max_keep_alive_request = num;
    }
    else if (config_eq(k, "KeepAliveTimeout") == 0) {
        num = atoi(v);
        if (num <= 0) {
            return -1;
        }
        server->keep_alive_timeout = num;
    }
    else if (config_eq(k, "UserDir") == 0) {
        server->conf_user_pub = mk_string_dup(v);
    }
    else if (config_eq(k, "IndexFile") == 0) {
        server->index_files = mk_string_split_line(v);
        if (!server->index_files) {
            return -1;
        }
    }
    else if (config_eq(k, "HideVersion") == 0) {
        b = bool_val(v);
        if (b == -1) {
            return -1;
        }
        server->hideversion = b;
    }
    else if (config_eq(k, "Resume") == 0) {
        b = bool_val(v);
        if (b == -1) {
            return -1;
        }
        server->resume = b;
    }
    else if (config_eq(k, "MaxRequestSize") == 0) {
        num = atoi(v);
        if (num <= 0) {
            return -1;
        }
        server->max_request_size = num;
    }
    else if (config_eq(k, "SymLink") == 0) {
        b = bool_val(v);
        if (b == -1) {
            return -1;
        }
        server->symlink = b;
    }
    else if (config_eq(k, "DefaultMimeType") == 0) {
        mk_string_build(&server->mimetype_default_str, &len, "%s\r\n", v);
    }
    else if (config_eq(k, "FDT") == 0) {
        b = bool_val(v);
        if (b == -1) {
            return -1;
        }
        server->fdt = b;
    }

    return 0;
}

int mk_config_set(mk_ctx_t *ctx, ...)
{
    int ret;
    char *key;
    char *value;
    va_list va;

    va_start(va, ctx);

    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        if (!value) {
            /* Wrong parameter */
            return -1;
        }

        ret = mk_config_set_property(ctx->server, key, value);
        if (ret != 0) {
            va_end(va);
            return -1;
        }
    }

    va_end(va);
    return 0;
}

/* Given a vhost id, return the vhost context */
static struct mk_vhost *mk_vhost_lookup(mk_ctx_t *ctx, int id)
{
    struct mk_vhost *host;
    struct mk_list *head;

    mk_list_foreach(head, &ctx->server->hosts) {
        host = mk_list_entry(head, struct mk_vhost, _head);
        if (host->id == id) {
            return host;
        }
    }

    return NULL;
}

int mk_vhost_create(mk_ctx_t *ctx, char *name)
{
    struct mk_vhost *h;
    struct mk_vhost_alias *halias;

    /* Virtual host */
    h = mk_mem_alloc_z(sizeof(struct mk_vhost));
    if (!h) {
        return -1;
    }

    /* Assign a virtual host id, we just set based on list size */
    h->id = mk_list_size(&ctx->server->hosts);
    mk_list_init(&h->error_pages);
    mk_list_init(&h->server_names);
    mk_list_init(&h->handlers);

    /* Host alias */
    halias = mk_mem_alloc_z(sizeof(struct mk_vhost_alias));
    if (!halias) {
        mk_mem_free(h);
        return -1;
    }

    /* Host name */
    if (!name) {
        halias->name = mk_string_dup("127.0.0.1");
    }
    else {
        halias->name = mk_string_dup(name);
    }
    mk_list_add(&halias->_head, &h->server_names);
    mk_list_add(&h->_head, &ctx->server->hosts);

    /* Return the host id, that number is enough for further operations */
    return h->id;
}

static int mk_vhost_set_property(struct mk_vhost *vh, char *k, char *v)
{
    struct mk_vhost_alias *ha;

    if (config_eq(k, "Name") == 0) {
        ha = mk_mem_alloc(sizeof(struct mk_vhost_alias));
        if (!ha) {
            return -1;
        }
        ha->name = mk_string_dup(v);
        ha->len  = strlen(v);
        mk_list_add(&ha->_head, &vh->server_names);
    }
    else if (config_eq(k, "DocumentRoot") == 0) {
        vh->documentroot.data = mk_string_dup(v);
        vh->documentroot.len  = strlen(v);
    }

    return 0;
}

int mk_vhost_set(mk_ctx_t *ctx, int vid, ...)
{
    int ret;
    char *key;
    char *value;
    va_list va;
    struct mk_vhost *vh;

    /* Lookup the virtual host */
    vh = mk_vhost_lookup(ctx, vid);
    if (!vh) {
        return -1;
    }

    va_start(va, vid);

    while ((key = va_arg(va, char *))) {
        value = va_arg(va, char *);
        if (!value) {
            /* Wrong parameter */
            return -1;
        }

        ret = mk_vhost_set_property(vh, key, value);
        if (ret != 0) {
            va_end(va);
            return -1;
        }
    }

    va_end(va);
    return 0;
}

int mk_vhost_handler(mk_ctx_t *ctx, int vid, char *regex,
                     void (*cb)(mk_request_t *, void *), void *data)
{
    struct mk_vhost *vh;
    struct mk_vhost_handler *handler;
    void (*_cb) (struct mk_http_request *, void *);

    /* Lookup the virtual host */
    vh = mk_vhost_lookup(ctx, vid);
    if (!vh) {
        return -1;
    }

    _cb = cb;
    handler = mk_vhost_handler_match(regex, _cb, data);
    if (!handler) {
        return -1;
    }
    mk_list_add(&handler->_head, &vh->handlers);

    return 0;
}

/* Flush streams data associated to a request in question */
int mk_http_flush(mk_request_t *req)
{
    int ret;
    size_t out_bytes = 0;

    ret = mk_channel_stream_write(&req->stream, &out_bytes);
    return ret;
}

int mk_http_status(mk_request_t *req, int status)
{
    req->headers.status = status;
    return 0;
}

/* Append a response header */
int mk_http_header(mk_request_t *req,
                   char *key, int key_len,
                   char *val, int val_len)
{
    int pos;
    int len;
    char *buf;
    struct response_headers *h;

    h = &req->headers;
    if (!h->_extra_rows) {
        h->_extra_rows = mk_iov_create(MK_PLUGIN_HEADER_EXTRA_ROWS * 2, 0);
        if (!h->_extra_rows) {
            return -1;
        }
    }

    len = key_len + val_len + 4;
    buf = mk_mem_alloc(len);
    if (!buf) {
        /* we don't free extra_rows as it's released later */
        return -1;
    }

    /* Compose the buffer */
    memcpy(buf, key, key_len);
    pos = key_len;
    buf[pos++] = ':';
    buf[pos++] = ' ';
    memcpy(buf + pos, val, val_len);
    pos += val_len;
    buf[pos++] = '\r';
    buf[pos++] = '\n';

    /* Add the new buffer */
    mk_iov_add(h->_extra_rows, buf, pos, MK_TRUE);

    return 0;
}

static inline int chunk_header(long num, char *out)
{
    int i = 1;
    int j, c;
    int remainder;
    int quotient;
    char tmp[32];
    char hex[] = "0123456789ABCDEF";

    if (num == 0) {
        out[0] = '0';
        out[1] = '\r';
        out[2] = '\n';
        out[3] = '\r';
        out[4] = '\n';
        out[5] = '\0';
        return 5;
    }

    quotient = num;
    while (quotient != 0) {
        remainder = quotient % 16;
        tmp[i++] = hex[remainder];
        quotient = quotient / 16;
    }

    c = 0;
    for (j = i -1 ; j > 0; j--, c++) {
        out[c] = tmp[j];
    }

    out[c++] = '\r';
    out[c++] = '\n';
    out[c] = '\0';

    return c;
}

static void free_chunk_header(struct mk_stream_input *input)
{
    mk_mem_free(input->buffer);
    input->buffer = NULL;
}

/* Enqueue some data for the body response */
int mk_http_send(mk_request_t *req, char *buf, size_t len,
                 void (*cb_finish)(mk_request_t *))
{
    int chunk_len;
    int ret;
    char *tmp;
    char chunk_pre[32];
    (void) cb_finish;

    if (req->session->channel->status != MK_CHANNEL_OK) {
        return -1;
    }

    if (req->headers.status == -1) {
        /* Cannot append data if the status have not been set */
        mk_err("HTTP: set the response status first");
        return -1;
    }

    /* Chunk encoding prefix */
    if (req->protocol == MK_HTTP_PROTOCOL_11) {
        chunk_len = chunk_header(len, chunk_pre);
        tmp = mk_string_dup(chunk_pre);
        if (!tmp) {
            return -1;
        }
        ret = mk_stream_in_raw(&req->stream, NULL,
                               tmp, chunk_len, NULL, free_chunk_header);
        if (ret != 0) {
            return -1;
        }
    }

    /* Append raw data */
    if (len > 0) {
        ret = mk_stream_in_raw(&req->stream, NULL,
                               buf, len, NULL, NULL);
        if (ret == 0) {
            /* Update count of bytes */
            req->stream_size += len;
        }
    }

    if (req->protocol == MK_HTTP_PROTOCOL_11 && len > 0) {
        ret = mk_stream_in_raw(&req->stream, NULL,
                               "\r\n", 2, NULL, NULL);
    }

    /*
     * Let's keep it simple for now: if the headers have not been sent, do it
     * now and then send the body content just queued.
     */
    if (req->headers.sent == MK_FALSE) {
        /* Force chunked-transfer encoding */
        if (req->protocol == MK_HTTP_PROTOCOL_11) {
            req->headers.transfer_encoding = MK_HEADER_TE_TYPE_CHUNKED;
        }
        else {
            req->headers.content_length = -1;
        }
        mk_header_prepare(req->session, req, req->session->server);
    }

    /* Flush channel data */
    ret = mk_http_flush(req);

    /*
     * Flush have been done, before to return our original caller, we want to yield
     * and give some execution time to the event loop to avoid possible blocking
     * since the caller might be using this mk_http_send() in a loop.
     */
    mk_lib_yield(req);
    return ret;
}

int mk_http_done(mk_request_t *req)
{
    if (req->session->channel->status != MK_CHANNEL_OK) {
        return -1;
    }
    /*

    struct mk_channel *channel;
    struct mk_event *event;

    channel = req->session->channel;
    event = channel->event;

    printf("event type => ");
    switch (event->type) {
    case MK_EVENT_NOTIFICATION:
        printf("notification");
        break;
    case MK_EVENT_LISTENER:
        printf("listener");
        break;
    case MK_EVENT_CONNECTION:
        printf("connection");
        break;
    case MK_EVENT_CUSTOM:
        printf("custom");
        break;
    case MK_EVENT_THREAD:
        printf("thread");
        break;
    default:
        printf("OTHER: %i", event->type);
    };

    printf(", status => ");
    if (event->status == MK_EVENT_NONE) {
        printf("MK_EVENT_NONE");
    }
    else if (event->status == MK_EVENT_REGISTERED) {
        printf("MK_EVENT_REGISTERED");
    }

    printf(", mask =>");
    if (event->mask & MK_EVENT_EMPTY) {
        printf(" MK_EVENT_EMPTY");
    }
    if (event->mask & MK_EVENT_READ) {
        printf(" MK_EVENT_READ");
    }
    if (event->mask & MK_EVENT_WRITE) {
        printf(" MK_EVENT_WRITE");
    }
    if (event->mask & MK_EVENT_SLEEP) {
        printf(" MK_EVENT_SLEEP");
    }
    if (event->mask & MK_EVENT_CLOSE) {
        printf(" MK_EVENT_CLOSE");
    }
    if (event->mask & MK_EVENT_IDLE) {
        printf(" MK_EVENT_IDLE");
    }
    printf("\n");
    fflush(stdout);
    */

    if (req->headers.transfer_encoding == MK_HEADER_TE_TYPE_CHUNKED) {
        /* Append end-of-chunk bytes */
        mk_http_send(req, NULL, 0, NULL);
    }

    return 0;
}
