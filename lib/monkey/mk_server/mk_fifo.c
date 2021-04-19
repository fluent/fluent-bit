/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#include <monkey/mk_fifo.h>
#include <monkey/mk_scheduler.h>

#ifdef _WIN32
#include <event.h>
#endif

static struct mk_fifo_worker *mk_fifo_worker_create(struct mk_fifo *ctx,
                                                    void *data)
{
    int id;
    int ret;
    struct mk_fifo_worker *fw;

    /* Get an ID */
    id = mk_list_size(&ctx->workers);

    fw = mk_mem_alloc(sizeof(struct mk_fifo_worker));
    if (!fw) {
        perror("malloc");
        return NULL;
    }
    MK_EVENT_NEW(&fw->event);

    fw->worker_id = id;
    fw->data = data;
    fw->fifo = ctx;

    fw->buf_data = mk_mem_alloc(MK_FIFO_BUF_SIZE);
    if (!fw->buf_data) {
        perror("malloc");
        mk_mem_free(fw);
        return NULL;
    }
    fw->buf_len = 0;
    fw->buf_size = MK_FIFO_BUF_SIZE;

#ifdef _WIN32
    ret = evutil_socketpair(AF_INET, SOCK_STREAM, 0, fw->channel);
    if (ret == -1) {
        perror("socketpair");
        mk_mem_free(fw);
        return NULL;
    }
#else
    ret = pipe(fw->channel);
    if (ret == -1) {
        perror("pipe");
        mk_mem_free(fw);
        return NULL;
    }
#endif

    mk_list_add(&fw->_head, &ctx->workers);
    return fw;
}

/*
 * Function used as a callback triggered by mk_worker_callback() or
 * through a mk_sched_worker_cb_add(). It purpose is to prepare the
 * channels on the final worker thread so it can consume pushed
 * messages.
 */
void mk_fifo_worker_setup(void *data)
{
    struct mk_fifo_worker *mw = NULL;
    struct mk_fifo *ctx = data;

    pthread_mutex_lock(&ctx->mutex_init);

    mw = mk_fifo_worker_create(ctx, data);
    if (!mw) {
        mk_err("[msg] error configuring msg-worker context ");
        pthread_mutex_unlock(&ctx->mutex_init);
        return;
    }

    /* Make the current worker context available */
    pthread_setspecific(*ctx->key, mw);
    pthread_mutex_unlock(&ctx->mutex_init);
}

struct mk_fifo *mk_fifo_create(pthread_key_t *key, void *data)
{
    struct mk_fifo *ctx;

    ctx = mk_mem_alloc(sizeof(struct mk_fifo));
    if (!ctx) {
        perror("malloc");
        return NULL;
    }
    ctx->data = data;

    /* Lists */
    mk_list_init(&ctx->queues);
    mk_list_init(&ctx->workers);


    /* Pthread specifics */
    ctx->key = key;
    pthread_key_create(ctx->key, NULL);
    pthread_mutex_init(&ctx->mutex_init, NULL);

    return ctx;
}

int mk_fifo_queue_create(struct mk_fifo *ctx, char *name,
                         void (*cb)(struct mk_fifo_queue *, void *,
                                    size_t, void *),
                         void *data)

{
    int id = -1;
    int len;
    struct mk_list *head;
    struct mk_fifo_queue *q;

    /* Get ID for the new queue */
    if (mk_list_is_empty(&ctx->queues) == 0) {
        id = 0;
    }
    else {
        q = mk_list_entry_last(&ctx->queues, struct mk_fifo_queue, _head);
        id = q->id + 1;
    }

    /* queue name might need to be truncated if is too long */
    len = strlen(name);
    if (len > (int) sizeof(name) - 1) {
        len = sizeof(name) - 1;
    }

    /* Validate that name is not a duplicated */
    mk_list_foreach(head, &ctx->queues) {
        q = mk_list_entry(head, struct mk_fifo_queue, _head);
        if (strlen(q->name) != (unsigned int) len) {
            continue;
        }

        if (strncmp(q->name, name, len) == 0) {
            return -1;
        }
    }

    /* Allocate and register queue */
    q = mk_mem_alloc(sizeof(struct mk_fifo_queue));
    if (!q) {
        perror("malloc");
        return -1;
    }
    q->id = id;
    q->cb_message = cb;
    q->data = data;

    strncpy(q->name, name, len);
    q->name[len] = '\0';
    mk_list_add(&q->_head, &ctx->queues);

    return id;
}

struct mk_fifo_queue *mk_fifo_queue_get(struct mk_fifo *ctx, int id)
{
    struct mk_list *head;
    struct mk_fifo_queue *q = NULL;

    mk_list_foreach(head, &ctx->queues) {
        q = mk_list_entry(head, struct mk_fifo_queue, _head);
        if (q->id == id) {
            return q;
        }
    }

    return NULL;
}

int mk_fifo_queue_destroy(struct mk_fifo *ctx, struct mk_fifo_queue *q)
{
    (void) ctx;

    mk_list_del(&q->_head);
    mk_mem_free(q);
    return 0;
}

int mk_fifo_queue_id_destroy(struct mk_fifo *ctx, int id)
{
    struct mk_fifo_queue *q;

    q = mk_fifo_queue_get(ctx, id);
    if (!q) {
        return -1;
    }

    mk_fifo_queue_destroy(ctx, q);
    return 0;
}

static int mk_fifo_queue_destroy_all(struct mk_fifo *ctx)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_fifo_queue *q;

    mk_list_foreach_safe(head, tmp, &ctx->queues) {
        q = mk_list_entry(head, struct mk_fifo_queue, _head);
        mk_fifo_queue_destroy(ctx, q);
        c++;
    }

    return c;
}

static int mk_fifo_worker_destroy_all(struct mk_fifo *ctx)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_fifo_worker *fw;

    mk_list_foreach_safe(head, tmp, &ctx->workers) {
        fw = mk_list_entry(head, struct mk_fifo_worker, _head);
        close(fw->channel[0]);
        close(fw->channel[1]);
        mk_list_del(&fw->_head);
        mk_mem_free(fw->buf_data);
        mk_mem_free(fw);
        c++;
    }

    return c;
}

static int msg_write(int fd, void *buf, size_t count)
{
    ssize_t bytes;
    size_t total = 0;

    do {
#ifdef _WIN32
        bytes = send(fd, (uint8_t *)buf + total, count - total, 0);
#else
        bytes = write(fd, (uint8_t *)buf + total, count - total);
#endif
        if (bytes == -1) {
            if (errno == EAGAIN) {
                /*
                 * This could happen, since this function goal is not to
                 * return until all data have been read, just sleep a little
                 * bit (0.05 seconds)
                 */

#ifdef _WIN32
                Sleep(5);
#else
                usleep(50000);
#endif
                continue;
            }
        }
        else if (bytes == 0) {
            /* Broken pipe ? */
            perror("write");
            return -1;
        }
        total += bytes;

    } while (total < count);

    return total;
}

/*
 * Push a message into a queue: this function runs from the parent thread
 * so it needs to write the message to every thread pipe channel.
 */
int mk_fifo_send(struct mk_fifo *ctx, int id, void *data, size_t size)
{
    int ret;
    struct mk_list *head;
    struct mk_fifo_msg msg;
    struct mk_fifo_queue *q;
    struct mk_fifo_worker *fw;

    /* Validate queue ID */
    q = mk_fifo_queue_get(ctx, id);
    if (!q) {
        return -1;
    }

    pthread_mutex_lock(&ctx->mutex_init);

    mk_list_foreach(head, &ctx->workers) {
        fw = mk_list_entry(head, struct mk_fifo_worker, _head);

        msg.length = size;
        msg.flags = 0;
        msg.queue_id = (uint16_t) id;

        ret = msg_write(fw->channel[1], &msg, sizeof(struct mk_fifo_msg));
        if (ret == -1) {
            pthread_mutex_unlock(&ctx->mutex_init);
            perror("write");
            fprintf(stderr, "[msg] error writing message header\n");
            return -1;
        }

        ret = msg_write(fw->channel[1], data, size);
        if (ret == -1) {
            pthread_mutex_unlock(&ctx->mutex_init);
            perror("write");
            fprintf(stderr, "[msg] error writing message body\n");
            return -1;
        }
    }

    pthread_mutex_unlock(&ctx->mutex_init);

    return 0;
}

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}

static inline int fifo_drop_msg(struct mk_fifo_worker *fw)
{
    size_t drop_bytes;
    struct mk_fifo_msg *msg;

    msg = (struct mk_fifo_msg *) fw->buf_data;
    drop_bytes = (sizeof(struct mk_fifo_msg) + msg->length);
    consume_bytes(fw->buf_data, drop_bytes, fw->buf_len);
    fw->buf_len -= drop_bytes;

    return 0;
}

static inline int fifo_is_msg_ready(struct mk_fifo_worker *fw)
{
    struct mk_fifo_msg *msg;

    msg = (struct mk_fifo_msg *) fw->buf_data;
    if (fw->buf_len >= (msg->length + sizeof(struct mk_fifo_msg))) {
        return MK_TRUE;
    }

    return MK_FALSE;
}

int mk_fifo_worker_read(void *event)
{
    int available;
    char *tmp;
    size_t size;
    ssize_t bytes;
    struct mk_fifo_msg *fm;
    struct mk_fifo_worker *fw;
    struct mk_fifo_queue *fq;

    fw = (struct mk_fifo_worker *) event;

    /* Check available space */
    available = fw->buf_size - fw->buf_len;
    if (available <= 1) {
        size = fw->buf_size + (MK_FIFO_BUF_SIZE / 2);
        tmp = mk_mem_realloc(fw->buf_data, size);
        if (!tmp) {
            perror("realloc");
            return -1;
        }
        fw->buf_data = tmp;
        fw->buf_size = size;
        available = fw->buf_size - fw->buf_len;
    }

    /* Read data from pipe */
#ifdef _WIN32
    bytes = recv(fw->channel[0], fw->buf_data + fw->buf_len, available, 0);
#else
    bytes = read(fw->channel[0], fw->buf_data + fw->buf_len, available);
#endif

    if (bytes == 0) {
        return -1;
    }
    else if (bytes == -1){
        perror("read");
        return -1;
    }

    fw->buf_len += bytes;

    /* Find messages and trigger callbacks */
    while (fw->buf_len > 0) {
        if (fifo_is_msg_ready(fw) == MK_TRUE) {
            /* we got a complete message */
            fm = (struct mk_fifo_msg *) fw->buf_data;
            fq = mk_fifo_queue_get(fw->fifo, fm->queue_id);
            if (!fq) {
                /* Invalid queue */
                fprintf(stderr, "[fifo worker read] invalid queue id %i\n",
                        fm->queue_id);
                fifo_drop_msg(fw);
                continue;
            }

            /* Trigger callback if any */
            if (fq->cb_message) {
                fq->cb_message(fq, fm->data, fm->length, fq->data);
            }
            fifo_drop_msg(fw);
        }
        else {
            /* msg not ready */
            break;
        }
    }

    return 0;
}

int mk_fifo_destroy(struct mk_fifo *ctx)
{
    mk_fifo_queue_destroy_all(ctx);
    mk_fifo_worker_destroy_all(ctx);
    mk_mem_free(ctx);
    return 0;
}
