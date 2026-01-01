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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_http_server.h>
#include "prom.h"
#include "prom_http.h"

pthread_key_t ph_metrics_key;

/* Return the newest storage metrics buffer */
static struct prom_http_buf *metrics_get_latest()
{
    struct prom_http_buf *buf;
    struct mk_list *metrics_list;

    metrics_list = pthread_getspecific(ph_metrics_key);
    if (!metrics_list) {
        return NULL;
    }

    if (mk_list_size(metrics_list) == 0) {
        return NULL;
    }

    buf = mk_list_entry_last(metrics_list, struct prom_http_buf, _head);
    return buf;
}

/* Delete unused metrics, note that we only care about the latest node */
static int cleanup_metrics()
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *metrics_list;
    struct prom_http_buf *last;
    struct prom_http_buf *entry;

    metrics_list = pthread_getspecific(ph_metrics_key);
    if (!metrics_list) {
        return -1;
    }

    last = metrics_get_latest();
    if (!last) {
        return -1;
    }

    mk_list_foreach_safe(head, tmp, metrics_list) {
        entry = mk_list_entry(head, struct prom_http_buf, _head);
        if (entry != last && entry->users == 0) {
            mk_list_del(&entry->_head);
            flb_free(entry->buf_data);
            flb_free(entry);
            c++;
        }
    }

    return c;
}

/* destructor callback */
static void destruct_metrics(void *data)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct mk_list *metrics_list = (struct mk_list*)data;
    struct prom_http_buf *entry;

    if (!metrics_list) {
        return;
    }

    mk_list_foreach_safe(head, tmp, metrics_list) {
        entry = mk_list_entry(head, struct prom_http_buf, _head);
        mk_list_del(&entry->_head);
        flb_free(entry->buf_data);
        flb_free(entry);
    }

    flb_free(metrics_list);
}

/*
 * Callback invoked every time a new payload of Metrics is received from
 * Fluent Bit engine through Message Queue channel.
 *
 * This function runs in a Monkey HTTP thread worker and it purpose is
 * to take the metrics data and store it locally for every thread, so then
 * it can be available on 'cb_metrics()' to serve it as a response.
 */
static void cb_mq_metrics(mk_mq_t *queue, void *data, size_t size)
{
    struct prom_http_buf *buf;
    struct mk_list *metrics_list = NULL;

    metrics_list = pthread_getspecific(ph_metrics_key);
    if (!metrics_list) {
        metrics_list = flb_malloc(sizeof(struct mk_list));
        if (!metrics_list) {
            flb_errno();
            return;
        }
        mk_list_init(metrics_list);
        pthread_setspecific(ph_metrics_key, metrics_list);
    }

    /* FIXME: convert data ? */
    buf = flb_malloc(sizeof(struct prom_http_buf));
    if (!buf) {
        flb_errno();
        return;
    }
    buf->users = 0;
    buf->buf_data = flb_malloc(size);
    if (!buf->buf_data) {
        flb_errno();
        flb_free(buf);
        return;
    }
    memcpy(buf->buf_data, data, size);
    buf->buf_size = size;

    mk_list_add(&buf->_head, metrics_list);
    cleanup_metrics();
}

/* Create message queue to receive Metrics payload from the engine */
static int http_server_mq_create(struct prom_http *ph)
{
    int ret;

    pthread_key_create(&ph_metrics_key, destruct_metrics);

    ret = mk_mq_create(ph->ctx, "/metrics", cb_mq_metrics, NULL);
    if (ret == -1) {
        return -1;
    }
    ph->qid_metrics = ret;
    return 0;
}

/* HTTP endpoint: /metrics */
static void cb_metrics(mk_request_t *request, void *data)
{
    struct prom_http_buf *buf;
    (void) data;

    buf = metrics_get_latest();
    if (!buf) {
        mk_http_status(request, 404);
        mk_http_done(request);
        return;
    }

    buf->users++;

    mk_http_status(request, 200);
    flb_hs_add_content_type_to_req(request, FLB_HS_CONTENT_TYPE_PROMETHEUS);
    mk_http_send(request, buf->buf_data, buf->buf_size, NULL);
    mk_http_done(request);

    buf->users--;
}

/* HTTP endpoint: / (root) */
static void cb_root(mk_request_t *request, void *data)
{
    (void) data;

    mk_http_status(request, 200);
    mk_http_send(request, "Fluent Bit Prometheus Exporter\n", 31, NULL);
    mk_http_done(request);
}

struct prom_http *prom_http_server_create(struct prom_exporter *ctx,
                                          const char *listen,
                                          int tcp_port,
                                          struct flb_config *config)
{
    int ret;
    int vid;
    char tmp[32];
    struct prom_http *ph;

    ph = flb_malloc(sizeof(struct prom_http));
    if (!ph) {
        flb_errno();
        return NULL;
    }
    ph->config = config;

    /* HTTP Server context */
    ph->ctx = mk_create();
    if (!ph->ctx) {
        flb_free(ph);
        return NULL;
    }

    /* Compose listen address */
    snprintf(tmp, sizeof(tmp) -1, "%s:%d", listen, tcp_port);
    mk_config_set(ph->ctx,
                  "Listen", tmp,
                  "Workers", "1",
                  NULL);

    /* Virtual host */
    vid = mk_vhost_create(ph->ctx, NULL);
    ph->vid = vid;

    /* Set HTTP URI callbacks */
    mk_vhost_handler(ph->ctx, vid, "/metrics", cb_metrics, NULL);
    mk_vhost_handler(ph->ctx, vid, "/", cb_root, NULL);

    /* Create a Message Queue to push 'metrics' to HTTP workers */
    ret = http_server_mq_create(ph);
    if (ret == -1) {
        mk_destroy(ph->ctx);
        flb_free(ph);
        return NULL;
    }

    return ph;
}

void prom_http_server_destroy(struct prom_http *ph)
{
    if (ph) {
        /* TODO: release mk_vhost */
        if (ph->ctx) {
            mk_destroy(ph->ctx);
        }
        flb_free(ph);
    }
}

int prom_http_server_start(struct prom_http *ph)
{
    return mk_start(ph->ctx);
}

int prom_http_server_stop(struct prom_http *ph)
{
    return mk_stop(ph->ctx);
}

int prom_http_server_mq_push_metrics(struct prom_http *ph,
                                     void *data, size_t size)
{
    return mk_mq_send(ph->ctx, ph->qid_metrics, data, size);
}
