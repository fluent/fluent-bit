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

#include <monkey/mk_lib.h>
#include <monkey/monkey.h>

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

    ctx = mk_mem_malloc(sizeof(mk_ctx_t));
    if (!ctx) {
        return NULL;
    }

    ctx->config = mk_server_init();
    return ctx;
}

int mk_start(mk_ctx_t *ctx)
{
    (void) ctx;

    mk_server_setup();
    mk_server_loop();

    return 0;
}

int mk_config_set_property(struct mk_server_config *config, char *k, char *v)
{
    int b;
    int ret;
    int num;
    unsigned long len;

    if (config_eq(k, "Listen") == 0) {
        ret = mk_config_listen_parse(v);
        if (ret != 0) {
            return -1;
        }
    }
    else if (config_eq(k, "Workers") == 0) {
        num = atoi(v);
        if (num <= 0) {
            config->workers = sysconf(_SC_NPROCESSORS_ONLN);
        }
        else {
            config->workers = num;
        }
    }
    else if (config_eq(k, "Timeout") == 0) {
        num = atoi(v);
        if (num <= 0) {
            return -1;
        }
        config->timeout = num;
    }
    else if (config_eq(k, "KeepAlive") == 0) {
        b = bool_val(v);
        if (b == -1) {
            return -1;
        }
        config->keep_alive = b;
    }
    else if (config_eq(k, "MaxKeepAliveRequest") == 0) {
        num = atoi(v);
        if (num <= 0) {
            return -1;
        }
        config->max_keep_alive_request = num;
    }
    else if (config_eq(k, "KeepAliveTimeout") == 0) {
        num = atoi(v);
        if (num <= 0) {
            return -1;
        }
        config->keep_alive_timeout = num;
    }
    else if (config_eq(k, "UserDir") == 0) {
        config->conf_user_pub = mk_string_dup(v);
    }
    else if (config_eq(k, "IndexFile") == 0) {
        config->index_files = mk_string_split_line(v);
        if (!config->index_files) {
            return -1;
        }
    }
    else if (config_eq(k, "HideVersion") == 0) {
        b = bool_val(v);
        if (b == -1) {
            return -1;
        }
        config->hideversion = b;
    }
    else if (config_eq(k, "Resume") == 0) {
        b = bool_val(v);
        if (b == -1) {
            return -1;
        }
        config->resume = b;
    }
    else if (config_eq(k, "MaxRequestSize") == 0) {
        num = atoi(v);
        if (num <= 0) {
            return -1;
        }
        config->max_request_size = num;
    }
    else if (config_eq(k, "SymLink") == 0) {
        b = bool_val(v);
        if (b == -1) {
            return -1;
        }
        config->symlink = b;
    }
    else if (config_eq(k, "DefaultMimeType") == 0) {
        mk_string_build(&mk_config->default_mimetype, &len, "%s\r\n", v);
    }
    else if (config_eq(k, "FDT") == 0) {
        b = bool_val(v);
        if (b == -1) {
            return -1;
        }
        config->fdt = b;
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

        ret = mk_config_set_property(ctx->config, key, value);
        if (ret != 0) {
            va_end(va);
            return -1;
        }
    }

    va_end(va);
    return 0;
}


mk_vhost_t *mk_vhost_create(mk_ctx_t *ctx, char *name)
{
    struct host *h;
    struct host_alias *halias;

    /* Virtual host */
    h = mk_mem_malloc_z(sizeof(struct host));
    if (!h) {
        return NULL;
    }
    mk_list_init(&h->error_pages);
    mk_list_init(&h->server_names);
    mk_list_init(&h->handlers);

    /* Host alias */
    halias = mk_mem_malloc_z(sizeof(struct host_alias));
    if (!halias) {
        mk_mem_free(h);
        return NULL;
    }

    /* Host name */
    if (!name) {
        halias->name = mk_string_dup("127.0.0.1");
    }
    else {
        halias->name = mk_string_dup(name);
    }
    mk_list_add(&halias->_head, &h->server_names);
    mk_list_add(&h->_head, &ctx->config->hosts);

    return h;
}

static int mk_vhost_set_property(mk_vhost_t *vh, char *k, char *v)
{
    struct host_alias *ha;

    if (config_eq(k, "Name") == 0) {
        ha = mk_mem_malloc(sizeof(struct host_alias));
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

int mk_vhost_set(mk_vhost_t *vh, ...)
{
    int ret;
    char *key;
    char *value;
    va_list va;

    va_start(va, vh);

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

int mk_vhost_handler(mk_vhost_t *vh, char *regex,
                     void (*cb)(mk_session_t *, mk_request_t *))
{
    struct mk_host_handler *handler;
    (void) vh;
    void (*_cb) (struct mk_http_session *, struct mk_http_request *) = \
        (void (*) (struct mk_http_session *, struct mk_http_request *)) cb;

    handler = mk_vhost_handler_match(regex, _cb);
    if (!handler) {
        return -1;
    }
    mk_list_add(&handler->_head, &vh->handlers);

    return 0;
}

int mk_http_status(mk_request_t *req, int status)
{
    req->headers.status = status;
    return 0;
}

/* Enqueue some data for the body response */
int mk_http_send(mk_request_t *req, char *buf, size_t len,
                 void (*cb_finish)(mk_request_t *))
{
    int ret;

    ret = mk_stream_in_raw(&req->stream, NULL,
                           buf, len, NULL, cb_finish);
    if (ret == 0) {
        /* Update content length */
        req->headers.content_length += len;
    }

    return ret;
}
