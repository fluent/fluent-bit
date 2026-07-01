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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_callback.h>
#include <fluent-bit/flb_http_client.h>

/*
 * Callbacks
 * =========
 */
static void debug_cb_request_headers(char *name, void *p1, void *p2)
{
    struct flb_http_client *c = p1;

    flb_idebug("[http] request headers\n%s", c->header_buf);
}

static void debug_cb_request_payload(char *name, void *p1, void *p2)
{
    unsigned char *ptr;
    struct flb_http_client *c = p1;

    if (c->body_len > 3) {
        ptr = (unsigned char *) c->body_buf;
        if (ptr[0] == 0x1F && ptr[1] == 0x8B && ptr[2] == 0x08) {
            flb_idebug("[http] request payload (%d bytes)\n[GZIP binary content...]",
                       c->body_len);
        }
        else {
            flb_idebug("[http] request payload (%d bytes)\n%s",
                       c->body_len, c->body_buf);
        }
    }
    else {
        flb_idebug("[http] request payload (%d bytes)\n%s",
                   c->body_len, c->body_buf);
    }
}

static void debug_cb_response_headers(char *name, void *p1, void *p2)
{
    char tmp;
    struct flb_http_client *c = p1;

    /*
     * Just to make easier debugging, we are going to put a NULL byte after
     * the header break (\r\n\r\n) and then restore it.
     */
    tmp = *c->resp.headers_end;
    *c->resp.headers_end = '\0';

    flb_idebug("[http] response headers\n%s", c->resp.data);
    *c->resp.headers_end = tmp;
}

static void debug_cb_response_payload(char *name, void *p1, void *p2)
{
    struct flb_http_client *c = p1;

    flb_idebug("[http] response payload (%lu bytes)\n%s",
               c->resp.payload_size, c->resp.payload);
}

struct flb_http_callback {
    char *name;
    void (*func)(char *, void *, void *);
};

/*
 * Callbacks Table
 */
struct flb_http_callback http_callbacks[] = {
    /* request */
    { "_debug.http.request_headers", debug_cb_request_headers },
    { "_debug.http.request_payload", debug_cb_request_payload },

    /* response */
    { "_debug.http.response_headers", debug_cb_response_headers },
    { "_debug.http.response_payload", debug_cb_response_payload },
    { 0 }
};

/*
 * Exported Functions
 * ==================
 */
/* Determinate if a http.debug property is valid or not */
int flb_http_client_debug_property_is_valid(char *key, char *val)
{
    int i;
    int ret;
    int len;
    struct flb_http_callback *cb;

    if (!key) {
        flb_error("[http_client] given property is invalid");
        return -1;
    }

    if (!val) {
        flb_error("[http_client] property '%s' don't have a valid value",
                  key);
        return -1;
    }

    len = (sizeof(http_callbacks) / sizeof(struct flb_http_callback)) - 1;
    for (i = 0; i < len ; i++) {
        cb = &http_callbacks[i];
        if (strcasecmp(key, cb->name) == 0) {
            ret = flb_utils_bool(val);
            if (ret == -1) {
                return FLB_FALSE;
            }
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}


int flb_http_client_debug_cb(struct flb_http_client *c, char *name)
{
    int ret;

    ret = flb_callback_do(c->cb_ctx, name, c, NULL);
    return ret;
}

/*
 * This function helps to setup 'HTTP' debugging mode on a HTTP client context
 * using the list of configuration properties set by the instance. On this
 * specific case we don't pass the 'plugin instance' reference since it can be
 * an input, filter or output, we try to make this agnostic.
 */
int flb_http_client_debug_setup(struct flb_callback *cb_ctx,
                                struct mk_list *props)
{
    int i;
    int len;
    int ret;
    const char *tmp;
    struct flb_http_callback *cb;

    /*
     * Iterate table of callbacks, if the callbacks are not pre-defined in the
     * context (this might happen when callbacks are overrided by a library
     * caller), set the default ones.
     */
    len = (sizeof(http_callbacks) / sizeof(struct flb_http_callback)) - 1;
    for (i = 0; i < len ; i++) {
        cb = &http_callbacks[i];

        /* Check if the debug property has been enabled */
        tmp = flb_config_prop_get(cb->name, props);
        if (!tmp) {
            continue;
        }

        ret = flb_utils_bool(tmp);
        if (ret == FLB_FALSE) {
            continue;
        }

        ret = flb_callback_exists(cb_ctx, cb->name);
        if (ret == FLB_FALSE) {
            /* Set default callback */
            ret = flb_callback_set(cb_ctx, cb->name, cb->func);
            if (ret == -1) {
                flb_error("[http_client] error setting up default "
                          "callback '%s'", cb->name);
            }
        }
    }
    return 0;
}
