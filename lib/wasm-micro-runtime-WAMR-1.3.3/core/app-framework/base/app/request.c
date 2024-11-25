/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "bi-inc/attr_container.h"
#include "wa-inc/request.h"
#include "wa-inc/timer_wasm_app.h"
#include "bi-inc/shared_utils.h"
#include "wasm_app.h"
#include "req_resp_api.h"
#include "timer_api.h"

#define TRANSACTION_TIMEOUT_MS 5000

typedef enum { Reg_Event, Reg_Request } reg_type_t;

typedef struct _res_register {
    struct _res_register *next;
    const char *url;
    reg_type_t reg_type;
    void (*request_handler)(request_t *);
} res_register_t;

typedef struct transaction {
    struct transaction *next;
    int mid;
    unsigned int time; /* start time */
    response_handler_f handler;
    void *user_data;
} transaction_t;

static res_register_t *g_resources = NULL;

static transaction_t *g_transactions = NULL;

static user_timer_t g_trans_timer = NULL;

static transaction_t *
transaction_find(int mid)
{
    transaction_t *t = g_transactions;

    while (t) {
        if (t->mid == mid)
            return t;
        t = t->next;
    }

    return NULL;
}

/*
 * new transaction is added to the tail of the list, so the list
 * is sorted by expiry time naturally.
 */
static void
transaction_add(transaction_t *trans)
{
    transaction_t *t;

    if (g_transactions == NULL) {
        g_transactions = trans;
        return;
    }

    t = g_transactions;
    while (t) {
        if (t->next == NULL) {
            t->next = trans;
            return;
        }
    }
}

static void
transaction_remove(transaction_t *trans)
{
    transaction_t *prev = NULL, *current = g_transactions;

    while (current) {
        if (current == trans) {
            if (prev == NULL) {
                g_transactions = current->next;
                free(current);
                return;
            }
            prev->next = current->next;
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
}

static bool
is_event_type(request_t *req)
{
    return req->action == COAP_EVENT;
}

static bool
register_url_handler(const char *url, request_handler_f request_handler,
                     reg_type_t reg_type)
{
    res_register_t *r = g_resources;

    while (r) {
        if (reg_type == r->reg_type && strcmp(r->url, url) == 0) {
            r->request_handler = request_handler;
            return true;
        }
        r = r->next;
    }

    r = (res_register_t *)malloc(sizeof(res_register_t));
    if (r == NULL)
        return false;

    memset(r, 0, sizeof(*r));

    r->url = strdup(url);
    if (!r->url) {
        free(r);
        return false;
    }

    r->request_handler = request_handler;
    r->reg_type = reg_type;
    r->next = g_resources;
    g_resources = r;

    // tell app mgr to route this url to me
    if (reg_type == Reg_Request)
        wasm_register_resource(url);
    else
        wasm_sub_event(url);

    return true;
}

bool
api_register_resource_handler(const char *url,
                              request_handler_f request_handler)
{
    return register_url_handler(url, request_handler, Reg_Request);
}

static void
transaction_timeout_handler(user_timer_t timer)
{
    transaction_t *cur, *expired = NULL;
    unsigned int elpased_ms, now = wasm_get_sys_tick_ms();

    /*
     * Since he transaction list is sorted by expiry time naturally,
     * we can easily get all expired transactions.
     * */
    cur = g_transactions;
    while (cur) {
        if (now < cur->time)
            elpased_ms = now + (0xFFFFFFFF - cur->time) + 1;
        else
            elpased_ms = now - cur->time;

        if (elpased_ms >= TRANSACTION_TIMEOUT_MS) {
            g_transactions = cur->next;
            cur->next = expired;
            expired = cur;
            cur = g_transactions;
        }
        else {
            break;
        }
    }

    /* call each transaction's handler with response set to NULL */
    cur = expired;
    while (cur) {
        transaction_t *tmp = cur;
        cur->handler(NULL, cur->user_data);
        cur = cur->next;
        free(tmp);
    }

    /*
     * If the transaction list is not empty, restart the timer according
     * to the first transaction. Otherwise, stop the timer.
     */
    if (g_transactions != NULL) {
        unsigned int elpased_ms, ms_to_expiry, now = wasm_get_sys_tick_ms();
        if (now < g_transactions->time) {
            elpased_ms = now + (0xFFFFFFFF - g_transactions->time) + 1;
        }
        else {
            elpased_ms = now - g_transactions->time;
        }
        ms_to_expiry = TRANSACTION_TIMEOUT_MS - elpased_ms;
        api_timer_restart(g_trans_timer, ms_to_expiry);
    }
    else {
        api_timer_cancel(g_trans_timer);
        g_trans_timer = NULL;
    }
}

void
api_send_request(request_t *request, response_handler_f response_handler,
                 void *user_data)
{
    int size;
    char *buffer;
    transaction_t *trans;

    if ((trans = (transaction_t *)malloc(sizeof(transaction_t))) == NULL) {
        printf(
            "send request: allocate memory for request transaction failed!\n");
        return;
    }

    memset(trans, 0, sizeof(transaction_t));
    trans->handler = response_handler;
    trans->mid = request->mid;
    trans->time = wasm_get_sys_tick_ms();
    trans->user_data = user_data;

    if ((buffer = pack_request(request, &size)) == NULL) {
        printf("send request: pack request failed!\n");
        free(trans);
        return;
    }

    transaction_add(trans);

    /* if the trans is the 1st one, start the timer */
    if (trans == g_transactions) {
        /* assert(g_trans_timer == NULL); */
        if (g_trans_timer == NULL) {
            g_trans_timer = api_timer_create(TRANSACTION_TIMEOUT_MS, false,
                                             true, transaction_timeout_handler);
        }
    }

    wasm_post_request(buffer, size);

    free_req_resp_packet(buffer);
}

/*
 *
 *  APIs for the native layers to callback for request/response arrived to this
 * app
 *
 */

void
on_response(char *buffer, int size)
{
    response_t response[1];
    transaction_t *trans;

    if (NULL == unpack_response(buffer, size, response)) {
        printf("unpack response failed\n");
        return;
    }

    if ((trans = transaction_find(response->mid)) == NULL) {
        printf("cannot find the transaction\n");
        return;
    }

    /*
     * When the 1st transaction get response:
     * 1. If the 2nd trans exist, restart the timer according to its expiry
     * time;
     * 2. Otherwise, stop the timer since there is no more transactions;
     */
    if (trans == g_transactions) {
        if (trans->next != NULL) {
            unsigned int elpased_ms, ms_to_expiry, now = wasm_get_sys_tick_ms();
            if (now < trans->next->time) {
                elpased_ms = now + (0xFFFFFFFF - trans->next->time) + 1;
            }
            else {
                elpased_ms = now - trans->next->time;
            }
            ms_to_expiry = TRANSACTION_TIMEOUT_MS - elpased_ms;
            api_timer_restart(g_trans_timer, ms_to_expiry);
        }
        else {
            api_timer_cancel(g_trans_timer);
            g_trans_timer = NULL;
        }
    }

    trans->handler(response, trans->user_data);
    transaction_remove(trans);
}

void
on_request(char *buffer, int size)
{
    request_t request[1];
    bool is_event;
    res_register_t *r = g_resources;

    if (NULL == unpack_request(buffer, size, request)) {
        printf("unpack request failed\n");
        return;
    }

    is_event = is_event_type(request);

    while (r) {
        if ((is_event && r->reg_type == Reg_Event)
            || (!is_event && r->reg_type == Reg_Request)) {
            if (check_url_start(request->url, strlen(request->url), r->url)
                > 0) {
                r->request_handler(request);
                return;
            }
        }

        r = r->next;
    }

    printf("on_request: exit. no service handler\n");
}

void
api_response_send(response_t *response)
{
    int size;
    char *buffer = pack_response(response, &size);
    if (buffer == NULL)
        return;

    wasm_response_send(buffer, size);
    free_req_resp_packet(buffer);
}

/// event api

bool
api_publish_event(const char *url, int fmt, void *payload, int payload_len)
{
    int size;
    request_t request[1];
    init_request(request, (char *)url, COAP_EVENT, fmt, payload, payload_len);
    char *buffer = pack_request(request, &size);
    if (buffer == NULL)
        return false;
    wasm_post_request(buffer, size);

    free_req_resp_packet(buffer);

    return true;
}

bool
api_subscribe_event(const char *url, request_handler_f handler)
{
    return register_url_handler(url, handler, Reg_Event);
}
