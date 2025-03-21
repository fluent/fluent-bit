/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "native_interface.h"
#include "app_manager.h"
#include "app_manager_export.h"
#include "bi-inc/shared_utils.h"
#include "bi-inc/attr_container.h"
#include "coap_ext.h"

typedef struct _app_res_register {
    struct _app_res_register *next;
    char *url;
    void (*request_handler)(request_t *, void *);
    uint32 register_id;
} app_res_register_t;

static app_res_register_t *g_resources = NULL;

void
module_request_handler(request_t *request, void *user_data)
{
    unsigned int mod_id = (unsigned int)(uintptr_t)user_data;
    bh_message_t msg;
    module_data *m_data;
    request_t *req;

    /* Check module name */
    m_data = module_data_list_lookup_id(mod_id);
    if (!m_data) {
        return;
    }

    if (m_data->wd_timer.is_interrupting) {
        return;
    }

    req = clone_request(request);
    if (!req) {
        return;
    }

    /* Set queue message and send to applet's queue */
    msg = bh_new_msg(RESTFUL_REQUEST, req, sizeof(*req), request_cleaner);
    if (!msg) {
        request_cleaner(req);
        return;
    }

    if (!bh_post_msg2(m_data->queue, msg)) {
        return;
    }

    app_manager_printf("Send request to app %s success.\n",
                       m_data->module_name);
}

void
targeted_app_request_handler(request_t *request, void *unused)
{
    char applet_name[128] = { 0 };
    int offset;
    char *url = request->url;
    module_data *m_data;

    offset = check_url_start(request->url, strlen(request->url), "/app/");

    if (offset <= 0) {
        return;
    }

    strncpy(applet_name, request->url + offset, sizeof(applet_name) - 1);
    char *p = strchr(applet_name, '/');
    if (p) {
        *p = 0;
    }
    else
        return;
    app_manager_printf("Send request to applet: %s\n", applet_name);

    request->url = p + 1;

    /* Check module name */
    m_data = module_data_list_lookup(applet_name);
    if (!m_data) {
        SEND_ERR_RESPONSE(request->mid,
                          "Send request to applet failed: invalid applet name");
        goto end;
    }

    module_request_handler(request, (void *)(uintptr_t)m_data->id);
end:
    request->url = url;
}

void
am_send_response(response_t *response)
{
    module_data *m_data;

    // if the receiver is not any of modules, just forward it to the host
    m_data = module_data_list_lookup_id(response->reciever);
    if (!m_data) {
        send_response_to_host(response);
    }
    else {
        response_t *resp_for_send = clone_response(response);
        if (!resp_for_send) {
            return;
        }

        bh_message_t msg = bh_new_msg(RESTFUL_RESPONSE, resp_for_send,
                                      sizeof(*resp_for_send), response_cleaner);
        if (!msg) {
            response_cleaner(resp_for_send);
            return;
        }

        if (!bh_post_msg2(m_data->queue, msg)) {
            return;
        }
    }
}

void *
am_dispatch_request(request_t *request)
{
    app_res_register_t *r = g_resources;

    while (r) {
        if (check_url_start(request->url, strlen(request->url), r->url) > 0) {
            r->request_handler(request, (void *)(uintptr_t)r->register_id);
            return r;
        }
        r = r->next;
    }
    return NULL;
}

bool
am_register_resource(const char *url,
                     void (*request_handler)(request_t *, void *),
                     uint32 register_id)
{
    app_res_register_t *r = g_resources;
    int register_num = 0;

    while (r) {
        if (strcmp(r->url, url) == 0) {
            return false;
        }

        if (r->register_id == register_id)
            register_num++;

        r = r->next;
    }

    if (strlen(url) > RESOUCE_EVENT_URL_LEN_MAX)
        return false;

    if (register_num >= RESOURCE_REGISTRATION_NUM_MAX)
        return false;

    r = (app_res_register_t *)APP_MGR_MALLOC(sizeof(app_res_register_t));
    if (r == NULL)
        return false;

    memset(r, 0, sizeof(*r));
    r->url = bh_strdup(url);
    if (r->url == NULL) {
        APP_MGR_FREE(r);
        return false;
    }

    r->request_handler = request_handler;
    r->next = g_resources;
    r->register_id = register_id;
    g_resources = r;

    return true;
}

void
am_cleanup_registeration(uint32 register_id)
{
    app_res_register_t *r = g_resources;
    app_res_register_t *prev = NULL;

    while (r) {
        app_res_register_t *next = r->next;

        if (register_id == r->register_id) {
            if (prev)
                prev->next = next;
            else
                g_resources = next;

            APP_MGR_FREE(r->url);
            APP_MGR_FREE(r);
        }
        else
            /* if r is freed, should not change prev. Only set prev to r
             when r isn't freed. */
            prev = r;

        r = next;
    }
}
