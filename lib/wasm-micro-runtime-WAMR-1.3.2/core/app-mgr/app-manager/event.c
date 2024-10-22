/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <string.h>

#include "event.h"

#include "app_manager.h"
#include "coap_ext.h"

typedef struct _subscribe {
    struct _subscribe *next;
    uint32 subscriber_id;
} subscribe_t;

typedef struct _event {
    struct _event *next;
    int subscriber_size;
    subscribe_t *subscribers;
    char url[1]; /* event url */
} event_reg_t;

event_reg_t *g_events = NULL;

static bool
find_subscriber(event_reg_t *reg, uint32 id, bool remove_found)
{
    subscribe_t *c = reg->subscribers;
    subscribe_t *prev = NULL;
    while (c) {
        subscribe_t *next = c->next;
        if (c->subscriber_id == id) {
            if (remove_found) {
                if (prev)
                    prev->next = next;
                else
                    reg->subscribers = next;

                APP_MGR_FREE(c);
            }

            return true;
        }
        else {
            prev = c;
            c = next;
        }
    }

    return false;
}

static bool
check_url(const char *url)
{
    if (*url == 0)
        return false;

    return true;
}

bool
am_register_event(const char *url, uint32_t reg_client)
{
    event_reg_t *current = g_events;

    app_manager_printf("am_register_event adding url:(%s)\n", url);

    if (!check_url(url)) {
        app_manager_printf("am_register_event: invaild url:(%s)\n", url);
        return false;
    }
    while (current) {
        if (strcmp(url, current->url) == 0)
            break;
        current = current->next;
    }

    if (current == NULL) {
        if (NULL
            == (current = (event_reg_t *)APP_MGR_MALLOC(
                    offsetof(event_reg_t, url) + strlen(url) + 1))) {
            app_manager_printf("am_register_event: malloc fail\n");
            return false;
        }

        memset(current, 0, sizeof(event_reg_t));
        bh_strcpy_s(current->url, strlen(url) + 1, url);
        current->next = g_events;
        g_events = current;
    }

    if (find_subscriber(current, reg_client, false)) {
        return true;
    }
    else {
        subscribe_t *s = (subscribe_t *)APP_MGR_MALLOC(sizeof(subscribe_t));
        if (s == NULL)
            return false;

        memset(s, 0, sizeof(subscribe_t));
        s->subscriber_id = reg_client;
        s->next = current->subscribers;
        current->subscribers = s;
        app_manager_printf("client: %d registered event (%s)\n", reg_client,
                           url);
    }

    return true;
}

// @url: NULL means the client wants to unregister all its subscribed items
bool
am_unregister_event(const char *url, uint32_t reg_client)
{
    event_reg_t *current = g_events, *pre = NULL;

    while (current != NULL) {
        if (url == NULL || strcmp(current->url, url) == 0) {
            event_reg_t *next = current->next;
            if (find_subscriber(current, reg_client, true)) {
                app_manager_printf("client: %d deregistered event (%s)\n",
                                   reg_client, current->url);
            }

            // remove the registration if no client subscribe it
            if (current->subscribers == NULL) {
                app_manager_printf("unregister for event deleted url:(%s)\n",
                                   current->url);
                if (pre)
                    pre->next = next;
                else
                    g_events = next;
                APP_MGR_FREE(current);
                current = next;
                continue;
            }
        }
        pre = current;
        current = current->next;
    }

    return true;
}

bool
event_handle_event_request(uint8_t code, const char *event_url,
                           uint32_t reg_client)
{
    if (code == COAP_PUT) { /* register */
        return am_register_event(event_url, reg_client);
    }
    else if (code == COAP_DELETE) { /* unregister */
        return am_unregister_event(event_url, reg_client);
    }
    else {
        /* invalid request */
        return false;
    }
}

void
am_publish_event(request_t *event)
{
    bh_assert(event->action == COAP_EVENT);

    event_reg_t *current = g_events;
    while (current) {
        if (0 == strcmp(event->url, current->url)) {
            subscribe_t *c = current->subscribers;
            while (c) {
                if (c->subscriber_id == ID_HOST) {
                    send_request_to_host(event);
                }
                else {
                    module_request_handler(event,
                                           (void *)(uintptr_t)c->subscriber_id);
                }
                c = c->next;
            }

            return;
        }

        current = current->next;
    }
}

bool
event_is_registered(const char *event_url)
{
    event_reg_t *current = g_events;

    while (current != NULL) {
        if (strcmp(current->url, event_url) == 0) {
            return true;
        }
        current = current->next;
    }

    return false;
}
