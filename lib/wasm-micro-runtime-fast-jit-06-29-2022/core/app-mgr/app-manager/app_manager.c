/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "app_manager.h"
#include "app_manager_host.h"
#include "bh_platform.h"
#include "bi-inc/attr_container.h"
#include "event.h"
#include "watchdog.h"
#include "coap_ext.h"

/* Queue of app manager */
static bh_queue *g_app_mgr_queue;
static bool g_app_mgr_started;

void *
get_app_manager_queue()
{
    return g_app_mgr_queue;
}

void
app_manager_post_applets_update_event()
{
    module_data *m_data;
    attr_container_t *attr_cont;
    request_t msg;
    int num = 0, i = 0;
    char *url = "/applets";

    if (!event_is_registered(url))
        return;

    if (!(attr_cont = attr_container_create("All Applets"))) {
        app_manager_printf("Post applets update event failed: "
                           "allocate memory failed.");
        return;
    }

    os_mutex_lock(&module_data_list_lock);

    m_data = module_data_list;
    while (m_data) {
        num++;
        m_data = m_data->next;
    }

    if (!(attr_container_set_int(&attr_cont, "num", num))) {
        app_manager_printf("Post applets update event failed: "
                           "set attr container key failed.");
        goto fail;
    }

    m_data = module_data_list;
    while (m_data) {
        char buf[32];
        i++;
        snprintf(buf, sizeof(buf), "%s%d", "applet", i);
        if (!(attr_container_set_string(&attr_cont, buf,
                                        m_data->module_name))) {
            app_manager_printf("Post applets update event failed: "
                               "set attr applet name key failed.");
            goto fail;
        }
        snprintf(buf, sizeof(buf), "%s%d", "heap", i);
        if (!(attr_container_set_int(&attr_cont, buf, m_data->heap_size))) {
            app_manager_printf("Post applets update event failed: "
                               "set attr heap key failed.");
            goto fail;
        }
        m_data = m_data->next;
    }

    memset(&msg, 0, sizeof(msg));
    msg.url = url;
    msg.action = COAP_EVENT;
    msg.payload = (char *)attr_cont;
    send_request_to_host(&msg);

    app_manager_printf("Post applets update event success!\n");
    attr_container_dump(attr_cont);

fail:
    os_mutex_unlock(&module_data_list_lock);
    attr_container_destroy(attr_cont);
}

static int
get_applets_count()
{
    module_data *m_data;
    int num = 0;

    os_mutex_lock(&module_data_list_lock);

    m_data = module_data_list;
    while (m_data) {
        num++;
        m_data = m_data->next;
    }

    os_mutex_unlock(&module_data_list_lock);

    return num;
}

/* Query fw apps info if name = NULL, otherwise query specify app */
static bool
app_manager_query_applets(request_t *msg, const char *name)
{
    module_data *m_data;
    attr_container_t *attr_cont;
    int num = 0, i = 0, len;
    bool ret = false, found = false;
    response_t response[1] = { 0 };

    attr_cont = attr_container_create("Applets Info");
    if (!attr_cont) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Query Applets failed: allocate memory failed.");
        return false;
    }

    os_mutex_lock(&module_data_list_lock);

    m_data = module_data_list;
    while (m_data) {
        num++;
        m_data = m_data->next;
    }

    if (name == NULL && !(attr_container_set_int(&attr_cont, "num", num))) {
        SEND_ERR_RESPONSE(
            msg->mid, "Query Applets failed: set attr container key failed.");
        goto fail;
    }

    m_data = module_data_list;
    while (m_data) {
        char buf[32];

        if (name == NULL) {
            i++;
            snprintf(buf, sizeof(buf), "%s%d", "applet", i);
            if (!(attr_container_set_string(&attr_cont, buf,
                                            m_data->module_name))) {
                SEND_ERR_RESPONSE(msg->mid, "Query Applets failed: "
                                            "set attr container key failed.");
                goto fail;
            }
            snprintf(buf, sizeof(buf), "%s%d", "heap", i);
            if (!(attr_container_set_int(&attr_cont, buf, m_data->heap_size))) {
                SEND_ERR_RESPONSE(msg->mid,
                                  "Query Applets failed: "
                                  "set attr container heap key failed.");
                goto fail;
            }
        }
        else if (!strcmp(name, m_data->module_name)) {
            found = true;
            if (!(attr_container_set_string(&attr_cont, "name",
                                            m_data->module_name))) {
                SEND_ERR_RESPONSE(msg->mid, "Query Applet failed: "
                                            "set attr container key failed.");
                goto fail;
            }
            if (!(attr_container_set_int(&attr_cont, "heap",
                                         m_data->heap_size))) {
                SEND_ERR_RESPONSE(msg->mid,
                                  "Query Applet failed: "
                                  "set attr container heap key failed.");
                goto fail;
            }
        }

        m_data = m_data->next;
    }

    if (name != NULL && !found) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Query Applet failed: the app is not found.");
        goto fail;
    }

    len = attr_container_get_serialize_length(attr_cont);

    make_response_for_request(msg, response);
    set_response(response, CONTENT_2_05, FMT_ATTR_CONTAINER, (char *)attr_cont,
                 len);
    send_response_to_host(response);

    ret = true;
    app_manager_printf("Query Applets success!\n");
    attr_container_dump(attr_cont);

fail:
    os_mutex_unlock(&module_data_list_lock);
    attr_container_destroy(attr_cont);
    return ret;
}

void
applet_mgt_reqeust_handler(request_t *request, void *unused)
{
    bh_message_t msg;
    /* deep copy, but not use app self heap, but use global heap */
    request_t *req = clone_request(request);

    if (!req)
        return;

    msg = bh_new_msg(RESTFUL_REQUEST, req, sizeof(*req), request_cleaner);
    if (!msg) {
        request_cleaner(req);
        return;
    }

    bh_post_msg2(get_app_manager_queue(), msg);
}

/* return -1 for error */
static int
get_module_type(char *kv_str)
{
    int module_type = -1;
    char type_str[16] = { 0 };

    find_key_value(kv_str, strlen(kv_str), "type", type_str,
                   sizeof(type_str) - 1, '&');

    if (strlen(type_str) == 0)
        module_type = Module_WASM_App;
    else if (strcmp(type_str, "jeff") == 0)
        module_type = Module_Jeff;
    else if (strcmp(type_str, "wasm") == 0)
        module_type = Module_WASM_App;
    else if (strcmp(type_str, "wasmlib") == 0)
        module_type = Module_WASM_Lib;

    return module_type;
}

#define APP_NAME_MAX_LEN 128

/* Queue callback of App Manager */

static void
app_manager_queue_callback(void *message, void *arg)
{
    request_t *request = (request_t *)bh_message_payload((bh_message_t)message);
    int mid = request->mid, module_type, offset;

    (void)arg;

    if ((offset =
             check_url_start(request->url, strlen(request->url), "/applet"))
        > 0) {
        module_type = get_module_type(request->url + offset);

        if (module_type == -1) {
            SEND_ERR_RESPONSE(mid,
                              "Applet Management failed: invalid module type.");
            goto fail;
        }

        /* Install Applet */
        if (request->action == COAP_PUT) {
            if (get_applets_count() >= MAX_APP_INSTALLATIONS) {
                SEND_ERR_RESPONSE(
                    mid,
                    "Install Applet failed: exceed max app installations.");
                goto fail;
            }

            if (!request->payload) {
                SEND_ERR_RESPONSE(mid,
                                  "Install Applet failed: invalid payload.");
                goto fail;
            }
            if (g_module_interfaces[module_type]
                && g_module_interfaces[module_type]->module_install) {
                if (!g_module_interfaces[module_type]->module_install(request))
                    goto fail;
            }
        }
        /* Uninstall Applet */
        else if (request->action == COAP_DELETE) {
            module_type = get_module_type(request->url + offset);
            if (module_type == -1) {
                SEND_ERR_RESPONSE(
                    mid, "Uninstall Applet failed: invalid module type.");
                goto fail;
            }

            if (g_module_interfaces[module_type]
                && g_module_interfaces[module_type]->module_uninstall) {
                if (!g_module_interfaces[module_type]->module_uninstall(
                        request))
                    goto fail;
            }
        }
        /* Query Applets installed */
        else if (request->action == COAP_GET) {
            char name[APP_NAME_MAX_LEN] = { 0 };
            char *properties = request->url + offset;
            find_key_value(properties, strlen(properties), "name", name,
                           sizeof(name) - 1, '&');
            if (strlen(name) > 0)
                app_manager_query_applets(request, name);
            else
                app_manager_query_applets(request, NULL);
        }
        else {
            SEND_ERR_RESPONSE(mid, "Invalid request of applet: invalid action");
        }
    }
    /* Event Register/Unregister */
    else if ((offset = check_url_start(request->url, strlen(request->url),
                                       "/event/"))
             > 0) {
        char url_buf[256] = { 0 };

        strncpy(url_buf, request->url + offset, sizeof(url_buf) - 1);

        if (!event_handle_event_request(request->action, url_buf, ID_HOST)) {
            SEND_ERR_RESPONSE(mid, "Handle event request failed.");
            goto fail;
        }
        send_error_response_to_host(mid, CONTENT_2_05, NULL); /* OK */
    }
    else {
        int i;
        for (i = 0; i < Module_Max; i++) {
            if (g_module_interfaces[i]
                && g_module_interfaces[i]->module_handle_host_url) {
                if (g_module_interfaces[i]->module_handle_host_url(request))
                    break;
            }
        }
    }

fail:
    return;
}

static void
module_interfaces_init()
{
    int i;
    for (i = 0; i < Module_Max; i++) {
        if (g_module_interfaces[i] && g_module_interfaces[i]->module_init)
            g_module_interfaces[i]->module_init();
    }
}

void
app_manager_startup(host_interface *interface)
{
    module_interfaces_init();

    /* Create queue of App Manager */
    g_app_mgr_queue = bh_queue_create();
    if (!g_app_mgr_queue)
        return;

    if (!module_data_list_init())
        goto fail1;

    if (!watchdog_startup())
        goto fail2;

    /* Initialize Host */
    app_manager_host_init(interface);

    am_register_resource("/app/", targeted_app_request_handler, ID_APP_MGR);

    /* /app/ and /event/ are both processed by applet_mgt_reqeust_handler */
    am_register_resource("/applet", applet_mgt_reqeust_handler, ID_APP_MGR);
    am_register_resource("/event/", applet_mgt_reqeust_handler, ID_APP_MGR);

    app_manager_printf("App Manager started.\n");

    g_app_mgr_started = true;

    /* Enter loop run */
    bh_queue_enter_loop_run(g_app_mgr_queue, app_manager_queue_callback, NULL);

    g_app_mgr_started = false;

    /* Destroy registered resources */
    am_cleanup_registeration(ID_APP_MGR);

    /* Destroy watchdog */
    watchdog_destroy();

fail2:
    module_data_list_destroy();

fail1:
    bh_queue_destroy(g_app_mgr_queue);
}

bool
app_manager_is_started(void)
{
    return g_app_mgr_started;
}

#include "module_config.h"

module_interface *g_module_interfaces[Module_Max] = {
#if ENABLE_MODULE_JEFF != 0
    &jeff_module_interface,
#else
    NULL,
#endif

#if ENABLE_MODULE_WASM_APP != 0
    &wasm_app_module_interface,
#else
    NULL,
#endif

#if ENABLE_MODULE_WASM_LIB != 0
    &wasm_lib_module_interface
#else
    NULL
#endif
};
