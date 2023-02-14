/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _APP_MANAGER_EXPORT_H_
#define _APP_MANAGER_EXPORT_H_

#include "native_interface.h"
#include "bi-inc/shared_utils.h"
#include "bh_queue.h"
#include "host_link.h"
#include "runtime_timer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Special module IDs */
#define ID_HOST -3
#define ID_APP_MGR -2
/* Invalid module ID */
#define ID_NONE ((uint32)-1)

struct attr_container;

/* Queue message type */
typedef enum QUEUE_MSG_TYPE {
    COAP_PARSED = LINK_MSG_TYPE_MAX + 1,
    RESTFUL_REQUEST,
    RESTFUL_RESPONSE,
    TIMER_EVENT = 5,
    SENSOR_EVENT = 6,
    GPIO_INTERRUPT_EVENT = 7,
    BLE_EVENT = 8,
    JDWP_REQUEST = 9,
    WD_TIMEOUT = 10,
    BASE_EVENT_MAX = 100

} QUEUE_MSG_TYPE;

typedef enum {
    Module_Jeff,
    Module_WASM_App,
    Module_WASM_Lib,
    Module_Max
} Module_Type;

struct module_data;

/* Watchdog timer of module */
typedef struct watchdog_timer {
    /* Timer handle of the platform */
    void *timer_handle;
    /* Module of the watchdog timer */
    struct module_data *module_data;
    /* Lock of the watchdog timer */
    korp_mutex lock;
    /* Flag indicates module is being interrupted by watchdog */
    bool is_interrupting;
    /* Flag indicates watchdog timer is stopped */
    bool is_stopped;
} watchdog_timer;

typedef struct module_data {
    struct module_data *next;

    /* ID of the module */
    uint32 id;

    /* Type of the module */
    Module_Type module_type;

    /* Heap of the module */
    void *heap;

    /* Heap size of the module */
    int heap_size;

    /* Module execution timeout in millisecond */
    int timeout;

    /* Queue of the module */
    bh_queue *queue;

    /* Watchdog timer of the module*/
    struct watchdog_timer wd_timer;

    timer_ctx_t timer_ctx;

    /* max timers number app can create */
    int timers;

    /* Internal data of the module */
    void *internal_data;

    /* Module name */
    char module_name[1];
} module_data;

/* Module function types */
typedef bool (*module_init_func)(void);
typedef bool (*module_install_func)(request_t *msg);
typedef bool (*module_uninstall_func)(request_t *msg);
typedef void (*module_watchdog_kill_func)(module_data *module_data);
typedef bool (*module_handle_host_url_func)(void *queue_msg);
typedef module_data *(*module_get_module_data_func)(void *inst);

/**
 * @typedef module_on_install_request_byte_arrive_func
 *
 * @brief Define the signature of function to handle one byte of
 *        module app install request for struct module_interface.
 *
 * @param ch the byte to be received and handled
 * @param total_size total size of the request
 * @param received_total_size currently received total size when
 *        the function return
 *
 * @return true if success, false otherwise
 */
typedef bool (*module_on_install_request_byte_arrive_func)(
    uint8 ch, int total_size, int *received_total_size);

/* Interfaces of each module */
typedef struct module_interface {
    module_init_func module_init;
    module_install_func module_install;
    module_uninstall_func module_uninstall;
    module_watchdog_kill_func module_watchdog_kill;
    module_handle_host_url_func module_handle_host_url;
    module_get_module_data_func module_get_module_data;
    module_on_install_request_byte_arrive_func module_on_install;
} module_interface;

/**
 * @typedef host_init_func
 * @brief Define the host initialize callback function signature for
 * struct host_interface.
 *
 * @return true if success, false if fail
 */
typedef bool (*host_init_func)(void);

/**
 * @typedef host_send_fun
 * @brief Define the host send callback function signature for
 * struct host_interface.
 *
 * @param buf data buffer to send.
 * @param size size of the data to send.
 *
 * @return size of the data sent in bytes
 */
typedef int (*host_send_fun)(void *ctx, const char *buf, int size);

/**
 * @typedef host_destroy_fun
 * @brief Define the host receive callback function signature for
 * struct host_interface.
 *
 */
typedef void (*host_destroy_fun)();

/* Interfaces of host communication */
typedef struct host_interface {
    host_init_func init;
    host_send_fun send;
    host_destroy_fun destroy;
} host_interface;

/**
 * Initialize communication with Host
 *
 * @param interface host communication interface
 *
 * @return true if success, false otherwise
 */
bool
app_manager_host_init(host_interface *intf);

/* Startup app manager */
void
app_manager_startup(host_interface *intf);

/* Return whether app manager is started */
bool
app_manager_is_started(void);

/* Get queue of current applet */
void *
app_manager_get_module_queue(uint32 module_type, void *module_inst);

/* Get applet name of current applet */
const char *
app_manager_get_module_name(uint32 module_type, void *module_inst);

/* Get heap of current applet */
void *
app_manager_get_module_heap(uint32 module_type, void *module_inst);

void *
get_app_manager_queue();

module_data *
app_manager_get_module_data(uint32 module_type, void *module_inst);

unsigned int
app_manager_get_module_id(uint32 module_type, void *module_inst);

module_data *
app_manager_lookup_module_data(const char *name);

module_data *
module_data_list_lookup(const char *module_name);

module_data *
module_data_list_lookup_id(unsigned int module_id);

void
app_manager_post_applets_update_event();

bool
am_register_resource(const char *url,
                     void (*request_handler)(request_t *, void *),
                     uint32 register_id);

void
am_cleanup_registeration(uint32 register_id);

bool
am_register_event(const char *url, uint32_t reg_client);

bool
am_unregister_event(const char *url, uint32_t reg_client);

void
am_publish_event(request_t *event);

void *
am_dispatch_request(request_t *request);

void
am_send_response(response_t *response);

void
module_request_handler(request_t *request, void *user_data);

/**
 * Send request message to host
 *
 * @param msg the request or event message.
 *    It is event when msg->action==COAP_EVENT
 *
 * @return true if success, false otherwise
 */
bool
send_request_to_host(request_t *msg);

/**
 * Send response message to host
 *
 * @param msg the response message
 *
 * @return true if success, false otherwise
 */
bool
send_response_to_host(response_t *msg);

/**
 * Send response with mid and code to host
 *
 * @param mid the message id of response
 * @param code the code/status of response
 * @param msg the detailed message
 *
 * @return true if success, false otherwise
 */
bool
send_error_response_to_host(int mid, int code, const char *msg);

/**
 * Check whether the applet has the permission
 *
 * @param perm the permission needed to check
 *
 * @return true if success, false otherwise
 */
bool
bh_applet_check_permission(const char *perm);

/**
 * Send message to Host
 *
 * @param buf buffer to send
 * @param size size of buffer
 *
 * @return size of buffer sent
 */
int
app_manager_host_send_msg(int msg_type, const char *buf, int size);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif
