/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef APP_MANAGER_H
#define APP_MANAGER_H

#include "bh_platform.h"
#include "app_manager_export.h"
#include "native_interface.h"
#include "bi-inc/shared_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define APP_MGR_MALLOC wasm_runtime_malloc
#define APP_MGR_FREE wasm_runtime_free

/* os_printf is defined in each platform */
#define app_manager_printf os_printf

#define SEND_ERR_RESPONSE(mid, err_msg)                                        \
    do {                                                                       \
        app_manager_printf("%s\n", err_msg);                                   \
        send_error_response_to_host(mid, INTERNAL_SERVER_ERROR_5_00, err_msg); \
    } while (0)

extern module_interface *g_module_interfaces[Module_Max];

/* Lock of the module data list */
extern korp_mutex module_data_list_lock;

/* Module data list */
extern module_data *module_data_list;

void
app_manager_add_module_data(module_data *m_data);

void
app_manager_del_module_data(module_data *m_data);

bool
module_data_list_init();

void
module_data_list_destroy();

bool
app_manager_is_interrupting_module(uint32 module_type, void *module_inst);

void
release_module(module_data *m_data);

void
module_data_list_remove(module_data *m_data);

void *
app_manager_timer_create(void (*timer_callback)(void *),
                         watchdog_timer *wd_timer);

void
app_manager_timer_destroy(void *timer);

void
app_manager_timer_start(void *timer, int timeout);

void
app_manager_timer_stop(void *timer);

watchdog_timer *
app_manager_get_wd_timer_from_timer_handle(void *timer);

int
app_manager_signature_verify(const uint8_t *file, unsigned int file_len,
                             const uint8_t *signature, unsigned int sig_size);

void
targeted_app_request_handler(request_t *request, void *unused);

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif
