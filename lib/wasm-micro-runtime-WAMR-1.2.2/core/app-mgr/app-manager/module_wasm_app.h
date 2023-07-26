/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _MODULE_WASM_APP_H_
#define _MODULE_WASM_APP_H_

#include "bh_queue.h"
#include "app_manager_export.h"
#include "wasm_export.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SECTION_TYPE_USER 0
#define SECTION_TYPE_TYPE 1
#define SECTION_TYPE_IMPORT 2
#define SECTION_TYPE_FUNC 3
#define SECTION_TYPE_TABLE 4
#define SECTION_TYPE_MEMORY 5
#define SECTION_TYPE_GLOBAL 6
#define SECTION_TYPE_EXPORT 7
#define SECTION_TYPE_START 8
#define SECTION_TYPE_ELEM 9
#define SECTION_TYPE_CODE 10
#define SECTION_TYPE_DATA 11

typedef enum AOTSectionType {
    AOT_SECTION_TYPE_TARGET_INFO = 0,
    AOT_SECTION_TYPE_INIT_DATA = 1,
    AOT_SECTION_TYPE_TEXT = 2,
    AOT_SECTION_TYPE_FUNCTION = 3,
    AOT_SECTION_TYPE_EXPORT = 4,
    AOT_SECTION_TYPE_RELOCATION = 5,
    AOT_SECTION_TYPE_SIGANATURE = 6,
    AOT_SECTION_TYPE_CUSTOM = 100,
} AOTSectionType;

enum {
    WASM_Msg_Start = BASE_EVENT_MAX,
    TIMER_EVENT_WASM,
    SENSOR_EVENT_WASM,
    CONNECTION_EVENT_WASM,
    WIDGET_EVENT_WASM,
    WASM_Msg_End = WASM_Msg_Start + 100
};

typedef struct wasm_data {
    /* for easily access the containing wasm module */
    wasm_module_t wasm_module;
    wasm_module_inst_t wasm_module_inst;
    /* Permissions of the WASM app */
    char *perms;
    /* thread list mapped with this WASM module */
    korp_tid thread_id;
    /* for easily access the containing module data */
    module_data *m_data;
    /* is bytecode or aot */
    bool is_bytecode;
    /* sections of wasm bytecode or aot file */
    void *sections;
    /* execution environment */
    wasm_exec_env_t exec_env;
} wasm_data;

/* sensor event */
typedef struct _sensor_event_data {
    uint32 sensor_id;

    int data_fmt;
    /* event of attribute container from context core */
    void *data;
} sensor_event_data_t;

/* WASM Bytecode File */
typedef struct wasm_bytecode_file {
    /* magics */
    int magic;
    /* current version */
    int version;
    /* WASM section list */
    wasm_section_list_t sections;
    /* Last WASM section in the list */
    wasm_section_t *section_end;
} wasm_bytecode_file_t;

/* WASM AOT File */
typedef struct wasm_aot_file {
    /* magics */
    int magic;
    /* current version */
    int version;
    /* AOT section list */
    aot_section_list_t sections;
    /* Last AOT section in the list */
    aot_section_t *section_end;
} wasm_aot_file_t;

/* WASM App File */
typedef struct wasm_app_file_t {
    union {
        wasm_bytecode_file_t bytecode;
        wasm_aot_file_t aot;
    } u;
} wasm_app_file_t;

extern module_interface wasm_app_module_interface;

typedef void (*message_type_handler_t)(module_data *m_data, bh_message_t msg);
extern bool
wasm_register_msg_callback(int msg_type,
                           message_type_handler_t message_handler);

typedef void (*resource_cleanup_handler_t)(uint32 module_id);
extern bool
wasm_register_cleanup_callback(resource_cleanup_handler_t handler);

/**
 * Set WASI root dir for modules. On each wasm app installation, a sub dir named
 * with the app's name will be created autamically. That wasm app can only
 * access this sub dir.
 *
 * @param root_dir the root dir to set
 * @return true for success, false otherwise
 */
bool
wasm_set_wasi_root_dir(const char *root_dir);

/**
 * Get WASI root dir
 *
 * @return the WASI root dir
 */
const char *
wasm_get_wasi_root_dir();

#ifdef __cplusplus
} /* end of extern "C" */
#endif

#endif /* _MODULE_WASM_APP_H_ */
