/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "module_wasm_app.h"

#include "native_interface.h" /* for request_t type */
#include "app_manager_host.h"
#include "bh_platform.h"
#include "bi-inc/attr_container.h"
#include "coap_ext.h"
#include "event.h"
#include "watchdog.h"
#include "runtime_lib.h"
#if WASM_ENABLE_INTERP != 0
#include "wasm.h"
#endif
#if WASM_ENABLE_AOT != 0
#include "aot_export.h"
#endif

/* clang-format off */
#if WASM_ENABLE_INTERP != 0 || WASM_ENABLE_JIT != 0
/* Wasm bytecode file 4 version bytes */
static uint8 wasm_bytecode_version[4] = {
    (uint8)0x01,
    (uint8)0x00,
    (uint8)0x00,
    (uint8)0x00
};
#endif

#if WASM_ENABLE_AOT != 0
/* Wasm aot file 4 version bytes */
static uint8 wasm_aot_version[4] = {
    (uint8)0x02,
    (uint8)0x00,
    (uint8)0x00,
    (uint8)0x00
};
#endif
/* clang-format on */

static union {
    int a;
    char b;
} __ue = { .a = 1 };

#define is_little_endian() (__ue.b == 1)
/* Wasm App Install Request Receiving Phase */
typedef enum wasm_app_install_req_recv_phase_t {
    Phase_Req_Ver,
    Phase_Req_Action,
    Phase_Req_Fmt,
    Phase_Req_Mid,
    Phase_Req_Sender,
    Phase_Req_Url_Len,
    Phase_Req_Payload_Len, /* payload is wasm app binary */
    Phase_Req_Url,

    /* Magic phase */
    Phase_App_Magic,

#if WASM_ENABLE_INTERP != 0 || WASM_ENABLE_JIT != 0
    /* Phases of wasm bytecode file */
    Phase_Wasm_Version,
    Phase_Wasm_Section_Type,
    Phase_Wasm_Section_Size,
    Phase_Wasm_Section_Content,
#endif

#if WASM_ENABLE_AOT != 0
    /* Phases of wasm AOT file */
    Phase_AOT_Version,
    Phase_AOT_Section_ID,
    Phase_AOT_Section_Size,
    Phase_AOT_Section_Content
#endif
} wasm_app_install_req_recv_phase_t;

/* Message for insall wasm app */
typedef struct install_wasm_app_msg_t {
    uint8 request_version;
    uint8 request_action;
    uint16 request_fmt;
    uint32 request_mid;
    uint32 request_sender;
    uint16 request_url_len;
    uint32 wasm_app_size; /* payload size is just wasm app binary size */
    char *request_url;
    wasm_app_file_t app_file;
    int app_file_magic;
} install_wasm_app_msg_t;

/* Wasm App Install Request Receive Context */
typedef struct wasm_app_install_req_recv_ctx_t {
    wasm_app_install_req_recv_phase_t phase;
    int size_in_phase;
    install_wasm_app_msg_t message;
    int total_received_size;
} wasm_app_install_req_recv_ctx_t;

/* Current wasm app install request receive context */
static wasm_app_install_req_recv_ctx_t recv_ctx;

static bool
wasm_app_module_init(void);

static bool
wasm_app_module_install(request_t *msg);

static bool
wasm_app_module_uninstall(request_t *msg);

static void
wasm_app_module_watchdog_kill(module_data *module_data);

static bool
wasm_app_module_handle_host_url(void *queue_msg);

static module_data *
wasm_app_module_get_module_data(void *inst);

static bool
wasm_app_module_on_install_request_byte_arrive(uint8 ch, int request_total_size,
                                               int *received_size);

static bool
module_wasm_app_handle_install_msg(install_wasm_app_msg_t *message);

#if WASM_ENABLE_INTERP != 0 || WASM_ENABLE_JIT != 0
static void
destroy_all_wasm_sections(wasm_section_list_t sections);

static void
destroy_part_wasm_sections(wasm_section_list_t *p_sections,
                           uint8 *section_types, int section_cnt);
#endif

#if WASM_ENABLE_AOT != 0
static void
destroy_all_aot_sections(aot_section_list_t sections);

static void
destroy_part_aot_sections(aot_section_list_t *p_sections, uint8 *section_types,
                          int section_cnt);
#endif

#define Max_Msg_Callback 10
int g_msg_type[Max_Msg_Callback] = { 0 };
message_type_handler_t g_msg_callbacks[Max_Msg_Callback] = { 0 };

#define Max_Cleanup_Callback 10
static resource_cleanup_handler_t g_cleanup_callbacks[Max_Cleanup_Callback] = {
    0
};

module_interface wasm_app_module_interface = {
    wasm_app_module_init,
    wasm_app_module_install,
    wasm_app_module_uninstall,
    wasm_app_module_watchdog_kill,
    wasm_app_module_handle_host_url,
    wasm_app_module_get_module_data,
    wasm_app_module_on_install_request_byte_arrive
};

#if WASM_ENABLE_INTERP == 0
static unsigned
align_uint(unsigned v, unsigned b)
{
    unsigned m = b - 1;
    return (v + m) & ~m;
}
#endif

static void
exchange_uint32(uint8 *p_data)
{
    uint8 value = *p_data;
    *p_data = *(p_data + 3);
    *(p_data + 3) = value;

    value = *(p_data + 1);
    *(p_data + 1) = *(p_data + 2);
    *(p_data + 2) = value;
}

static wasm_function_inst_t
app_manager_lookup_function(const wasm_module_inst_t module_inst,
                            const char *name, const char *signature)
{
    wasm_function_inst_t func;

    func = wasm_runtime_lookup_function(module_inst, name, signature);
    if (!func && name[0] == '_')
        func = wasm_runtime_lookup_function(module_inst, name + 1, signature);
    return func;
}

static void
app_instance_queue_callback(void *queue_msg, void *arg)
{
    uint32 argv[2];
    wasm_function_inst_t func_onRequest, func_onTimer;

    wasm_module_inst_t inst = (wasm_module_inst_t)arg;
    module_data *m_data = app_manager_get_module_data(Module_WASM_App, inst);
    wasm_data *wasm_app_data;
    int message_type;

    bh_assert(m_data);
    wasm_app_data = (wasm_data *)m_data->internal_data;
    message_type = bh_message_type(queue_msg);

    if (message_type < BASE_EVENT_MAX) {
        switch (message_type) {
            case RESTFUL_REQUEST:
            {
                request_t *request = (request_t *)bh_message_payload(queue_msg);
                int size;
                char *buffer;
                int32 buffer_offset;

                app_manager_printf("App %s got request, url %s, action %d\n",
                                   m_data->module_name, request->url,
                                   request->action);

                func_onRequest = app_manager_lookup_function(
                    inst, "_on_request", "(i32i32)");
                if (!func_onRequest) {
                    app_manager_printf("Cannot find function onRequest\n");
                    break;
                }

                buffer = pack_request(request, &size);
                if (buffer == NULL)
                    break;

                buffer_offset =
                    wasm_runtime_module_dup_data(inst, buffer, size);
                if (buffer_offset == 0) {
                    const char *exception = wasm_runtime_get_exception(inst);
                    if (exception) {
                        app_manager_printf(
                            "Got exception running wasm code: %s\n", exception);
                        wasm_runtime_clear_exception(inst);
                    }
                    free_req_resp_packet(buffer);
                    break;
                }

                free_req_resp_packet(buffer);

                argv[0] = (uint32)buffer_offset;
                argv[1] = (uint32)size;

                if (!wasm_runtime_call_wasm(wasm_app_data->exec_env,
                                            func_onRequest, 2, argv)) {
                    const char *exception = wasm_runtime_get_exception(inst);
                    bh_assert(exception);
                    app_manager_printf("Got exception running wasm code: %s\n",
                                       exception);
                    wasm_runtime_clear_exception(inst);
                    wasm_runtime_module_free(inst, buffer_offset);
                    break;
                }

                wasm_runtime_module_free(inst, buffer_offset);
                app_manager_printf("Wasm app process request success.\n");
                break;
            }
            case RESTFUL_RESPONSE:
            {
                wasm_function_inst_t func_onResponse;
                response_t *response =
                    (response_t *)bh_message_payload(queue_msg);
                int size;
                char *buffer;
                int32 buffer_offset;

                app_manager_printf("App %s got response_t,status %d\n",
                                   m_data->module_name, response->status);

                func_onResponse = app_manager_lookup_function(
                    inst, "_on_response", "(i32i32)");
                if (!func_onResponse) {
                    app_manager_printf("Cannot find function on_response\n");
                    break;
                }

                buffer = pack_response(response, &size);
                if (buffer == NULL)
                    break;

                buffer_offset =
                    wasm_runtime_module_dup_data(inst, buffer, size);
                if (buffer_offset == 0) {
                    const char *exception = wasm_runtime_get_exception(inst);
                    if (exception) {
                        app_manager_printf(
                            "Got exception running wasm code: %s\n", exception);
                        wasm_runtime_clear_exception(inst);
                    }
                    free_req_resp_packet(buffer);
                    break;
                }

                free_req_resp_packet(buffer);

                argv[0] = (uint32)buffer_offset;
                argv[1] = (uint32)size;

                if (!wasm_runtime_call_wasm(wasm_app_data->exec_env,
                                            func_onResponse, 2, argv)) {
                    const char *exception = wasm_runtime_get_exception(inst);
                    bh_assert(exception);
                    app_manager_printf("Got exception running wasm code: %s\n",
                                       exception);
                    wasm_runtime_clear_exception(inst);
                    wasm_runtime_module_free(inst, buffer_offset);
                    break;
                }

                wasm_runtime_module_free(inst, buffer_offset);
                app_manager_printf("Wasm app process response success.\n");
                break;
            }
            default:
            {
                for (int i = 0; i < Max_Msg_Callback; i++) {
                    if (g_msg_type[i] == message_type) {
                        g_msg_callbacks[i](m_data, queue_msg);
                        return;
                    }
                }
                app_manager_printf(
                    "Invalid message type of WASM app queue message.\n");
                break;
            }
        }
    }
    else {
        switch (message_type) {
            case TIMER_EVENT_WASM:
            {
                unsigned int timer_id;
                if (bh_message_payload(queue_msg)) {
                    /* Call Timer.callOnTimer() method */
                    func_onTimer = app_manager_lookup_function(
                        inst, "_on_timer_callback", "(i32)");

                    if (!func_onTimer) {
                        app_manager_printf(
                            "Cannot find function _on_timer_callback\n");
                        break;
                    }
                    timer_id =
                        (unsigned int)(uintptr_t)bh_message_payload(queue_msg);
                    argv[0] = timer_id;
                    if (!wasm_runtime_call_wasm(wasm_app_data->exec_env,
                                                func_onTimer, 1, argv)) {
                        const char *exception =
                            wasm_runtime_get_exception(inst);
                        bh_assert(exception);
                        app_manager_printf(
                            "Got exception running wasm code: %s\n", exception);
                        wasm_runtime_clear_exception(inst);
                    }
                }
                break;
            }
            default:
            {
                for (int i = 0; i < Max_Msg_Callback; i++) {
                    if (g_msg_type[i] == message_type) {
                        g_msg_callbacks[i](m_data, queue_msg);
                        return;
                    }
                }
                app_manager_printf(
                    "Invalid message type of WASM app queue message.\n");
                break;
            }
        }
    }
}

#if WASM_ENABLE_LIBC_WASI != 0
static bool
wasm_app_prepare_wasi_dir(wasm_module_t module, const char *module_name,
                          char *wasi_dir_buf, uint32 buf_size)
{
    const char *wasi_root = wasm_get_wasi_root_dir();
    char *p = wasi_dir_buf;
    uint32 module_name_len = strlen(module_name);
    uint32 wasi_root_len = strlen(wasi_root);
    uint32 total_size;
    struct stat st = { 0 };

    bh_assert(wasi_root);

    /* wasi_dir: wasi_root/module_name */
    total_size = wasi_root_len + 1 + module_name_len + 1;
    if (total_size > buf_size)
        return false;
    memcpy(p, wasi_root, wasi_root_len);
    p += wasi_root_len;
    *p++ = '/';
    memcpy(p, module_name, module_name_len);
    p += module_name_len;
    *p++ = '\0';

    if (mkdir(wasi_dir_buf, 0777) != 0) {
        if (errno == EEXIST) {
            /* Failed due to dir already exist */
            if ((stat(wasi_dir_buf, &st) == 0) && (st.st_mode & S_IFDIR)) {
                return true;
            }
        }

        return false;
    }

    return true;
}
#endif

/* WASM app thread main routine */
static void *
wasm_app_routine(void *arg)
{
    wasm_function_inst_t func_onInit;
    wasm_function_inst_t func_onDestroy;

    module_data *m_data = (module_data *)arg;
    wasm_data *wasm_app_data = (wasm_data *)m_data->internal_data;
    wasm_module_inst_t inst = wasm_app_data->wasm_module_inst;

    /* Set m_data to the VM managed instance's custom data */
    wasm_runtime_set_custom_data(inst, m_data);

    app_manager_printf("WASM app '%s' started\n", m_data->module_name);

#if WASM_ENABLE_LIBC_WASI != 0
    if (wasm_runtime_is_wasi_mode(inst)) {
        wasm_function_inst_t func_start;
        /* In wasi mode, we should call function named "_start"
           which initializes the wasi envrionment. The "_start" function
           will call "main" function */
        if ((func_start = wasm_runtime_lookup_wasi_start_function(inst))) {
            if (!wasm_runtime_call_wasm(wasm_app_data->exec_env, func_start, 0,
                                        NULL)) {
                const char *exception = wasm_runtime_get_exception(inst);
                bh_assert(exception);
                app_manager_printf(
                    "Got exception running wasi start function: %s\n",
                    exception);
                wasm_runtime_clear_exception(inst);
                goto fail1;
            }
        }
        /* if no start function is found, we execute
           the _on_init function as normal */
    }
#endif

    /* Call app's onInit() method */
    func_onInit = app_manager_lookup_function(inst, "_on_init", "()");
    if (!func_onInit) {
        app_manager_printf("Cannot find function on_init().\n");
        goto fail1;
    }

    if (!wasm_runtime_call_wasm(wasm_app_data->exec_env, func_onInit, 0,
                                NULL)) {
        const char *exception = wasm_runtime_get_exception(inst);
        bh_assert(exception);
        app_manager_printf("Got exception running WASM code: %s\n", exception);
        wasm_runtime_clear_exception(inst);
        /* call on_destroy() in case some resources are opened in on_init()
         * and then exception thrown */
        goto fail2;
    }

    /* Enter queue loop run to receive and process applet queue message */
    bh_queue_enter_loop_run(m_data->queue, app_instance_queue_callback, inst);

    app_manager_printf("App instance main thread exit.\n");

fail2:
    /* Call WASM app onDestroy() method if there is */
    func_onDestroy = app_manager_lookup_function(inst, "_on_destroy", "()");
    if (func_onDestroy) {
        if (!wasm_runtime_call_wasm(wasm_app_data->exec_env, func_onDestroy, 0,
                                    NULL)) {
            const char *exception = wasm_runtime_get_exception(inst);
            bh_assert(exception);
            app_manager_printf("Got exception running WASM code: %s\n",
                               exception);
            wasm_runtime_clear_exception(inst);
        }
    }

fail1:

    return NULL;
}

static void
cleanup_app_resource(module_data *m_data)
{
    int i;
    wasm_data *wasm_app_data = (wasm_data *)m_data->internal_data;
    bool is_bytecode = wasm_app_data->is_bytecode;

    am_cleanup_registeration(m_data->id);

    am_unregister_event(NULL, m_data->id);

    for (i = 0; i < Max_Cleanup_Callback; i++) {
        if (g_cleanup_callbacks[i] != NULL)
            g_cleanup_callbacks[i](m_data->id);
        else
            break;
    }

    wasm_runtime_deinstantiate(wasm_app_data->wasm_module_inst);

    /* Destroy remain sections (i.e. data segment section for bytecode file
     * or text section of aot file) from app file's section list. */
    if (is_bytecode) {
#if WASM_ENABLE_INTERP != 0 || WASM_ENABLE_JIT != 0
        destroy_all_wasm_sections(
            (wasm_section_list_t)(wasm_app_data->sections));
#else
        bh_assert(0);
#endif
    }
    else {
#if WASM_ENABLE_AOT != 0
        destroy_all_aot_sections((aot_section_list_t)(wasm_app_data->sections));
#else
        bh_assert(0);
#endif
    }

    if (wasm_app_data->wasm_module)
        wasm_runtime_unload(wasm_app_data->wasm_module);

    if (wasm_app_data->exec_env)
        wasm_runtime_destroy_exec_env(wasm_app_data->exec_env);

    /* Destroy watchdog timer */
    watchdog_timer_destroy(&m_data->wd_timer);

    /* Remove module data from module data list and free it */
    app_manager_del_module_data(m_data);
}

/************************************************************/
/*        Module specific functions implementation          */
/************************************************************/

static bool
wasm_app_module_init(void)
{
    uint32 version;

#if WASM_ENABLE_INTERP != 0 || WASM_ENABLE_JIT != 0
    version = WASM_CURRENT_VERSION;
    if (!is_little_endian())
        exchange_uint32((uint8 *)&version);
    bh_memcpy_s(wasm_bytecode_version, 4, &version, 4);
#endif

#if WASM_ENABLE_AOT != 0
    version = AOT_CURRENT_VERSION;
    if (!is_little_endian())
        exchange_uint32((uint8 *)&version);
    bh_memcpy_s(wasm_aot_version, 4, &version, 4);
#endif
    return true;
}

#define APP_NAME_MAX_LEN 128
#define MAX_INT_STR_LEN 11

static bool
wasm_app_module_install(request_t *msg)
{
    unsigned int m_data_size, heap_size, stack_size;
    unsigned int timeout, timers, err_size;
    char *properties;
    int properties_offset;
    wasm_app_file_t *wasm_app_file;
    wasm_data *wasm_app_data;
    package_type_t package_type;
    module_data *m_data = NULL;
    wasm_module_t module = NULL;
    wasm_module_inst_t inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    char m_name[APP_NAME_MAX_LEN] = { 0 };
    char timeout_str[MAX_INT_STR_LEN] = { 0 };
    char heap_size_str[MAX_INT_STR_LEN] = { 0 };
    char timers_str[MAX_INT_STR_LEN] = { 0 }, err[128], err_resp[256];
#if WASM_ENABLE_LIBC_WASI != 0
    char wasi_dir_buf[PATH_MAX] = { 0 };
    const char *wasi_dir_list[] = { wasi_dir_buf };
#endif

    err_size = sizeof(err);

    /* Check payload */
    if (!msg->payload || msg->payload_len == 0) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install WASM app failed: invalid wasm file.");
        return false;
    }

    /* Judge the app type is AOTed or not */
    package_type = get_package_type((uint8 *)msg->payload, msg->payload_len);
    wasm_app_file = (wasm_app_file_t *)msg->payload;

    /* Check app name */
    properties_offset = check_url_start(msg->url, strlen(msg->url), "/applet");
    bh_assert(properties_offset > 0);
    if (properties_offset <= 0) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install WASM app failed: invalid app name.");
        goto fail;
    }

    properties = msg->url + properties_offset;
    find_key_value(properties, strlen(properties), "name", m_name,
                   sizeof(m_name) - 1, '&');

    if (strlen(m_name) == 0) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install WASM app failed: invalid app name.");
        goto fail;
    }

    if (app_manager_lookup_module_data(m_name)) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install WASM app failed: app already installed.");
        goto fail;
    }

    /* Parse heap size */
    heap_size = APP_HEAP_SIZE_DEFAULT;
    find_key_value(properties, strlen(properties), "heap", heap_size_str,
                   sizeof(heap_size_str) - 1, '&');
    if (strlen(heap_size_str) > 0) {
        heap_size = atoi(heap_size_str);
        if (heap_size < APP_HEAP_SIZE_MIN)
            heap_size = APP_HEAP_SIZE_MIN;
        else if (heap_size > APP_HEAP_SIZE_MAX)
            heap_size = APP_HEAP_SIZE_MAX;
    }

    /* Load WASM file and instantiate*/
    switch (package_type) {
#if WASM_ENABLE_AOT != 0
        case Wasm_Module_AoT:
        {
            wasm_aot_file_t *aot_file;
            /* clang-format off */
            /* Sections to be released after loading */
            uint8 sections1[] = {
                AOT_SECTION_TYPE_TARGET_INFO,
                AOT_SECTION_TYPE_INIT_DATA,
                AOT_SECTION_TYPE_FUNCTION,
                AOT_SECTION_TYPE_EXPORT,
                AOT_SECTION_TYPE_RELOCATION,
                AOT_SECTION_TYPE_SIGANATURE,
                AOT_SECTION_TYPE_CUSTOM,
            };
            /* clang-format on */

            aot_file = &wasm_app_file->u.aot;

            /* Load AOT module from sections */
            module = wasm_runtime_load_from_sections(aot_file->sections, true,
                                                     err, err_size);
            if (!module) {
                snprintf(err_resp, sizeof(err_resp),
                         "Install WASM app failed: %s", err);
                SEND_ERR_RESPONSE(msg->mid, err_resp);
                goto fail;
            }
            /* Destroy useless sections from list after load */
            destroy_part_aot_sections(&aot_file->sections, sections1,
                                      sizeof(sections1) / sizeof(uint8));

#if WASM_ENABLE_LIBC_WASI != 0
            if (!wasm_app_prepare_wasi_dir(module, m_name, wasi_dir_buf,
                                           sizeof(wasi_dir_buf))) {
                SEND_ERR_RESPONSE(
                    msg->mid,
                    "Install WASM app failed: prepare wasi env failed.");
                goto fail;
            }
            wasm_runtime_set_wasi_args(module, wasi_dir_list, 1, NULL, 0, NULL,
                                       0, NULL, 0);
#endif

            /* Instantiate the AOT module */
            inst =
                wasm_runtime_instantiate(module, 0, heap_size, err, err_size);
            if (!inst) {
                snprintf(err_resp, sizeof(err_resp),
                         "Install WASM app failed: %s", err);
                SEND_ERR_RESPONSE(msg->mid, err);
                goto fail;
            }
            break;
        }
#endif /* endof WASM_ENABLE_AOT != 0 */

#if WASM_ENABLE_INTERP != 0 || WASM_ENABLE_JIT != 0
        case Wasm_Module_Bytecode:
        {
            wasm_bytecode_file_t *bytecode_file;
            /* Sections to be released after loading */
            uint8 sections1[] = {
                SECTION_TYPE_USER,
                SECTION_TYPE_TYPE,
                SECTION_TYPE_IMPORT,
                SECTION_TYPE_FUNC,
                SECTION_TYPE_TABLE,
                SECTION_TYPE_MEMORY,
                SECTION_TYPE_GLOBAL,
                SECTION_TYPE_EXPORT,
                SECTION_TYPE_START,
                SECTION_TYPE_ELEM,
#if WASM_ENABLE_BULK_MEMORY != 0
                SECTION_TYPE_DATACOUNT
#endif

            };
            /* Sections to be released after instantiating */
            uint8 sections2[] = { SECTION_TYPE_DATA };

            bytecode_file = &wasm_app_file->u.bytecode;

            /* Load wasm module from sections */
            module = wasm_runtime_load_from_sections(bytecode_file->sections,
                                                     false, err, err_size);
            if (!module) {
                snprintf(err_resp, sizeof(err_resp),
                         "Install WASM app failed: %s", err);
                SEND_ERR_RESPONSE(msg->mid, err_resp);
                goto fail;
            }

            /* Destroy useless sections from list after load */
            destroy_part_wasm_sections(&bytecode_file->sections, sections1,
                                       sizeof(sections1) / sizeof(uint8));

#if WASM_ENABLE_LIBC_WASI != 0
            if (!wasm_app_prepare_wasi_dir(module, m_name, wasi_dir_buf,
                                           sizeof(wasi_dir_buf))) {
                SEND_ERR_RESPONSE(
                    msg->mid,
                    "Install WASM app failed: prepare wasi env failed.");
                goto fail;
            }
            wasm_runtime_set_wasi_args(module, wasi_dir_list, 1, NULL, 0, NULL,
                                       0, NULL, 0);
#endif

            /* Instantiate the wasm module */
            inst =
                wasm_runtime_instantiate(module, 0, heap_size, err, err_size);
            if (!inst) {
                snprintf(err_resp, sizeof(err_resp),
                         "Install WASM app failed: %s", err);
                SEND_ERR_RESPONSE(msg->mid, err_resp);
                goto fail;
            }

            /* Destroy useless sections from list after instantiate */
            destroy_part_wasm_sections(&bytecode_file->sections, sections2,
                                       sizeof(sections2) / sizeof(uint8));
            break;
        }
#endif /* endof WASM_ENALBE_INTERP != 0 || WASM_ENABLE_JIT != 0 */
        default:
            SEND_ERR_RESPONSE(
                msg->mid,
                "Install WASM app failed: invalid wasm package type.");
            goto fail;
    }

    /* Create module data including the wasm_app_data as its internal_data*/
    m_data_size = offsetof(module_data, module_name) + strlen(m_name) + 1;
    m_data_size = align_uint(m_data_size, 4);
    m_data = APP_MGR_MALLOC(m_data_size + sizeof(wasm_data));
    if (!m_data) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install WASM app failed: allocate memory failed.");
        goto fail;
    }
    memset(m_data, 0, m_data_size + sizeof(wasm_data));

    m_data->module_type = Module_WASM_App;
    m_data->internal_data = (uint8 *)m_data + m_data_size;
    wasm_app_data = (wasm_data *)m_data->internal_data;
    wasm_app_data->wasm_module_inst = inst;
    wasm_app_data->wasm_module = module;
    wasm_app_data->m_data = m_data;
    if (package_type == Wasm_Module_Bytecode) {
        wasm_app_data->is_bytecode = true;
        wasm_app_data->sections = wasm_app_file->u.bytecode.sections;
    }
    else {
        wasm_app_data->is_bytecode = false;
        wasm_app_data->sections = wasm_app_file->u.aot.sections;
    }

    if (!(wasm_app_data->exec_env = exec_env =
              wasm_runtime_create_exec_env(inst, DEFAULT_WASM_STACK_SIZE))) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install WASM app failed: create exec env failed.");
        goto fail;
    }

    /* Set module data - name and module type */
    bh_strcpy_s(m_data->module_name, strlen(m_name) + 1, m_name);

    /* Set module data - execution timeout */
    timeout = DEFAULT_WATCHDOG_INTERVAL;
    find_key_value(properties, strlen(properties), "wd", timeout_str,
                   sizeof(timeout_str) - 1, '&');
    if (strlen(timeout_str) > 0)
        timeout = atoi(timeout_str);
    m_data->timeout = timeout;

    /* Set module data - create queue */
    m_data->queue = bh_queue_create();
    if (!m_data->queue) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install WASM app failed: create app queue failed.");
        goto fail;
    }

    /* Set heap size */
    m_data->heap_size = heap_size;

    /* Set module data - timers number */
    timers = DEFAULT_TIMERS_PER_APP;
    find_key_value(properties, strlen(properties), "timers", timers_str,
                   sizeof(timers_str) - 1, '&');
    if (strlen(timers_str) > 0) {
        timers = atoi(timers_str);
        if (timers > MAX_TIMERS_PER_APP)
            timers = MAX_TIMERS_PER_APP;
    }

    /* Attention: must add the module before start the thread! */
    app_manager_add_module_data(m_data);

    m_data->timer_ctx = create_wasm_timer_ctx(m_data->id, timers);
    if (!m_data->timer_ctx) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Install WASM app failed: create app timers failed.");
        goto fail;
    }

    /* Initialize watchdog timer */
    if (!watchdog_timer_init(m_data)) {
        SEND_ERR_RESPONSE(
            msg->mid,
            "Install WASM app failed: create app watchdog timer failed.");
        goto fail;
    }

    stack_size = APP_THREAD_STACK_SIZE_DEFAULT;
#ifdef OS_ENABLE_HW_BOUND_CHECK
    stack_size += 4 * BH_KB;
#endif
    /* Create WASM app thread. */
    if (os_thread_create(&wasm_app_data->thread_id, wasm_app_routine,
                         (void *)m_data, stack_size)
        != 0) {
        module_data_list_remove(m_data);
        SEND_ERR_RESPONSE(msg->mid,
                          "Install WASM app failed: create app thread failed.");
        goto fail;
    }

    /* only when thread is created it is the flag of installation success */
    app_manager_post_applets_update_event();

    app_manager_printf("Install WASM app success!\n");
    send_error_response_to_host(msg->mid, CREATED_2_01, NULL); /* CREATED */

    return true;

fail:
    if (m_data)
        release_module(m_data);

    if (inst)
        wasm_runtime_deinstantiate(inst);

    if (module)
        wasm_runtime_unload(module);

    if (exec_env)
        wasm_runtime_destroy_exec_env(exec_env);

    switch (package_type) {
#if WASM_ENABLE_INTERP != 0 || WASM_ENABLE_JIT != 0
        case Wasm_Module_Bytecode:
            destroy_all_wasm_sections(wasm_app_file->u.bytecode.sections);
            break;
#endif
#if WASM_ENABLE_AOT != 0
        case Wasm_Module_AoT:
            destroy_all_aot_sections(wasm_app_file->u.aot.sections);
            break;
#endif
        default:
            break;
    }

    return false;
}

/* For internal use: if defined to 1, the process will
 * exit when wasm app is uninstalled. Hence valgrind can
 * print memory leak report. */
#ifndef VALGRIND_CHECK
#define VALGRIND_CHECK 0
#endif

/* Uninstall WASM app */
static bool
wasm_app_module_uninstall(request_t *msg)
{
    module_data *m_data;
    wasm_data *wasm_app_data;
    char m_name[APP_NAME_MAX_LEN] = { 0 };
    char *properties;
    int properties_offset;

    properties_offset = check_url_start(msg->url, strlen(msg->url), "/applet");
    /* TODO: assert(properties_offset > 0) */
    if (properties_offset <= 0)
        return false;
    properties = msg->url + properties_offset;
    find_key_value(properties, strlen(properties), "name", m_name,
                   sizeof(m_name) - 1, '&');

    if (strlen(m_name) == 0) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Uninstall WASM app failed: invalid app name.");
        return false;
    }

    m_data = app_manager_lookup_module_data(m_name);
    if (!m_data) {
        SEND_ERR_RESPONSE(msg->mid, "Uninstall WASM app failed: no app found.");
        return false;
    }

    if (m_data->module_type != Module_WASM_App) {
        SEND_ERR_RESPONSE(msg->mid,
                          "Uninstall WASM app failed: invalid module type.");
        return false;
    }

    if (m_data->wd_timer.is_interrupting) {
        SEND_ERR_RESPONSE(
            msg->mid,
            "Uninstall WASM app failed: app is being interrupted by watchdog.");
        return false;
    }

    /* Exit app queue loop run */
    bh_queue_exit_loop_run(m_data->queue);

    /* Wait for wasm app thread to exit */
    wasm_app_data = (wasm_data *)m_data->internal_data;
    os_thread_join(wasm_app_data->thread_id, NULL);

    cleanup_app_resource(m_data);

    app_manager_post_applets_update_event();

    app_manager_printf("Uninstall WASM app successful!\n");

#ifdef COLLECT_CODE_COVERAGE
    /* Exit app manager so as to collect code coverage data */
    if (!strcmp(m_name, "__exit_app_manager__")) {
        app_manager_printf("Exit app manager\n");
        bh_queue_exit_loop_run(get_app_manager_queue());
    }
#endif

#if VALGRIND_CHECK != 0
    bh_queue_exit_loop_run(get_app_manager_queue());
#endif

    send_error_response_to_host(msg->mid, DELETED_2_02, NULL); /* DELETED */
    return true;
}

static bool
wasm_app_module_handle_host_url(void *queue_msg)
{
    /* TODO: implement in future */
    app_manager_printf("App handles host url address %d\n",
                       (int)(uintptr_t)queue_msg);
    return false;
}

static module_data *
wasm_app_module_get_module_data(void *inst)
{
    wasm_module_inst_t module_inst = (wasm_module_inst_t)inst;
    return (module_data *)wasm_runtime_get_custom_data(module_inst);
}

static void
wasm_app_module_watchdog_kill(module_data *m_data)
{
    /* TODO: implement in future */
    app_manager_printf("Watchdog kills app: %s\n", m_data->module_name);
    return;
}

bool
wasm_register_msg_callback(int message_type,
                           message_type_handler_t message_handler)
{
    int i;
    int freeslot = -1;
    for (i = 0; i < Max_Msg_Callback; i++) {
        /* replace handler for the same event registered */
        if (g_msg_type[i] == message_type)
            break;

        if (g_msg_callbacks[i] == NULL && freeslot == -1)
            freeslot = i;
    }

    if (i != Max_Msg_Callback)
        g_msg_callbacks[i] = message_handler;
    else if (freeslot != -1) {
        g_msg_callbacks[freeslot] = message_handler;
        g_msg_type[freeslot] = message_type;
    }
    else
        return false;

    return true;
}

bool
wasm_register_cleanup_callback(resource_cleanup_handler_t handler)
{
    int i;

    for (i = 0; i < Max_Cleanup_Callback; i++) {
        if (g_cleanup_callbacks[i] == NULL) {
            g_cleanup_callbacks[i] = handler;
            return true;
        }
    }

    return false;
}

#define RECV_INTEGER(value, next_phase)                \
    do {                                               \
        uint8 *p = (uint8 *)&value;                    \
        p[recv_ctx.size_in_phase++] = ch;              \
        if (recv_ctx.size_in_phase == sizeof(value)) { \
            if (sizeof(value) == 4)                    \
                value = ntohl(value);                  \
            else if (sizeof(value) == 2)               \
                value = ntohs(value);                  \
            recv_ctx.phase = next_phase;               \
            recv_ctx.size_in_phase = 0;                \
        }                                              \
    } while (0)

/* return:
 * 1: whole wasm app arrived
 * 0: one valid byte arrived
 * -1: fail to process the byte arrived, e.g. allocate memory fail
 */
static bool
wasm_app_module_on_install_request_byte_arrive(uint8 ch, int request_total_size,
                                               int *received_size)
{
    uint8 *p;
    int magic;
    package_type_t package_type = Package_Type_Unknown;

    if (recv_ctx.phase == Phase_Req_Ver) {
        recv_ctx.phase = Phase_Req_Ver;
        recv_ctx.size_in_phase = 0;
        recv_ctx.total_received_size = 0;
    }

    recv_ctx.total_received_size++;
    *received_size = recv_ctx.total_received_size;

    if (recv_ctx.phase == Phase_Req_Ver) {
        if (ch != 1 /* REQUES_PACKET_VER from restful_utils.c */)
            return false;
        recv_ctx.phase = Phase_Req_Action;
        return true;
    }
    else if (recv_ctx.phase == Phase_Req_Action) {
        recv_ctx.message.request_action = ch;
        recv_ctx.phase = Phase_Req_Fmt;
        recv_ctx.size_in_phase = 0;
        return true;
    }
    else if (recv_ctx.phase == Phase_Req_Fmt) {
        RECV_INTEGER(recv_ctx.message.request_fmt, Phase_Req_Mid);
        return true;
    }
    else if (recv_ctx.phase == Phase_Req_Mid) {
        RECV_INTEGER(recv_ctx.message.request_mid, Phase_Req_Sender);
        return true;
    }
    else if (recv_ctx.phase == Phase_Req_Sender) {
        RECV_INTEGER(recv_ctx.message.request_sender, Phase_Req_Url_Len);
        return true;
    }
    else if (recv_ctx.phase == Phase_Req_Url_Len) {
        p = (uint8 *)&recv_ctx.message.request_url_len;

        p[recv_ctx.size_in_phase++] = ch;
        if (recv_ctx.size_in_phase
            == sizeof(recv_ctx.message.request_url_len)) {
            recv_ctx.message.request_url_len =
                ntohs(recv_ctx.message.request_url_len);
            recv_ctx.message.request_url =
                APP_MGR_MALLOC(recv_ctx.message.request_url_len + 1);
            if (NULL == recv_ctx.message.request_url) {
                app_manager_printf("Allocate memory failed!\n");
                SEND_ERR_RESPONSE(recv_ctx.message.request_mid,
                                  "Install WASM app failed: "
                                  "allocate memory failed.");
                goto fail;
            }
            memset(recv_ctx.message.request_url, 0,
                   recv_ctx.message.request_url_len + 1);
            recv_ctx.phase = Phase_Req_Payload_Len;
            recv_ctx.size_in_phase = 0;
        }
        return true;
    }
    else if (recv_ctx.phase == Phase_Req_Payload_Len) {
        RECV_INTEGER(recv_ctx.message.wasm_app_size, Phase_Req_Url);
        return true;
    }
    else if (recv_ctx.phase == Phase_Req_Url) {
        recv_ctx.message.request_url[recv_ctx.size_in_phase++] = ch;
        if (recv_ctx.size_in_phase == recv_ctx.message.request_url_len) {
            recv_ctx.phase = Phase_App_Magic;
            recv_ctx.size_in_phase = 0;
        }
        return true;
    }
    else if (recv_ctx.phase == Phase_App_Magic) {
        /* start to receive wasm app magic: bytecode or aot */
        p = (uint8 *)&recv_ctx.message.app_file_magic;

        p[recv_ctx.size_in_phase++] = ch;

        if (recv_ctx.size_in_phase == sizeof(recv_ctx.message.app_file_magic)) {
            magic = recv_ctx.message.app_file_magic;
            package_type = get_package_type((uint8 *)&magic, sizeof(magic) + 1);
            switch (package_type) {
#if WASM_ENABLE_INTERP != 0 || WASM_ENABLE_JIT != 0
                case Wasm_Module_Bytecode:
                    recv_ctx.message.app_file.u.bytecode.magic =
                        recv_ctx.message.app_file_magic;
                    recv_ctx.phase = Phase_Wasm_Version;
                    recv_ctx.size_in_phase = 0;
                    break;
#endif
#if WASM_ENABLE_AOT != 0
                case Wasm_Module_AoT:
                    recv_ctx.message.app_file.u.aot.magic =
                        recv_ctx.message.app_file_magic;
                    recv_ctx.phase = Phase_AOT_Version;
                    recv_ctx.size_in_phase = 0;
                    break;
#endif
                default:
                    SEND_ERR_RESPONSE(recv_ctx.message.request_mid,
                                      "Install WASM app failed: "
                                      "invalid file format.");
                    goto fail;
            }
        }
        return true;
    }
#if WASM_ENABLE_INTERP != 0 || WASM_ENABLE_JIT != 0
    else if (recv_ctx.phase == Phase_Wasm_Version) {
        p = (uint8 *)&recv_ctx.message.app_file.u.bytecode.version;

        if (ch == wasm_bytecode_version[recv_ctx.size_in_phase])
            p[recv_ctx.size_in_phase++] = ch;
        else {
            app_manager_printf("Invalid WASM version!\n");
            SEND_ERR_RESPONSE(recv_ctx.message.request_mid,
                              "Install WASM app failed: invalid WASM version.");
            goto fail;
        }

        if (recv_ctx.size_in_phase
            == sizeof(recv_ctx.message.app_file.u.bytecode.version)) {
            recv_ctx.phase = Phase_Wasm_Section_Type;
            recv_ctx.size_in_phase = 0;
        }
        return true;
    }
    else if (recv_ctx.phase == Phase_Wasm_Section_Type) {
        uint8 section_type = ch;
#if WASM_ENABLE_BULK_MEMORY == 0
        uint8 section_type_max = SECTION_TYPE_DATA;
#else
        uint8 section_type_max = SECTION_TYPE_DATACOUNT;
#endif
        if (section_type <= section_type_max) {
            wasm_section_t *new_section;
            if (!(new_section = (wasm_section_t *)APP_MGR_MALLOC(
                      sizeof(wasm_section_t)))) {
                app_manager_printf("Allocate memory failed!\n");
                SEND_ERR_RESPONSE(recv_ctx.message.request_mid,
                                  "Install WASM app failed: "
                                  "allocate memory failed.");
                goto fail;
            }
            memset(new_section, 0, sizeof(wasm_section_t));
            new_section->section_type = section_type;
            new_section->next = NULL;

            /* add the section to tail of link list */
            if (NULL == recv_ctx.message.app_file.u.bytecode.sections) {
                recv_ctx.message.app_file.u.bytecode.sections = new_section;
                recv_ctx.message.app_file.u.bytecode.section_end = new_section;
            }
            else {
                recv_ctx.message.app_file.u.bytecode.section_end->next =
                    new_section;
                recv_ctx.message.app_file.u.bytecode.section_end = new_section;
            }

            recv_ctx.phase = Phase_Wasm_Section_Size;
            recv_ctx.size_in_phase = 0;

            return true;
        }
        else {
            char error_buf[128];

            app_manager_printf("Invalid wasm section type: %d\n", section_type);
            snprintf(error_buf, sizeof(error_buf),
                     "Install WASM app failed: invalid wasm section type %d",
                     section_type);
            SEND_ERR_RESPONSE(recv_ctx.message.request_mid, error_buf);
            goto fail;
        }
    }
    else if (recv_ctx.phase == Phase_Wasm_Section_Size) {
        /* the last section is the current receiving one */
        wasm_section_t *section =
            recv_ctx.message.app_file.u.bytecode.section_end;
        uint32 byte;

        bh_assert(section);

        byte = ch;

        section->section_body_size |=
            ((byte & 0x7f) << recv_ctx.size_in_phase * 7);
        recv_ctx.size_in_phase++;
        /* check leab128 overflow for uint32 value */
        if (recv_ctx.size_in_phase
            > (sizeof(section->section_body_size) * 8 + 7 - 1) / 7) {
            app_manager_printf("LEB overflow when parsing section size\n");
            SEND_ERR_RESPONSE(recv_ctx.message.request_mid,
                              "Install WASM app failed: "
                              "LEB overflow when parsing section size");
            goto fail;
        }

        if ((byte & 0x80) == 0) {
            /* leb128 encoded section size parsed done */
            if (!(section->section_body =
                      APP_MGR_MALLOC(section->section_body_size))) {
                app_manager_printf("Allocate memory failed!\n");
                SEND_ERR_RESPONSE(
                    recv_ctx.message.request_mid,
                    "Install WASM app failed: allocate memory failed");
                goto fail;
            }
            recv_ctx.phase = Phase_Wasm_Section_Content;
            recv_ctx.size_in_phase = 0;
        }

        return true;
    }
    else if (recv_ctx.phase == Phase_Wasm_Section_Content) {
        /* the last section is the current receiving one */
        wasm_section_t *section =
            recv_ctx.message.app_file.u.bytecode.section_end;

        bh_assert(section);

        section->section_body[recv_ctx.size_in_phase++] = ch;

        if (recv_ctx.size_in_phase == section->section_body_size) {
            if (recv_ctx.total_received_size == request_total_size) {
                /* whole wasm app received */
                if (module_wasm_app_handle_install_msg(&recv_ctx.message)) {
                    APP_MGR_FREE(recv_ctx.message.request_url);
                    recv_ctx.message.request_url = NULL;
                    memset(&recv_ctx, 0, sizeof(recv_ctx));
                    return true;
                }
                else {
                    app_manager_printf("Handle install message failed!\n");
                    SEND_ERR_RESPONSE(recv_ctx.message.request_mid,
                                      "Install WASM app failed: "
                                      "handle install message failed");
                    /**
                     * The sections were destroyed inside
                     * module_wasm_app_handle_install_msg(),
                     * no need to destroy again.
                     */
                    return false;
                }
            }
            else {
                recv_ctx.phase = Phase_Wasm_Section_Type;
                recv_ctx.size_in_phase = 0;
                return true;
            }
        }

        return true;
    }
#endif /* end of WASM_ENABLE_INTERP != 0 || WASM_ENABLE_JIT != 0 */
#if WASM_ENABLE_AOT != 0
    else if (recv_ctx.phase == Phase_AOT_Version) {
        p = (uint8 *)&recv_ctx.message.app_file.u.aot.version;

        if (ch == wasm_aot_version[recv_ctx.size_in_phase])
            p[recv_ctx.size_in_phase++] = ch;
        else {
            app_manager_printf("Invalid AOT version!\n");
            SEND_ERR_RESPONSE(recv_ctx.message.request_mid,
                              "Install WASM app failed: invalid AOT version");
            goto fail;
        }

        if (recv_ctx.size_in_phase
            == sizeof(recv_ctx.message.app_file.u.aot.version)) {
            recv_ctx.phase = Phase_AOT_Section_ID;
            recv_ctx.size_in_phase = 0;
        }
        return true;
    }
    else if (recv_ctx.phase == Phase_AOT_Section_ID) {
        aot_section_t *cur_section;
        uint32 aot_file_cur_offset =
            recv_ctx.total_received_size - 1
            - 18 /* Request fixed part */ - recv_ctx.message.request_url_len;

        if (recv_ctx.size_in_phase == 0) {
            /* Skip paddings */
            if (aot_file_cur_offset % 4)
                return true;

            if (!(cur_section =
                      (aot_section_t *)APP_MGR_MALLOC(sizeof(aot_section_t)))) {
                app_manager_printf("Allocate memory failed!\n");
                SEND_ERR_RESPONSE(recv_ctx.message.request_mid,
                                  "Install WASM app failed: "
                                  "allocate memory failed");
                goto fail;
            }
            memset(cur_section, 0, sizeof(aot_section_t));

            /* add the section to tail of link list */
            if (NULL == recv_ctx.message.app_file.u.aot.sections) {
                recv_ctx.message.app_file.u.aot.sections = cur_section;
                recv_ctx.message.app_file.u.aot.section_end = cur_section;
            }
            else {
                recv_ctx.message.app_file.u.aot.section_end->next = cur_section;
                recv_ctx.message.app_file.u.aot.section_end = cur_section;
            }
        }
        else {
            cur_section = recv_ctx.message.app_file.u.aot.section_end;
            bh_assert(cur_section);
        }

        p = (uint8 *)&cur_section->section_type;
        p[recv_ctx.size_in_phase++] = ch;
        if (recv_ctx.size_in_phase == sizeof(cur_section->section_type)) {
            /* Notes: integers are always little endian encoded in AOT file */
            if (!is_little_endian())
                exchange_uint32(p);
            if (cur_section->section_type < AOT_SECTION_TYPE_SIGANATURE
                || cur_section->section_type == AOT_SECTION_TYPE_CUSTOM) {
                recv_ctx.phase = Phase_AOT_Section_Size;
                recv_ctx.size_in_phase = 0;
            }
            else {
                char error_buf[128];

                app_manager_printf("Invalid AOT section id: %d\n",
                                   cur_section->section_type);
                snprintf(error_buf, sizeof(error_buf),
                         "Install WASM app failed: invalid AOT section id %d",
                         cur_section->section_type);
                SEND_ERR_RESPONSE(recv_ctx.message.request_mid, error_buf);
                goto fail;
            }
        }

        return true;
    }
    else if (recv_ctx.phase == Phase_AOT_Section_Size) {
        /* the last section is the current receiving one */
        aot_section_t *section = recv_ctx.message.app_file.u.aot.section_end;
        bh_assert(section);

        p = (uint8 *)&section->section_body_size;
        p[recv_ctx.size_in_phase++] = ch;
        if (recv_ctx.size_in_phase == sizeof(section->section_body_size)) {
            /* Notes: integers are always little endian encoded in AOT file */
            if (!is_little_endian())
                exchange_uint32(p);
            /* Allocate memory for section body */
            if (section->section_body_size > 0) {
                if (section->section_type == AOT_SECTION_TYPE_TEXT) {
                    int map_prot =
                        MMAP_PROT_READ | MMAP_PROT_WRITE | MMAP_PROT_EXEC;
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64) \
    || defined(BUILD_TARGET_RISCV64_LP64D)                       \
    || defined(BUILD_TARGET_RISCV64_LP64)
                    /* aot code and data in x86_64 must be in range 0 to 2G due
                       to relocation for R_X86_64_32/32S/PC32 */
                    int map_flags = MMAP_MAP_32BIT;
#else
                    int map_flags = MMAP_MAP_NONE;
#endif
                    uint64 total_size = (uint64)section->section_body_size
                                        + aot_get_plt_table_size();
                    total_size = (total_size + 3) & ~((uint64)3);
                    if (total_size >= UINT32_MAX
                        || !(section->section_body =
                                 os_mmap(NULL, (uint32)total_size, map_prot,
                                         map_flags, os_get_invalid_handle()))) {
                        app_manager_printf(
                            "Allocate executable memory failed!\n");
                        SEND_ERR_RESPONSE(recv_ctx.message.request_mid,
                                          "Install WASM app failed: "
                                          "allocate memory failed");
                        goto fail;
                    }
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64)
                    /* address must be in the first 2 Gigabytes of
                       the process address space */
                    bh_assert((uintptr_t)section->section_body < INT32_MAX);
#endif
                }
                else {
                    if (!(section->section_body =
                              APP_MGR_MALLOC(section->section_body_size))) {
                        app_manager_printf("Allocate memory failed!\n");
                        SEND_ERR_RESPONSE(recv_ctx.message.request_mid,
                                          "Install WASM app failed: "
                                          "allocate memory failed");
                        goto fail;
                    }
                }
            }

            recv_ctx.phase = Phase_AOT_Section_Content;
            recv_ctx.size_in_phase = 0;
        }

        return true;
    }
    else if (recv_ctx.phase == Phase_AOT_Section_Content) {
        /* the last section is the current receiving one */
        aot_section_t *section = recv_ctx.message.app_file.u.aot.section_end;
        bh_assert(section && section->section_body);

        section->section_body[recv_ctx.size_in_phase++] = ch;

        if (recv_ctx.size_in_phase == section->section_body_size) {
            if (section->section_type == AOT_SECTION_TYPE_TEXT) {
                uint32 total_size =
                    section->section_body_size + aot_get_plt_table_size();
                total_size = (total_size + 3) & ~3;
                if (total_size > section->section_body_size) {
                    memset(section->section_body + section->section_body_size,
                           0, total_size - section->section_body_size);
                    section->section_body_size = total_size;
                }
            }
            if (recv_ctx.total_received_size == request_total_size) {
                /* whole aot file received */
                if (module_wasm_app_handle_install_msg(&recv_ctx.message)) {
                    APP_MGR_FREE(recv_ctx.message.request_url);
                    recv_ctx.message.request_url = NULL;
                    memset(&recv_ctx, 0, sizeof(recv_ctx));
                    return true;
                }
                else {
                    app_manager_printf("Handle install message failed!\n");
                    SEND_ERR_RESPONSE(recv_ctx.message.request_mid,
                                      "Install WASM app failed: "
                                      "handle install message failed");
                    /**
                     * The sections were destroyed inside
                     * module_wasm_app_handle_install_msg(),
                     * no need to destroy again.
                     */
                    return false;
                }
            }
            else {
                recv_ctx.phase = Phase_AOT_Section_ID;
                recv_ctx.size_in_phase = 0;
                return true;
            }
        }

        return true;
    }
#endif /* end of WASM_ENABLE_AOT != 0 */

fail:
    /* Restore the package type */
    magic = recv_ctx.message.app_file_magic;
    package_type = get_package_type((uint8 *)&magic, sizeof(magic) + 1);
    switch (package_type) {
#if WASM_ENABLE_INTERP != 0 || WASM_ENABLE_JIT != 0
        case Wasm_Module_Bytecode:
            destroy_all_wasm_sections(
                recv_ctx.message.app_file.u.bytecode.sections);
            break;
#endif
#if WASM_ENABLE_AOT != 0
        case Wasm_Module_AoT:
            destroy_all_aot_sections(recv_ctx.message.app_file.u.aot.sections);
            break;
#endif
        default:
            break;
    }

    if (recv_ctx.message.request_url != NULL) {
        APP_MGR_FREE(recv_ctx.message.request_url);
        recv_ctx.message.request_url = NULL;
    }

    memset(&recv_ctx, 0, sizeof(recv_ctx));
    return false;
}

static bool
module_wasm_app_handle_install_msg(install_wasm_app_msg_t *message)
{
    request_t *request = NULL;
    bh_message_t msg;

    request = (request_t *)APP_MGR_MALLOC(sizeof(request_t));
    if (request == NULL)
        return false;

    memset(request, 0, sizeof(*request));
    request->action = message->request_action;
    request->fmt = message->request_fmt;
    request->url = bh_strdup(message->request_url);
    request->sender = ID_HOST;
    request->mid = message->request_mid;
    request->payload_len = sizeof(message->app_file);
    request->payload = APP_MGR_MALLOC(request->payload_len);

    if (request->url == NULL || request->payload == NULL) {
        request_cleaner(request);
        return false;
    }

    /* Request payload is set to wasm_app_file_t struct,
     * but not whole app buffer */
    bh_memcpy_s(request->payload, request->payload_len, &message->app_file,
                request->payload_len);

    /* Since it's a wasm app install request, so directly post to app-mgr's
     * queue. The benefit is that section list can be freed when the msg
     * failed to post to app-mgr's queue. The defect is missing url check. */
    if (!(msg = bh_new_msg(RESTFUL_REQUEST, request, sizeof(*request),
                           request_cleaner))) {
        request_cleaner(request);
        return false;
    }

    if (!bh_post_msg2(get_app_manager_queue(), msg))
        return false;

    return true;
}

#if WASM_ENABLE_INTERP != 0 || WASM_ENABLE_JIT != 0
static void
destroy_all_wasm_sections(wasm_section_list_t sections)
{
    wasm_section_t *cur = sections;
    while (cur) {
        wasm_section_t *next = cur->next;
        if (cur->section_body != NULL)
            APP_MGR_FREE(cur->section_body);
        APP_MGR_FREE(cur);
        cur = next;
    }
}

static void
destroy_part_wasm_sections(wasm_section_list_t *p_sections,
                           uint8 *section_types, int section_cnt)
{
    int i;
    for (i = 0; i < section_cnt; i++) {
        uint8 section_type = section_types[i];
        wasm_section_t *cur = *p_sections, *prev = NULL;

        while (cur) {
            wasm_section_t *next = cur->next;
            if (cur->section_type == section_type) {
                if (prev)
                    prev->next = next;
                else
                    *p_sections = next;

                if (cur->section_body != NULL)
                    APP_MGR_FREE(cur->section_body);
                APP_MGR_FREE(cur);
                break;
            }
            else {
                prev = cur;
                cur = next;
            }
        }
    }
}
#endif

#if WASM_ENABLE_AOT != 0
static void
destroy_all_aot_sections(aot_section_list_t sections)
{
    aot_section_t *cur = sections;
    while (cur) {
        aot_section_t *next = cur->next;
        if (cur->section_body != NULL) {
            if (cur->section_type == AOT_SECTION_TYPE_TEXT)
                os_munmap(cur->section_body, cur->section_body_size);
            else
                APP_MGR_FREE(cur->section_body);
        }
        APP_MGR_FREE(cur);
        cur = next;
    }
}

static void
destroy_part_aot_sections(aot_section_list_t *p_sections, uint8 *section_types,
                          int section_cnt)
{
    int i;
    for (i = 0; i < section_cnt; i++) {
        uint8 section_type = section_types[i];
        aot_section_t *cur = *p_sections, *prev = NULL;

        while (cur) {
            aot_section_t *next = cur->next;
            if (cur->section_type == section_type) {
                if (prev)
                    prev->next = next;
                else
                    *p_sections = next;

                if (cur->section_body != NULL) {
                    if (cur->section_type == AOT_SECTION_TYPE_TEXT)
                        os_munmap(cur->section_body, cur->section_body_size);
                    else
                        APP_MGR_FREE(cur->section_body);
                }
                APP_MGR_FREE(cur);
                break;
            }
            else {
                prev = cur;
                cur = next;
            }
        }
    }
}
#endif

#if WASM_ENABLE_LIBC_WASI != 0
static char wasi_root_dir[PATH_MAX] = { '.' };

bool
wasm_set_wasi_root_dir(const char *root_dir)
{
    char *path, resolved_path[PATH_MAX];

    if (!(path = realpath(root_dir, resolved_path)))
        return false;

    snprintf(wasi_root_dir, sizeof(wasi_root_dir), "%s", path);
    return true;
}

const char *
wasm_get_wasi_root_dir()
{
    return wasi_root_dir;
}
#endif
