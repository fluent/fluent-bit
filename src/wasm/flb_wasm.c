/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

/* Don't use and expose bh_ prefixed headers in flb_wasm.h.
   Their definitions are tightly coupled in wasm-micro-runtime library. */
#include "bh_read_file.h"
#include "bh_getopt.h"

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/wasm/flb_wasm.h>

#ifdef FLB_SYSTEM_WINDOWS
#define STDIN_FILENO (_fileno( stdin ))
#define STDOUT_FILENO (_fileno( stdout ))
#define STDERR_FILENO (_fileno( stderr ))
#else
#include <unistd.h>
#endif

void flb_wasm_init(struct flb_config *config)
{
    wasm_runtime_init();
    mk_list_init(&config->wasm_list);
}

static int flb_wasm_load_wasm_binary(const char *wasm_path, int8_t **out_buf, uint32_t *out_size)
{
    char *buffer;
    uint32_t buf_size;
    buffer = bh_read_file_to_buffer(wasm_path, &buf_size);
    if (!buffer) {
        flb_error("Open wasm file [%s] failed.", wasm_path);
        goto error;
    }

    if ((get_package_type((const uint8_t *)buffer, buf_size) != Wasm_Module_Bytecode) &&
        (get_package_type((const uint8_t *)buffer, buf_size) != Wasm_Module_AoT)) {
        flb_error("WASM bytecode or AOT is expected but other file format");
        goto error;
    }

    *out_buf = buffer;
    *out_size = buf_size;

    return buffer != NULL;

error:

    return -1;
}

struct flb_wasm *flb_wasm_instantiate(struct flb_config *config, const char *wasm_path,
                                      struct mk_list *accessible_dir_list,
                                      int stdinfd, int stdoutfd, int stderrfd)
{
    struct flb_wasm *fw;
    uint32_t buf_size, stack_size = 8 * 1024, heap_size = 8 * 1024;
    int8_t *buffer = NULL;
    char error_buf[128];
#if WASM_ENABLE_LIBC_WASI != 0
    struct mk_list *head;
    struct flb_slist_entry *wasi_dir;
    const size_t accessible_dir_list_size = mk_list_size(accessible_dir_list);
    const char **wasi_dir_list = NULL;
    size_t dir_index = 0;
#endif

    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    wasm_exec_env_t exec_env = NULL;

    RuntimeInitArgs wasm_args;

    fw = flb_malloc(sizeof(struct flb_wasm));
    if (!fw) {
        flb_errno();
        return NULL;
    }

#if WASM_ENABLE_LIBC_WASI != 0
    wasi_dir_list = flb_malloc(sizeof(char *) * accessible_dir_list_size);
    if (!wasi_dir_list) {
        flb_errno();
        return NULL;
    }
    mk_list_foreach(head, accessible_dir_list) {
        wasi_dir = mk_list_entry(head, struct flb_slist_entry, _head);
        wasi_dir_list[dir_index] = wasi_dir->str;
        dir_index++;
    }
#endif

    fw->config = config;

    memset(&wasm_args, 0, sizeof(RuntimeInitArgs));

    wasm_args.mem_alloc_type = Alloc_With_Allocator;
    wasm_args.mem_alloc_option.allocator.malloc_func = flb_malloc;
    wasm_args.mem_alloc_option.allocator.realloc_func = flb_realloc;
    wasm_args.mem_alloc_option.allocator.free_func = flb_free;

    if (!wasm_runtime_full_init(&wasm_args)) {
        flb_error("Init runtime environment failed.");
        return NULL;
    }

    if(!flb_wasm_load_wasm_binary(wasm_path, &buffer, &buf_size)) {
        goto error;
    }

    module = wasm_runtime_load((uint8_t *)buffer, buf_size, error_buf, sizeof(error_buf));
    if (!module) {
        flb_error("Load wasm module failed. error: %s", error_buf);
        goto error;
    }

#if WASM_ENABLE_LIBC_WASI != 0
    wasm_runtime_set_wasi_args_ex(module, wasi_dir_list, accessible_dir_list_size, NULL, 0,
                                  NULL, 0, NULL, 0,
                                  (stdinfd != -1) ? stdinfd : STDIN_FILENO,
                                  (stdoutfd != -1) ? stdoutfd : STDOUT_FILENO,
                                  (stderrfd != -1) ? stderrfd : STDERR_FILENO);
#endif

    module_inst = wasm_runtime_instantiate(module, stack_size, heap_size,
                                           error_buf, sizeof(error_buf));
    if (!module_inst) {
        flb_error("Instantiate wasm module failed. error: %s", error_buf);
        goto error;
    }

    exec_env = wasm_runtime_create_exec_env(module_inst, stack_size);
    if (!exec_env) {
        flb_error("Create wasm execution environment failed.");
        goto error;
    }

    fw->buffer = buffer;
    fw->module = module;
    fw->module_inst = module_inst;
    fw->exec_env = exec_env;

    mk_list_add(&fw->_head, &config->wasm_list);

#if WASM_ENABLE_LIBC_WASI != 0
    flb_free(wasi_dir_list);
#endif

    return fw;

error:
#if WASM_ENABLE_LIBC_WASI != 0
    if (wasi_dir_list != NULL) {
        flb_free(wasi_dir_list);
    }
#endif
    if (exec_env) {
        wasm_runtime_destroy_exec_env(exec_env);
    }
    if (module_inst) {
        wasm_runtime_deinstantiate(module_inst);
    }
    if (module) {
        wasm_runtime_unload(module);
    }
    if (buffer != NULL) {
        BH_FREE(buffer);
    }

    wasm_runtime_destroy();

    return NULL;
}

int flb_wasm_call_wasi_main(struct flb_wasm *fw)
{
    wasm_function_inst_t func = NULL;

    if (!(func = wasm_runtime_lookup_wasi_start_function(fw->module_inst))) {
        flb_error("The wasi mode main function is not found.");
        return -1;
    }

    return wasm_runtime_call_wasm(fw->exec_env, func, 0, NULL);
}

void flb_wasm_destroy(struct flb_wasm *fw)
{
    if (fw->exec_env) {
        wasm_runtime_destroy_exec_env(fw->exec_env);
    }
    if (fw->module_inst) {
        if (fw->wasm_buffer) {
            wasm_runtime_module_free(fw->module_inst, fw->wasm_buffer);
        }
        wasm_runtime_deinstantiate(fw->module_inst);
    }
    if (fw->module) {
        wasm_runtime_unload(fw->module);
    }
    if (fw->buffer) {
        BH_FREE(fw->buffer);
    }
    wasm_runtime_destroy();

    mk_list_del(&fw->_head);
    flb_free(fw);
}

int flb_wasm_destroy_all(struct flb_config *ctx)
{
    int c = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_wasm *fw;

    mk_list_foreach_safe(head, tmp, &ctx->wasm_list) {
        fw = mk_list_entry(head, struct flb_wasm, _head);
        flb_wasm_destroy(fw);
        c++;
    }

    return c;
}
