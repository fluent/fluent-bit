/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>

#include "wasi_nn_private.h"
#include "utils/wasi_nn_app_native.h"
#include "utils/logger.h"

#include "bh_platform.h"
#include "wasi_nn_types.h"
#include "wasm_export.h"

#if WASM_ENABLE_WASI_EPHEMERAL_NN == 0
#warning You are using "wasi_nn", which is a legacy WAMR-specific ABI. It's deperecated and will likely be removed in future versions of WAMR. Please use "wasi_ephemeral_nn" instead. (For a WASM module, use the wasi_ephemeral_nn.h header instead. For the runtime configurations, enable WASM_ENABLE_WASI_EPHEMERAL_NN/WAMR_BUILD_WASI_EPHEMERAL_NN.)
#endif

#define HASHMAP_INITIAL_SIZE 20
#if defined(__APPLE__)
#define LIB_EXTENTION ".dylib"
#else
#define LIB_EXTENTION ".so"
#endif
#define TFLITE_BACKEND_LIB "libwasi_nn_tflite" LIB_EXTENTION
#define OPENVINO_BACKEND_LIB "libwasi_nn_openvino" LIB_EXTENTION
#define LLAMACPP_BACKEND_LIB "libwasi_nn_llamacpp" LIB_EXTENTION

/* Global variables */
static korp_mutex wasi_nn_lock;
/*
 * the "lookup" table is protected by wasi_nn_lock.
 *
 * an exception: during wasm_runtime_destroy, wasi_nn_destroy tears down
 * the table without acquiring the lock. it's ok because there should be
 * no other threads using the runtime at this point.
 */
struct backends_api_functions {
    void *backend_handle;
    api_function functions;
} lookup[autodetect + 1] = { 0 };

#define call_wasi_nn_func(backend_encoding, func, wasi_error, ...)         \
    do {                                                                   \
        wasi_error = lookup[backend_encoding].functions.func(__VA_ARGS__); \
        if (wasi_error != success)                                         \
            NN_ERR_PRINTF("Error %s() -> %d", #func, wasi_error);          \
    } while (0)

static void *wasi_nn_key;

static void
wasi_nn_ctx_destroy(WASINNContext *wasi_nn_ctx)
{
    if (wasi_nn_ctx == NULL) {
        return;
    }
    NN_DBG_PRINTF("[WASI NN] DEINIT...");
    NN_DBG_PRINTF("Freeing wasi-nn");
    NN_DBG_PRINTF("-> is_model_loaded: %d", wasi_nn_ctx->is_model_loaded);
    NN_DBG_PRINTF("-> current_encoding: %d", wasi_nn_ctx->backend);

    bh_assert(!wasi_nn_ctx->busy);

    /* deinit() the backend */
    if (wasi_nn_ctx->is_backend_ctx_initialized) {
        wasi_nn_error res;
        call_wasi_nn_func(wasi_nn_ctx->backend, deinit, res,
                          wasi_nn_ctx->backend_ctx);
    }

    os_mutex_destroy(&wasi_nn_ctx->lock);
    wasm_runtime_free(wasi_nn_ctx);
}

static void
dtor(wasm_module_inst_t inst, void *ctx)
{
    wasi_nn_ctx_destroy(ctx);
}

bool
wasi_nn_initialize()
{
    NN_DBG_PRINTF("[WASI NN General] Initializing wasi-nn");

    if (os_mutex_init(&wasi_nn_lock)) {
        NN_ERR_PRINTF("Error while initializing global lock");
        return false;
    }

    wasi_nn_key = wasm_runtime_create_context_key(dtor);
    if (wasi_nn_key == NULL) {
        NN_ERR_PRINTF("Failed to create context key");
        os_mutex_destroy(&wasi_nn_lock);
        return false;
    }

    return true;
}

static WASINNContext *
wasi_nn_initialize_context()
{
    NN_DBG_PRINTF("[WASI NN] INIT...");

    WASINNContext *wasi_nn_ctx =
        (WASINNContext *)wasm_runtime_malloc(sizeof(WASINNContext));
    if (wasi_nn_ctx == NULL) {
        NN_ERR_PRINTF("Error when allocating memory for WASI-NN context");
        return NULL;
    }

    memset(wasi_nn_ctx, 0, sizeof(WASINNContext));
    if (os_mutex_init(&wasi_nn_ctx->lock)) {
        NN_ERR_PRINTF("Error when initializing a lock for WASI-NN context");
        wasm_runtime_free(wasi_nn_ctx);
        return NULL;
    }
    return wasi_nn_ctx;
}

/* Get wasi-nn context from module instance */
static WASINNContext *
wasm_runtime_get_wasi_nn_ctx(wasm_module_inst_t instance)
{
    WASINNContext *wasi_nn_ctx =
        wasm_runtime_get_context(instance, wasi_nn_key);
    if (wasi_nn_ctx == NULL) {
        WASINNContext *newctx = wasi_nn_initialize_context();
        if (newctx == NULL)
            return NULL;
        os_mutex_lock(&wasi_nn_lock);
        wasi_nn_ctx = wasm_runtime_get_context(instance, wasi_nn_key);
        if (wasi_nn_ctx == NULL) {
            wasm_runtime_set_context_spread(instance, wasi_nn_key, newctx);
            wasi_nn_ctx = newctx;
            newctx = NULL;
        }
        os_mutex_unlock(&wasi_nn_lock);
        if (newctx != NULL) {
            wasi_nn_ctx_destroy(newctx);
        }
    }
    return wasi_nn_ctx;
}

static WASINNContext *
lock_ctx(wasm_module_inst_t instance)
{
    WASINNContext *wasi_nn_ctx = wasm_runtime_get_wasi_nn_ctx(instance);
    if (wasi_nn_ctx == NULL) {
        return NULL;
    }
    os_mutex_lock(&wasi_nn_ctx->lock);
    if (wasi_nn_ctx->busy) {
        os_mutex_unlock(&wasi_nn_ctx->lock);
        return NULL;
    }
    wasi_nn_ctx->busy = true;
    os_mutex_unlock(&wasi_nn_ctx->lock);
    return wasi_nn_ctx;
}

static void
unlock_ctx(WASINNContext *wasi_nn_ctx)
{
    if (wasi_nn_ctx == NULL) {
        return;
    }
    os_mutex_lock(&wasi_nn_ctx->lock);
    bh_assert(wasi_nn_ctx->busy);
    wasi_nn_ctx->busy = false;
    os_mutex_unlock(&wasi_nn_ctx->lock);
}

void
wasi_nn_destroy()
{
    wasm_runtime_destroy_context_key(wasi_nn_key);

    // close backends' libraries and registered functions
    for (unsigned i = 0; i < sizeof(lookup) / sizeof(lookup[0]); i++) {
        if (lookup[i].backend_handle) {
            dlclose(lookup[i].backend_handle);
            lookup[i].backend_handle = NULL;
        }

        memset(&lookup[i].functions, 0, sizeof(api_function));
    }

    os_mutex_destroy(&wasi_nn_lock);
}

/* Utils */
static wasi_nn_error
is_model_initialized(WASINNContext *wasi_nn_ctx)
{
    if (!wasi_nn_ctx->is_model_loaded) {
        NN_ERR_PRINTF("Model not initialized.");
        return runtime_error;
    }
    return success;
}

/*
 *TODO: choose a proper backend based on
 * - hardware
 * - model file format
 * - on device ML framework
 */
static graph_encoding
choose_a_backend()
{
    void *handle;

    handle = dlopen(LLAMACPP_BACKEND_LIB, RTLD_LAZY);
    if (handle) {
        NN_INFO_PRINTF("Using llama.cpp backend");
        dlclose(handle);
        return ggml;
    }

#ifndef NDEBUG
    NN_WARN_PRINTF("%s", dlerror());
#endif

    handle = dlopen(OPENVINO_BACKEND_LIB, RTLD_LAZY);
    if (handle) {
        NN_INFO_PRINTF("Using openvino backend");
        dlclose(handle);
        return openvino;
    }

#ifndef NDEBUG
    NN_WARN_PRINTF("%s", dlerror());
#endif

    handle = dlopen(TFLITE_BACKEND_LIB, RTLD_LAZY);
    if (handle) {
        NN_INFO_PRINTF("Using tflite backend");
        dlclose(handle);
        return tensorflowlite;
    }

#ifndef NDEBUG
    NN_WARN_PRINTF("%s", dlerror());
#endif

    NN_WARN_PRINTF("No backend found");
    return unknown_backend;
}

static bool
register_backend(void *handle, api_function *functions)
{
    BACKEND_INITIALIZE init = (BACKEND_INITIALIZE)dlsym(handle, "init_backend");
    if (!init) {
        NN_WARN_PRINTF("init_backend() not found");
        return false;
    }
    functions->init = init;

    BACKEND_DEINITIALIZE deinit =
        (BACKEND_DEINITIALIZE)dlsym(handle, "deinit_backend");
    if (!deinit) {
        NN_WARN_PRINTF("deinit_backend() not found");
        return false;
    }
    functions->deinit = deinit;

    LOAD load = (LOAD)dlsym(handle, "load");
    if (!load) {
        NN_WARN_PRINTF("load() not found");
        return false;
    }
    functions->load = load;

    LOAD_BY_NAME load_by_name = (LOAD_BY_NAME)dlsym(handle, "load_by_name");
    if (!load_by_name) {
        NN_WARN_PRINTF("load_by_name() not found");
        return false;
    }
    functions->load_by_name = load_by_name;

    LOAD_BY_NAME_WITH_CONFIG load_by_name_with_config =
        (LOAD_BY_NAME_WITH_CONFIG)dlsym(handle, "load_by_name_with_config");
    if (!load_by_name_with_config) {
        NN_WARN_PRINTF("load_by_name_with_config() not found");
        // since only llama.cpp backend need to support this function
    }
    functions->load_by_name_with_config = load_by_name_with_config;

    INIT_EXECUTION_CONTEXT init_execution_context =
        (INIT_EXECUTION_CONTEXT)dlsym(handle, "init_execution_context");
    if (!init_execution_context) {
        NN_WARN_PRINTF("init_execution_context() not found");
        return false;
    }
    functions->init_execution_context = init_execution_context;

    SET_INPUT set_input = (SET_INPUT)dlsym(handle, "set_input");
    if (!set_input) {
        NN_WARN_PRINTF("set_input() not found");
        return false;
    }
    functions->set_input = set_input;

    COMPUTE compute = (COMPUTE)dlsym(handle, "compute");
    if (!compute) {
        NN_WARN_PRINTF("compute() not found");
        return false;
    }
    functions->compute = compute;

    GET_OUTPUT get_output = (GET_OUTPUT)dlsym(handle, "get_output");
    if (!get_output) {
        NN_WARN_PRINTF("get_output() not found");
        return false;
    }
    functions->get_output = get_output;

    return true;
}

static bool
prepare_backend(const char *lib_name, struct backends_api_functions *backend)
{
    NN_DBG_PRINTF("[Native Register] prepare_backend %s", lib_name);

    void *handle;
    handle = dlopen(lib_name, RTLD_LAZY);
    if (!handle) {
        NN_ERR_PRINTF("Error loading %s. %s", lib_name, dlerror());
        return false;
    }

    if (!register_backend(handle, &(backend->functions))) {
        NN_ERR_PRINTF("Error when registering functions of %s", lib_name);
        dlclose(handle);
        return false;
    }

    backend->backend_handle = handle;
    return true;
}

static const char *
graph_encoding_to_backend_lib_name(graph_encoding encoding)
{
    switch (encoding) {
        case openvino:
            return OPENVINO_BACKEND_LIB;
        case tensorflowlite:
            return TFLITE_BACKEND_LIB;
        case ggml:
            return LLAMACPP_BACKEND_LIB;
        default:
            return NULL;
    }
}

static bool
detect_and_load_backend(graph_encoding backend_hint,
                        graph_encoding *loaded_backend)
{
    bool ret;

    if (backend_hint > autodetect)
        return false;

    if (backend_hint == autodetect)
        backend_hint = choose_a_backend();

    if (backend_hint == unknown_backend)
        return false;

    *loaded_backend = backend_hint;

    os_mutex_lock(&wasi_nn_lock);
    /* if already loaded */
    if (lookup[backend_hint].backend_handle) {
        os_mutex_unlock(&wasi_nn_lock);
        return true;
    }

    const char *backend_lib_name =
        graph_encoding_to_backend_lib_name(backend_hint);
    if (!backend_lib_name) {
        os_mutex_unlock(&wasi_nn_lock);
        return false;
    }

    ret = prepare_backend(backend_lib_name, lookup + backend_hint);
    os_mutex_unlock(&wasi_nn_lock);
    return ret;
}

static wasi_nn_error
ensure_backend(wasm_module_inst_t instance, graph_encoding encoding,
               WASINNContext *wasi_nn_ctx)
{
    wasi_nn_error res;

    graph_encoding loaded_backend = autodetect;
    if (!detect_and_load_backend(encoding, &loaded_backend)) {
        res = invalid_encoding;
        NN_ERR_PRINTF("load backend failed");
        goto fail;
    }

    if (wasi_nn_ctx->is_backend_ctx_initialized) {
        if (wasi_nn_ctx->backend != loaded_backend) {
            res = unsupported_operation;
            goto fail;
        }
    }
    else {
        wasi_nn_ctx->backend = loaded_backend;

        /* init() the backend */
        call_wasi_nn_func(wasi_nn_ctx->backend, init, res,
                          &wasi_nn_ctx->backend_ctx);
        if (res != success)
            goto fail;

        wasi_nn_ctx->is_backend_ctx_initialized = true;
    }
    return success;
fail:
    return res;
}

/* WASI-NN implementation */

#if WASM_ENABLE_WASI_EPHEMERAL_NN != 0
wasi_nn_error
wasi_nn_load(wasm_exec_env_t exec_env, graph_builder_wasm *builder,
             uint32_t builder_wasm_size, graph_encoding encoding,
             execution_target target, graph *g)
#else  /* WASM_ENABLE_WASI_EPHEMERAL_NN == 0 */
wasi_nn_error
wasi_nn_load(wasm_exec_env_t exec_env, graph_builder_array_wasm *builder,
             graph_encoding encoding, execution_target target, graph *g)
#endif /* WASM_ENABLE_WASI_EPHEMERAL_NN != 0 */
{
    wasi_nn_error res;

    NN_DBG_PRINTF("[WASI NN] LOAD [encoding=%d, target=%d]...", encoding,
                  target);

    wasm_module_inst_t instance = wasm_runtime_get_module_inst(exec_env);
    if (!instance)
        return runtime_error;

    WASINNContext *wasi_nn_ctx = lock_ctx(instance);
    if (wasi_nn_ctx == NULL) {
        res = busy;
        goto fail;
    }

    graph_builder_array builder_native = { 0 };
#if WASM_ENABLE_WASI_EPHEMERAL_NN != 0
    if (success
        != (res = graph_builder_array_app_native(
                instance, builder, builder_wasm_size, &builder_native)))
        goto fail;
#else  /* WASM_ENABLE_WASI_EPHEMERAL_NN == 0 */
    if (success
        != (res = graph_builder_array_app_native(instance, builder,
                                                 &builder_native)))
        goto fail;
#endif /* WASM_ENABLE_WASI_EPHEMERAL_NN != 0 */

    if (!wasm_runtime_validate_native_addr(instance, g,
                                           (uint64)sizeof(graph))) {
        NN_ERR_PRINTF("graph is invalid");
        res = invalid_argument;
        goto fail;
    }

    res = ensure_backend(instance, encoding, wasi_nn_ctx);
    if (res != success)
        goto fail;

    call_wasi_nn_func(wasi_nn_ctx->backend, load, res, wasi_nn_ctx->backend_ctx,
                      &builder_native, encoding, target, g);
    if (res != success)
        goto fail;

    wasi_nn_ctx->is_model_loaded = true;

fail:
    // XXX: Free intermediate structure pointers
    if (builder_native.buf)
        wasm_runtime_free(builder_native.buf);
    unlock_ctx(wasi_nn_ctx);

    return res;
}

wasi_nn_error
wasi_nn_load_by_name(wasm_exec_env_t exec_env, char *name, uint32_t name_len,
                     graph *g)
{
    wasi_nn_error res;

    wasm_module_inst_t instance = wasm_runtime_get_module_inst(exec_env);
    if (!instance) {
        return runtime_error;
    }

    if (!wasm_runtime_validate_native_addr(instance, name, name_len)) {
        NN_ERR_PRINTF("name is invalid");
        return invalid_argument;
    }

    if (!wasm_runtime_validate_native_addr(instance, g,
                                           (uint64)sizeof(graph))) {
        NN_ERR_PRINTF("graph is invalid");
        return invalid_argument;
    }

    if (name_len == 0 || name[name_len] != '\0') {
        NN_ERR_PRINTF("Invalid filename");
        return invalid_argument;
    }

    NN_DBG_PRINTF("[WASI NN] LOAD_BY_NAME %s...", name);

    WASINNContext *wasi_nn_ctx = lock_ctx(instance);
    if (wasi_nn_ctx == NULL) {
        res = busy;
        goto fail;
    }

    res = ensure_backend(instance, autodetect, wasi_nn_ctx);
    if (res != success)
        goto fail;

    call_wasi_nn_func(wasi_nn_ctx->backend, load_by_name, res,
                      wasi_nn_ctx->backend_ctx, name, name_len, g);
    if (res != success)
        goto fail;

    wasi_nn_ctx->is_model_loaded = true;
    res = success;
fail:
    unlock_ctx(wasi_nn_ctx);
    return res;
}

wasi_nn_error
wasi_nn_load_by_name_with_config(wasm_exec_env_t exec_env, char *name,
                                 int32_t name_len, char *config,
                                 int32_t config_len, graph *g)
{
    wasi_nn_error res;

    wasm_module_inst_t instance = wasm_runtime_get_module_inst(exec_env);
    if (!instance) {
        return runtime_error;
    }

    if (!wasm_runtime_validate_native_addr(instance, name, name_len)) {
        NN_ERR_PRINTF("name is invalid");
        return invalid_argument;
    }

    if (!wasm_runtime_validate_native_addr(instance, g,
                                           (uint64)sizeof(graph))) {
        NN_ERR_PRINTF("graph is invalid");
        return invalid_argument;
    }

    if (name_len == 0 || name[name_len] != '\0') {
        NN_ERR_PRINTF("Invalid filename");
        return invalid_argument;
    }

    if (!config || config_len == 0 || config[config_len] != '\0') {
        NN_ERR_PRINTF("Invalid config");
        return invalid_argument;
    }

    NN_DBG_PRINTF("[WASI NN] LOAD_BY_NAME_WITH_CONFIG %s %s...", name, config);

    WASINNContext *wasi_nn_ctx = lock_ctx(instance);
    if (wasi_nn_ctx == NULL) {
        res = busy;
        goto fail;
    }

    res = ensure_backend(instance, autodetect, wasi_nn_ctx);
    if (res != success)
        goto fail;
    ;

    call_wasi_nn_func(wasi_nn_ctx->backend, load_by_name_with_config, res,
                      wasi_nn_ctx->backend_ctx, name, name_len, config,
                      config_len, g);
    if (res != success)
        goto fail;

    wasi_nn_ctx->is_model_loaded = true;
    res = success;
fail:
    unlock_ctx(wasi_nn_ctx);
    return res;
}

wasi_nn_error
wasi_nn_init_execution_context(wasm_exec_env_t exec_env, graph g,
                               graph_execution_context *ctx)
{
    NN_DBG_PRINTF("[WASI NN] INIT_EXECUTION_CONTEXT...");

    wasm_module_inst_t instance = wasm_runtime_get_module_inst(exec_env);
    if (!instance) {
        return runtime_error;
    }

    wasi_nn_error res;
    WASINNContext *wasi_nn_ctx = lock_ctx(instance);
    if (wasi_nn_ctx == NULL) {
        res = busy;
        goto fail;
    }

    if (success != (res = is_model_initialized(wasi_nn_ctx)))
        goto fail;

    if (!wasm_runtime_validate_native_addr(
            instance, ctx, (uint64)sizeof(graph_execution_context))) {
        NN_ERR_PRINTF("ctx is invalid");
        res = invalid_argument;
        goto fail;
    }

    call_wasi_nn_func(wasi_nn_ctx->backend, init_execution_context, res,
                      wasi_nn_ctx->backend_ctx, g, ctx);
fail:
    unlock_ctx(wasi_nn_ctx);
    return res;
}

wasi_nn_error
wasi_nn_set_input(wasm_exec_env_t exec_env, graph_execution_context ctx,
                  uint32_t index, tensor_wasm *input_tensor)
{
    NN_DBG_PRINTF("[WASI NN] SET_INPUT [ctx=%d, index=%d]...", ctx, index);

    wasm_module_inst_t instance = wasm_runtime_get_module_inst(exec_env);
    if (!instance) {
        return runtime_error;
    }

    wasi_nn_error res;
    WASINNContext *wasi_nn_ctx = lock_ctx(instance);
    if (wasi_nn_ctx == NULL) {
        res = busy;
        goto fail;
    }

    if (success != (res = is_model_initialized(wasi_nn_ctx)))
        goto fail;

    tensor input_tensor_native = { 0 };
    if (success
        != (res = tensor_app_native(instance, input_tensor,
                                    &input_tensor_native)))
        goto fail;

    call_wasi_nn_func(wasi_nn_ctx->backend, set_input, res,
                      wasi_nn_ctx->backend_ctx, ctx, index,
                      &input_tensor_native);
    // XXX: Free intermediate structure pointers
    if (input_tensor_native.dimensions)
        wasm_runtime_free(input_tensor_native.dimensions);
fail:
    unlock_ctx(wasi_nn_ctx);
    return res;
}

wasi_nn_error
wasi_nn_compute(wasm_exec_env_t exec_env, graph_execution_context ctx)
{
    NN_DBG_PRINTF("[WASI NN] COMPUTE [ctx=%d]...", ctx);

    wasm_module_inst_t instance = wasm_runtime_get_module_inst(exec_env);
    if (!instance) {
        return runtime_error;
    }

    wasi_nn_error res;
    WASINNContext *wasi_nn_ctx = lock_ctx(instance);
    if (wasi_nn_ctx == NULL) {
        res = busy;
        goto fail;
    }

    if (success != (res = is_model_initialized(wasi_nn_ctx)))
        goto fail;

    call_wasi_nn_func(wasi_nn_ctx->backend, compute, res,
                      wasi_nn_ctx->backend_ctx, ctx);
fail:
    unlock_ctx(wasi_nn_ctx);
    return res;
}

#if WASM_ENABLE_WASI_EPHEMERAL_NN != 0
wasi_nn_error
wasi_nn_get_output(wasm_exec_env_t exec_env, graph_execution_context ctx,
                   uint32_t index, void *output_tensor,
                   uint32_t output_tensor_len, uint32_t *output_tensor_size)
#else  /* WASM_ENABLE_WASI_EPHEMERAL_NN == 0 */
wasi_nn_error
wasi_nn_get_output(wasm_exec_env_t exec_env, graph_execution_context ctx,
                   uint32_t index, void *output_tensor,
                   uint32_t *output_tensor_size)
#endif /* WASM_ENABLE_WASI_EPHEMERAL_NN != 0 */
{
    NN_DBG_PRINTF("[WASI NN] GET_OUTPUT [ctx=%d, index=%d]...", ctx, index);

    wasm_module_inst_t instance = wasm_runtime_get_module_inst(exec_env);
    if (!instance) {
        return runtime_error;
    }

    wasi_nn_error res;
    WASINNContext *wasi_nn_ctx = lock_ctx(instance);
    if (wasi_nn_ctx == NULL) {
        res = busy;
        goto fail;
    }

    if (success != (res = is_model_initialized(wasi_nn_ctx)))
        goto fail;

    if (!wasm_runtime_validate_native_addr(instance, output_tensor_size,
                                           (uint64)sizeof(uint32_t))) {
        NN_ERR_PRINTF("output_tensor_size is invalid");
        res = invalid_argument;
        goto fail;
    }

    tensor_data tensor = {
        .buf = output_tensor,
#if WASM_ENABLE_WASI_EPHEMERAL_NN != 0
        .size = output_tensor_len,
#else
        .size = *output_tensor_size,
#endif
    };
    call_wasi_nn_func(wasi_nn_ctx->backend, get_output, res,
                      wasi_nn_ctx->backend_ctx, ctx, index, &tensor,
                      output_tensor_size);
fail:
    unlock_ctx(wasi_nn_ctx);
    return res;
}

/* Register WASI-NN in WAMR */

/* clang-format off */
#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, wasi_nn_##func_name, signature, NULL }
/* clang-format on */

static NativeSymbol native_symbols_wasi_nn[] = {
#if WASM_ENABLE_WASI_EPHEMERAL_NN != 0
    REG_NATIVE_FUNC(load, "(*iii*)i"),
    REG_NATIVE_FUNC(load_by_name, "(*i*)i"),

    /* load_by_name_with_config is intented to be compatible with
     * a wasmedge extension.
     * https://github.com/second-state/wasmedge-wasi-nn/pull/2
     * https://github.com/WasmEdge/WasmEdge/blob/5553924e8cdccdc2cbd2a6a6d0ed9b11250c353e/plugins/wasi_nn/wasinnmodule.cpp#L13-L14
     */
    REG_NATIVE_FUNC(load_by_name_with_config, "(*i*i*)i"),
    REG_NATIVE_FUNC(init_execution_context, "(i*)i"),
    REG_NATIVE_FUNC(set_input, "(ii*)i"),
    REG_NATIVE_FUNC(compute, "(i)i"),
    REG_NATIVE_FUNC(get_output, "(ii*i*)i"),
#else  /* WASM_ENABLE_WASI_EPHEMERAL_NN == 0 */
    REG_NATIVE_FUNC(load, "(*ii*)i"),
    REG_NATIVE_FUNC(load_by_name, "(*i*)i"),
    REG_NATIVE_FUNC(init_execution_context, "(i*)i"),
    REG_NATIVE_FUNC(set_input, "(ii*)i"),
    REG_NATIVE_FUNC(compute, "(i)i"),
    REG_NATIVE_FUNC(get_output, "(ii**)i"),
#endif /* WASM_ENABLE_WASI_EPHEMERAL_NN != 0 */
};

uint32_t
get_wasi_nn_export_apis(NativeSymbol **p_native_symbols)
{
    *p_native_symbols = native_symbols_wasi_nn;
    return sizeof(native_symbols_wasi_nn) / sizeof(NativeSymbol);
}
