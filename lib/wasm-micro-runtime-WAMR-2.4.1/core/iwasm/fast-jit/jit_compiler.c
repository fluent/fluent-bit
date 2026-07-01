/*
 * Copyright (C) 2021 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "jit_compiler.h"
#include "jit_ir.h"
#include "jit_codegen.h"
#include "jit_codecache.h"
#include "../interpreter/wasm.h"

typedef struct JitCompilerPass {
    /* Name of the pass */
    const char *name;
    /* The entry of the compiler pass */
    bool (*run)(JitCompContext *cc);
} JitCompilerPass;

/* clang-format off */
static JitCompilerPass compiler_passes[] = {
    { NULL, NULL },
#define REG_PASS(name) { #name, jit_pass_##name }
    REG_PASS(dump),
    REG_PASS(update_cfg),
    REG_PASS(frontend),
    REG_PASS(lower_cg),
    REG_PASS(regalloc),
    REG_PASS(codegen),
    REG_PASS(register_jitted_code)
#undef REG_PASS
};

/* Number of compiler passes */
#define COMPILER_PASS_NUM (sizeof(compiler_passes) / sizeof(compiler_passes[0]))

#if WASM_ENABLE_FAST_JIT_DUMP == 0
static const uint8 compiler_passes_without_dump[] = {
    3, 4, 5, 6, 7, 0
};
#else
static const uint8 compiler_passes_with_dump[] = {
    3, 2, 1, 4, 1, 5, 1, 6, 1, 7, 0
};
#endif

/* The exported global data of JIT compiler */
static JitGlobals jit_globals = {
#if WASM_ENABLE_FAST_JIT_DUMP == 0
    .passes = compiler_passes_without_dump,
#else
    .passes = compiler_passes_with_dump,
#endif
    .return_to_interp_from_jitted = NULL,
#if WASM_ENABLE_LAZY_JIT != 0
    .compile_fast_jit_and_then_call = NULL,
#endif
};
/* clang-format on */

static bool
apply_compiler_passes(JitCompContext *cc)
{
    const uint8 *p = jit_globals.passes;

    for (; *p; p++) {
        /* Set the pass NO */
        cc->cur_pass_no = p - jit_globals.passes;
        bh_assert(*p < COMPILER_PASS_NUM);

        if (!compiler_passes[*p].run(cc) || jit_get_last_error(cc)) {
            LOG_VERBOSE("JIT: compilation failed at pass[%td] = %s\n",
                        p - jit_globals.passes, compiler_passes[*p].name);
            return false;
        }
    }

    return true;
}

bool
jit_compiler_init(const JitCompOptions *options)
{
    uint32 code_cache_size = options->code_cache_size > 0
                                 ? options->code_cache_size
                                 : FAST_JIT_DEFAULT_CODE_CACHE_SIZE;

    LOG_VERBOSE("JIT: compiler init with code cache size: %u\n",
                code_cache_size);

    if (!jit_code_cache_init(code_cache_size))
        return false;

    if (!jit_codegen_init())
        goto fail1;

    return true;

fail1:
    jit_code_cache_destroy();
    return false;
}

void
jit_compiler_destroy()
{
    jit_codegen_destroy();

    jit_code_cache_destroy();
}

JitGlobals *
jit_compiler_get_jit_globals()
{
    return &jit_globals;
}

const char *
jit_compiler_get_pass_name(unsigned i)
{
    return i < COMPILER_PASS_NUM ? compiler_passes[i].name : NULL;
}

bool
jit_compiler_compile(WASMModule *module, uint32 func_idx)
{
    JitCompContext *cc = NULL;
    char *last_error;
    bool ret = false;
    uint32 i = func_idx - module->import_function_count;
    uint32 j = i % WASM_ORC_JIT_BACKEND_THREAD_NUM;

    /* Lock to avoid duplicated compilation by other threads */
    os_mutex_lock(&module->fast_jit_thread_locks[j]);

    if (jit_compiler_is_compiled(module, func_idx)) {
        /* Function has been compiled */
        os_mutex_unlock(&module->fast_jit_thread_locks[j]);
        return true;
    }

    /* Initialize the compilation context */
    if (!(cc = jit_calloc(sizeof(*cc)))) {
        goto fail;
    }

    if (!jit_cc_init(cc, 64)) {
        goto fail;
    }

    cc->cur_wasm_module = module;
    cc->cur_wasm_func = module->functions[i];
    cc->cur_wasm_func_idx = func_idx;
    cc->mem_space_unchanged = (!cc->cur_wasm_func->has_op_memory_grow
                               && !cc->cur_wasm_func->has_op_func_call)
                              || (!module->possible_memory_grow);

    /* Apply compiler passes */
    if (!apply_compiler_passes(cc) || jit_get_last_error(cc)) {
        last_error = jit_get_last_error(cc);

#if WASM_ENABLE_CUSTOM_NAME_SECTION != 0
        char *function_name = cc->cur_wasm_func->field_name;
        LOG_ERROR("fast jit compilation failed: %s (function_name=%s)\n",
                  last_error ? last_error : "unknown error", function_name);
#else
        LOG_ERROR("fast jit compilation failed: %s\n",
                  last_error ? last_error : "unknown error");
#endif

        goto fail;
    }

    ret = true;

fail:
    /* Destroy the compilation context */
    if (cc)
        jit_cc_delete(cc);

    os_mutex_unlock(&module->fast_jit_thread_locks[j]);

    return ret;
}

bool
jit_compiler_compile_all(WASMModule *module)
{
    uint32 i;

    for (i = 0; i < module->function_count; i++) {
        if (!jit_compiler_compile(module, module->import_function_count + i)) {
            return false;
        }
    }

    return true;
}

bool
jit_compiler_is_compiled(const WASMModule *module, uint32 func_idx)
{
    uint32 i = func_idx - module->import_function_count;

    bh_assert(func_idx >= module->import_function_count
              && func_idx
                     < module->import_function_count + module->function_count);

#if WASM_ENABLE_LAZY_JIT == 0
    return module->fast_jit_func_ptrs[i] ? true : false;
#else
    return module->fast_jit_func_ptrs[i]
                   != jit_globals.compile_fast_jit_and_then_call
               ? true
               : false;
#endif
}

#if WASM_ENABLE_LAZY_JIT != 0 && WASM_ENABLE_JIT != 0
bool
jit_compiler_set_call_to_llvm_jit(WASMModule *module, uint32 func_idx)
{
    uint32 i = func_idx - module->import_function_count;
    uint32 j = i % WASM_ORC_JIT_BACKEND_THREAD_NUM;
    WASMType *func_type = module->functions[i]->func_type;
    uint32 k =
        ((uint32)(uintptr_t)func_type >> 3) % WASM_ORC_JIT_BACKEND_THREAD_NUM;
    void *func_ptr = NULL;

    /* Compile code block of call_to_llvm_jit_from_fast_jit of
       this kind of function type if it hasn't been compiled */
    if (!(func_ptr = func_type->call_to_llvm_jit_from_fast_jit)) {
        os_mutex_lock(&module->fast_jit_thread_locks[k]);
        if (!(func_ptr = func_type->call_to_llvm_jit_from_fast_jit)) {
            if (!(func_ptr = func_type->call_to_llvm_jit_from_fast_jit =
                      jit_codegen_compile_call_to_llvm_jit(func_type))) {
                os_mutex_unlock(&module->fast_jit_thread_locks[k]);
                return false;
            }
        }
        os_mutex_unlock(&module->fast_jit_thread_locks[k]);
    }

    /* Switch current fast jit func ptr to the code block */
    os_mutex_lock(&module->fast_jit_thread_locks[j]);
    module->fast_jit_func_ptrs[i] = func_ptr;
    os_mutex_unlock(&module->fast_jit_thread_locks[j]);
    return true;
}

bool
jit_compiler_set_call_to_fast_jit(WASMModule *module, uint32 func_idx)
{
    void *func_ptr = NULL;

    func_ptr = jit_codegen_compile_call_to_fast_jit(module, func_idx);
    if (func_ptr) {
        uint32 i = func_idx - module->import_function_count;
        module->functions[i]->call_to_fast_jit_from_llvm_jit = func_ptr;
        jit_compiler_set_llvm_jit_func_ptr(module, func_idx, func_ptr);
    }

    return func_ptr ? true : false;
}

void
jit_compiler_set_llvm_jit_func_ptr(WASMModule *module, uint32 func_idx,
                                   void *func_ptr)
{
    WASMModuleInstance *instance;
    uint32 i = func_idx - module->import_function_count;

    os_mutex_lock(&module->instance_list_lock);

    module->func_ptrs[i] = func_ptr;

    instance = module->instance_list;
    while (instance) {
        if (instance->e->running_mode == Mode_Multi_Tier_JIT)
            instance->func_ptrs[func_idx] = func_ptr;
        instance = instance->e->next;
    }
    os_mutex_unlock(&module->instance_list_lock);
}
#endif /* end of WASM_ENABLE_LAZY_JIT != 0 && WASM_ENABLE_JIT != 0 */

int
jit_interp_switch_to_jitted(void *exec_env, JitInterpSwitchInfo *info,
                            uint32 func_idx, void *pc)
{
    return jit_codegen_interp_jitted_glue(exec_env, info, func_idx, pc);
}
