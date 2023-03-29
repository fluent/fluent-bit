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
    /* Name of the pass.  */
    const char *name;
    /* The entry of the compiler pass.  */
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

/* Number of compiler passes.  */
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

/* The exported global data of JIT compiler.  */
static JitGlobals jit_globals = {
#if WASM_ENABLE_FAST_JIT_DUMP == 0
    .passes = compiler_passes_without_dump,
#else
    .passes = compiler_passes_with_dump,
#endif
    .return_to_interp_from_jitted = NULL
};
/* clang-format on */

static bool
apply_compiler_passes(JitCompContext *cc)
{
    const uint8 *p = jit_globals.passes;

    for (; *p; p++) {
        /* Set the pass NO.  */
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
    JitCompContext *cc;
    char *last_error;
    bool ret = true;

    /* Initialize compilation context.  */
    if (!(cc = jit_calloc(sizeof(*cc))))
        return false;

    if (!jit_cc_init(cc, 64)) {
        jit_free(cc);
        return false;
    }

    cc->cur_wasm_module = module;
    cc->cur_wasm_func =
        module->functions[func_idx - module->import_function_count];
    cc->cur_wasm_func_idx = func_idx;
    cc->mem_space_unchanged = (!cc->cur_wasm_func->has_op_memory_grow
                               && !cc->cur_wasm_func->has_op_func_call)
                              || (!module->possible_memory_grow);

    /* Apply compiler passes.  */
    if (!apply_compiler_passes(cc) || jit_get_last_error(cc)) {
        last_error = jit_get_last_error(cc);
        os_printf("fast jit compilation failed: %s\n",
                  last_error ? last_error : "unknown error");
        ret = false;
    }

    /* Delete the compilation context.  */
    jit_cc_delete(cc);

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

int
jit_interp_switch_to_jitted(void *exec_env, JitInterpSwitchInfo *info, void *pc)
{
    return jit_codegen_interp_jitted_glue(exec_env, info, pc);
}
