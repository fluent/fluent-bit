/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_llvm.h"
#include "aot_llvm_extra2.h"
#include "aot_compiler.h"
#include "aot_emit_exception.h"
#include "aot_emit_table.h"
#include "../aot/aot_runtime.h"
#include "../aot/aot_intrinsic.h"
#include "../interpreter/wasm_runtime.h"

#if WASM_ENABLE_DEBUG_AOT != 0
#include "debug/dwarf_extractor.h"
#endif

static bool
create_native_symbol(const AOTCompContext *comp_ctx, AOTFuncContext *func_ctx);
static bool
create_native_stack_bound(const AOTCompContext *comp_ctx,
                          AOTFuncContext *func_ctx);
static bool
create_native_stack_top_min(const AOTCompContext *comp_ctx,
                            AOTFuncContext *func_ctx);

LLVMTypeRef
wasm_type_to_llvm_type(const AOTCompContext *comp_ctx,
                       const AOTLLVMTypes *llvm_types, uint8 wasm_type)
{
    switch (wasm_type) {
        case VALUE_TYPE_I32:
            return llvm_types->int32_type;
        case VALUE_TYPE_FUNCREF:
        case VALUE_TYPE_EXTERNREF:
            if (comp_ctx->enable_ref_types)
                return llvm_types->int32_type;
            else {
                bh_assert(comp_ctx->enable_gc);
                return llvm_types->gc_ref_type;
            }
        case VALUE_TYPE_I64:
            return llvm_types->int64_type;
        case VALUE_TYPE_F32:
            return llvm_types->float32_type;
        case VALUE_TYPE_F64:
            return llvm_types->float64_type;
        case VALUE_TYPE_V128:
            return llvm_types->i64x2_vec_type;
        case VALUE_TYPE_VOID:
            return llvm_types->void_type;
        case REF_TYPE_NULLFUNCREF:
        case REF_TYPE_NULLEXTERNREF:
        case REF_TYPE_NULLREF:
        /* case REF_TYPE_FUNCREF: */
        /* case REF_TYPE_EXTERNREF: */
        case REF_TYPE_ANYREF:
        case REF_TYPE_EQREF:
        case REF_TYPE_HT_NULLABLE:
        case REF_TYPE_HT_NON_NULLABLE:
        case REF_TYPE_I31REF:
        case REF_TYPE_STRUCTREF:
        case REF_TYPE_ARRAYREF:
#if WASM_ENABLE_STRINGREF != 0
        case REF_TYPE_STRINGREF:
        case REF_TYPE_STRINGVIEWWTF8:
        case REF_TYPE_STRINGVIEWWTF16:
        case REF_TYPE_STRINGVIEWITER:
#endif
        case VALUE_TYPE_GC_REF:
            bh_assert(comp_ctx->enable_gc);
            return llvm_types->gc_ref_type;
        default:
            break;
    }
    bh_assert(0);
    return NULL;
}

static LLVMValueRef
aot_add_llvm_func1(const AOTCompContext *comp_ctx, LLVMModuleRef module,
                   uint32 func_index, uint32 param_count, LLVMTypeRef func_type,
                   const char *prefix)
{
    char func_name[48] = { 0 };
    LLVMValueRef func;
    LLVMValueRef local_value;
    uint32 i, j;

    /* Add LLVM function */
    snprintf(func_name, sizeof(func_name), "%s%d", prefix, func_index);
    if (!(func = LLVMAddFunction(module, func_name, func_type))) {
        aot_set_last_error("add LLVM function failed.");
        return NULL;
    }

    j = 0;
    local_value = LLVMGetParam(func, j++);
    LLVMSetValueName(local_value, "exec_env");

    /* Set parameter names */
    for (i = 0; i < param_count; i++) {
        local_value = LLVMGetParam(func, j++);
        LLVMSetValueName(local_value, "");
    }

    return func;
}

/*
 * create a basic func_ctx enough to call aot_emit_exception.
 *
 * that is:
 * - exec_env
 * - aot_inst
 * - native_symbol (if is_indirect_mode)
 */
static bool
create_basic_func_context(const AOTCompContext *comp_ctx,
                          AOTFuncContext *func_ctx)
{
    LLVMValueRef aot_inst_offset = I32_TWO, aot_inst_addr;

    /* Save the parameters for fast access */
    func_ctx->exec_env = LLVMGetParam(func_ctx->func, 0);

    /* Get aot inst address, the layout of exec_env is:
       exec_env->next, exec_env->prev, exec_env->module_inst, and argv_buf */
    if (!(aot_inst_addr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env,
              &aot_inst_offset, 1, "aot_inst_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        goto fail;
    }

    /* Load aot inst */
    if (!(func_ctx->aot_inst = LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE,
                                              aot_inst_addr, "aot_inst"))) {
        aot_set_last_error("llvm build load failed");
        goto fail;
    }

    if (comp_ctx->is_indirect_mode
        && !create_native_symbol(comp_ctx, func_ctx)) {
        goto fail;
    }

    return true;
fail:
    return false;
}

/*
 * return if the "precheck" wrapper function can use tail call optimization
 */
bool
aot_target_precheck_can_use_musttail(const AOTCompContext *comp_ctx)
{
    if (!strcmp(comp_ctx->target_arch, "xtensa")) {
        /*
         * xtensa windowed ABI doesn't have tail call optimization.
         *
         * Note: as of writing this, the xtensa version of LLVM
         * simply ignores the musttail attribute.
         * https://github.com/espressif/llvm-project/pull/73
         */
        return false;
    }
    if (!strcmp(comp_ctx->target_arch, "riscv32")
        || !strcmp(comp_ctx->target_arch, "riscv64")) {
        /*
         * REVISIT: actually, riscv can use tail call optimization
         * in some cases. I (yamamoto) don't know the exact conditions
         * though.
         */
        return false;
    }
    if (!strcmp(comp_ctx->target_arch, "mips")) {
        /*
         * cf.
         * https://github.com/bytecodealliance/wasm-micro-runtime/issues/2412
         */
        return false;
    }
    if (strstr(comp_ctx->target_arch, "thumb")) {
        /*
         * cf.
         * https://github.com/bytecodealliance/wasm-micro-runtime/issues/2412
         */
        return false;
    }
    /*
     * x86-64/i386: true
     *
     * others: assume true for now
     */
    return true;
}

unsigned int
aot_estimate_stack_usage_for_function_call(const AOTCompContext *comp_ctx,
                                           const AOTFuncType *callee_func_type)
{
    /*
     * Estimate how much stack is necessary to make a function call.
     * This does not include the stack consumption of the callee function.
     *
     * For precise estimation, ideally this function needs to be
     * target-specific.
     * However, this implementation aims to be target-independent,
     * allowing a small overstimation, which is probably ok for our purpose.
     * (overflow detection and memory profiling)
     * On the other hand, an underestimation should be avoided as it
     * can cause more serious problems like silent data corruptions.
     *
     * Assumptions:
     *
     * - the first result is returned via a register.
     *
     * - all parameters, including exec_env and pointers to non-first
     *   results, are passed via stack.
     *   (this is a bit pessimistic than many of real calling conventions,
     *   where some of parameters are passed via register.)
     *
     * - N-byte value needs N-byte alignment on stack.
     *
     * - a value smaller than a pointer is extended.
     *   (eg. 4 byte values are extended to 8 byte on x86-64.)
     */

    const unsigned int param_count = callee_func_type->param_count;
    const unsigned int result_count = callee_func_type->result_count;
    unsigned int size = 0;
    unsigned int i;
    unsigned int nb;

    if (!strcmp(comp_ctx->target_arch, "xtensa")) {
        /*
         * In the xtensa windowed ABI, outgoing arguments are already
         * included in the callee's stack frame size, which equals to
         * the operand of the ENTRY instruction and what LLVM
         * MFI->getStackSize returns.
         */
        return 0;
    }

    /* exec_env */
    size = comp_ctx->pointer_size;

    /* parameters */
    for (i = 0; i < param_count; i++) {
        nb = wasm_value_type_cell_num(callee_func_type->types[i]) * 4;
        if (nb < comp_ctx->pointer_size) {
            nb = comp_ctx->pointer_size;
        }
        size = align_uint(size, nb) + nb;
    }

    /* pointers to results */
    nb = comp_ctx->pointer_size;
    for (i = 1; i < result_count; i++) {
        size = align_uint(size, nb) + nb;
    }

    /* return address */
    nb = comp_ctx->pointer_size;
    size = align_uint(size, nb) + nb;

    /*
     * some extra for possible arch-dependent things like
     * 16-byte alignment for x86_64.
     */
    size += 16;
    return size;
}

/*
 * a "precheck" function performs a few things before calling wrapped_func.
 *
 * - update native_stack_top_min if necessary
 * - stack overflow check (if it does, trap)
 */
static bool
aot_build_precheck_function(AOTCompContext *comp_ctx, LLVMModuleRef module,
                            LLVMValueRef precheck_func, uint32 func_index,
                            LLVMTypeRef func_type, LLVMValueRef wrapped_func)
{
    LLVMBasicBlockRef begin = NULL;
    LLVMBasicBlockRef check_top_block = NULL;
    LLVMBasicBlockRef update_top_block = NULL;
    LLVMBasicBlockRef stack_bound_check_block = NULL;
    LLVMBasicBlockRef call_wrapped_func_block = NULL;
    LLVMValueRef *params = NULL;

    begin = LLVMAppendBasicBlockInContext(comp_ctx->context, precheck_func,
                                          "begin");
    check_top_block = LLVMAppendBasicBlockInContext(
        comp_ctx->context, precheck_func, "check_top_block");
    if (comp_ctx->enable_stack_estimation) {
        update_top_block = LLVMAppendBasicBlockInContext(
            comp_ctx->context, precheck_func, "update_top_block");
        if (!update_top_block) {
            goto fail;
        }
    }
    stack_bound_check_block = LLVMAppendBasicBlockInContext(
        comp_ctx->context, precheck_func, "stack_bound_check_block");
    call_wrapped_func_block = LLVMAppendBasicBlockInContext(
        comp_ctx->context, precheck_func, "call_wrapped_func");
    if (!begin || !check_top_block || !stack_bound_check_block
        || !call_wrapped_func_block) {
        goto fail;
    }
    LLVMBuilderRef b = comp_ctx->builder;
    LLVMPositionBuilderAtEnd(b, begin);

    /* create a temporary minimum func_ctx */
    AOTFuncContext tmp;
    AOTFuncContext *func_ctx = &tmp;
    memset(func_ctx, 0, sizeof(*func_ctx));
    func_ctx->func = precheck_func;
    func_ctx->module = module;
    func_ctx->aot_func = comp_ctx->comp_data->funcs[func_index];
#if WASM_ENABLE_DEBUG_AOT != 0
    func_ctx->debug_func = NULL;
#endif
    if (!create_basic_func_context(comp_ctx, func_ctx))
        goto fail;
    if (comp_ctx->enable_stack_bound_check
        && !create_native_stack_bound(comp_ctx, func_ctx))
        goto fail;
    if (comp_ctx->enable_stack_estimation
        && !create_native_stack_top_min(comp_ctx, func_ctx)) {
        goto fail;
    }

    uint32 param_count = LLVMCountParams(precheck_func);
    uint32 sz = param_count * (uint32)sizeof(LLVMValueRef);
    params = wasm_runtime_malloc(sz);
    if (params == NULL) {
        goto fail;
    }
    LLVMGetParams(precheck_func, params);

    const bool is_64bit = comp_ctx->pointer_size == sizeof(uint64);
    LLVMTypeRef uintptr_type;
    if (is_64bit)
        uintptr_type = I64_TYPE;
    else
        uintptr_type = I32_TYPE;

    /*
     * load the stack pointer
     */
    LLVMValueRef sp_ptr = LLVMBuildAlloca(b, I32_TYPE, "sp_ptr");
    if (!sp_ptr) {
        goto fail;
    }
    LLVMValueRef sp = LLVMBuildPtrToInt(b, sp_ptr, uintptr_type, "sp");
    if (!sp) {
        goto fail;
    }

    /*
     * load the value for this wrapped function from the stack_sizes array
     */
    LLVMValueRef stack_sizes;
    if (comp_ctx->is_indirect_mode) {
        uint32 offset_u32;
        LLVMValueRef offset;
        LLVMValueRef stack_sizes_p;

        offset_u32 = get_module_inst_extra_offset(comp_ctx);
        offset_u32 += offsetof(AOTModuleInstanceExtra, stack_sizes);
        offset = I32_CONST(offset_u32);
        if (!offset) {
            goto fail;
        }
        stack_sizes_p =
            LLVMBuildInBoundsGEP2(b, INT8_TYPE, func_ctx->aot_inst, &offset, 1,
                                  "aot_inst_stack_sizes_p");
        if (!stack_sizes_p) {
            goto fail;
        }
        stack_sizes =
            LLVMBuildLoad2(b, INT32_PTR_TYPE, stack_sizes_p, "stack_sizes");
        if (!stack_sizes) {
            goto fail;
        }
    }
    else {
        stack_sizes = comp_ctx->stack_sizes;
    }
    LLVMValueRef func_index_const = I32_CONST(func_index);
    LLVMValueRef sizes =
        LLVMBuildBitCast(b, stack_sizes, INT32_PTR_TYPE, "sizes");
    if (!sizes) {
        goto fail;
    }
    LLVMValueRef sizep = LLVMBuildInBoundsGEP2(b, I32_TYPE, sizes,
                                               &func_index_const, 1, "sizep");
    if (!sizep) {
        goto fail;
    }
    LLVMValueRef size32 = LLVMBuildLoad2(b, I32_TYPE, sizep, "size32");
    if (!size32) {
        goto fail;
    }
    LLVMValueRef size;
    if (is_64bit) {
        size = LLVMBuildZExt(b, size32, uintptr_type, "size");
        if (!size) {
            goto fail;
        }
    }
    else {
        size = size32;
    }
    /*
     * calculate new sp
     */
    LLVMValueRef underflow =
        LLVMBuildICmp(b, LLVMIntULT, sp, size, "underflow");
    if (!underflow) {
        goto fail;
    }
    LLVMValueRef new_sp = LLVMBuildSub(b, sp, size, "new_sp");
    if (!new_sp) {
        goto fail;
    }
    if (!LLVMBuildBr(b, check_top_block)) {
        goto fail;
    }

    LLVMPositionBuilderAtEnd(b, check_top_block);
    if (comp_ctx->enable_stack_estimation) {
        /*
         * load native_stack_top_min from the exec_env
         */
        LLVMValueRef top_min =
            LLVMBuildLoad2(b, OPQ_PTR_TYPE, func_ctx->native_stack_top_min_addr,
                           "native_stack_top_min");
        if (!top_min) {
            goto fail;
        }
        LLVMValueRef top_min_int = LLVMBuildPtrToInt(
            b, top_min, uintptr_type, "native_stack_top_min_int");
        if (!top_min_int) {
            goto fail;
        }

        bh_assert(update_top_block);

        /*
         * update native_stack_top_min if
         * new_sp = sp - size < native_stack_top_min
         *
         * Note: unless the stack has already overflown in this exec_env,
         * native_stack_bound <= native_stack_top_min
         */
        LLVMValueRef cmp_top =
            LLVMBuildICmp(b, LLVMIntULT, new_sp, top_min_int, "cmp_top");
        if (!cmp_top) {
            goto fail;
        }
        cmp_top = LLVMBuildOr(b, underflow, cmp_top, "cmp_top2");
        if (!cmp_top) {
            goto fail;
        }
        if (!LLVMBuildCondBr(b, cmp_top, update_top_block,
                             call_wrapped_func_block)) {
            aot_set_last_error("llvm build cond br failed.");
            goto fail;
        }

        /*
         * update native_stack_top_min
         */
        LLVMPositionBuilderAtEnd(b, update_top_block);
        LLVMValueRef new_sp_ptr =
            LLVMBuildIntToPtr(b, new_sp, INT8_PTR_TYPE, "new_sp_ptr");
        if (!new_sp_ptr) {
            goto fail;
        }
        if (!LLVMBuildStore(b, new_sp_ptr,
                            func_ctx->native_stack_top_min_addr)) {
            goto fail;
        }
        if (!LLVMBuildBr(b, stack_bound_check_block)) {
            goto fail;
        }
    }
    else {
        if (!LLVMBuildBr(b, stack_bound_check_block)) {
            goto fail;
        }
    }

    LLVMPositionBuilderAtEnd(b, stack_bound_check_block);
    if (comp_ctx->enable_stack_bound_check) {
        /*
         * trap if new_sp < native_stack_bound
         */
        LLVMValueRef bound_int = LLVMBuildPtrToInt(
            b, func_ctx->native_stack_bound, uintptr_type, "bound_base_int");
        if (!bound_int) {
            goto fail;
        }
        LLVMValueRef cmp =
            LLVMBuildICmp(b, LLVMIntULT, new_sp, bound_int, "cmp");
        if (!cmp) {
            goto fail;
        }
        cmp = LLVMBuildOr(b, underflow, cmp, "cmp2");
        if (!cmp) {
            goto fail;
        }
        /* todo: @llvm.expect.i1(i1 %cmp, i1 0) */
        if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_NATIVE_STACK_OVERFLOW,
                                true, cmp, call_wrapped_func_block))
            goto fail;
    }
    else {
        if (!LLVMBuildBr(b, call_wrapped_func_block)) {
            goto fail;
        }
    }

    /*
     * call the wrapped function
     * use a tail-call if possible
     */
    LLVMPositionBuilderAtEnd(b, call_wrapped_func_block);
    const char *name = "tail_call";
    LLVMTypeRef ret_type = LLVMGetReturnType(func_type);
    if (ret_type == VOID_TYPE) {
        name = "";
    }
    LLVMValueRef retval =
        LLVMBuildCall2(b, func_type, wrapped_func, params, param_count, name);
    if (!retval) {
        goto fail;
    }
    wasm_runtime_free(params);
    params = NULL;
    if (aot_target_precheck_can_use_musttail(comp_ctx)) {
        LLVMSetTailCallKind(retval, LLVMTailCallKindMustTail);
    }
    else {
        LLVMSetTailCallKind(retval, LLVMTailCallKindTail);
    }
    if (ret_type == VOID_TYPE) {
        if (!LLVMBuildRetVoid(b)) {
            goto fail;
        }
    }
    else {
        if (!LLVMBuildRet(b, retval)) {
            goto fail;
        }
    }

    return true;
fail:
    if (params != NULL) {
        wasm_runtime_free(params);
    }
    aot_set_last_error("failed to build precheck wrapper function.");
    return false;
}

static bool
check_wasm_type(AOTCompContext *comp_ctx, uint8 type)
{
    if (type == VALUE_TYPE_FUNCREF || type == VALUE_TYPE_EXTERNREF) {
        if (!comp_ctx->enable_ref_types && !comp_ctx->enable_gc) {
            aot_set_last_error("funcref or externref type was found, "
                               "try removing --disable-ref-types option "
                               "or adding --enable-gc option.");
            return false;
        }
        else
            return true;
    }
    else if (aot_is_type_gc_reftype(type)) {
        if (!comp_ctx->enable_gc) {
            aot_set_last_error("GC reference type was found, "
                               "try adding --enable-gc option.");
            return false;
        }
        else
            return true;
    }
    else if (type == VALUE_TYPE_V128) {
        if (!comp_ctx->enable_simd) {
            aot_set_last_error("SIMD type was found, try removing "
                               " --disable-simd option.");
            return false;
        }
        return true;
    }
    else if (type != VALUE_TYPE_I32 && type != VALUE_TYPE_I64
             && type != VALUE_TYPE_F32 && type != VALUE_TYPE_F64) {
        bh_assert(0);
    }

    return true;
}

/**
 * Add LLVM function
 */
static LLVMValueRef
aot_add_llvm_func(AOTCompContext *comp_ctx, LLVMModuleRef module,
                  const AOTFuncType *aot_func_type, uint32 func_index,
                  LLVMTypeRef *p_func_type, LLVMValueRef *p_precheck_func)
{
    WASMFunction *aot_func =
        comp_ctx->comp_data->wasm_module->functions[func_index];
    LLVMValueRef func = NULL;
    LLVMTypeRef *param_types, ret_type, func_type;
    LLVMTypeRef func_type_wrapper;
    LLVMValueRef func_wrapper;
    LLVMBasicBlockRef func_begin;
    char func_name[48];
    uint64 size;
    uint32 i, j = 0, param_count = (uint64)aot_func_type->param_count;
    uint32 backend_thread_num, compile_thread_num;

    /* Check function parameter types and result types */
    for (i = 0;
         i < (uint32)(aot_func_type->param_count + aot_func_type->result_count);
         i++) {
        if (!check_wasm_type(comp_ctx, aot_func_type->types[i]))
            return NULL;
    }
    /* Check function local types */
    for (i = 0; i < aot_func->local_count; i++) {
        if (!check_wasm_type(comp_ctx, aot_func->local_types[i]))
            return NULL;
    }

    /* exec env as first parameter */
    param_count++;

    /* Extra wasm function results(except the first one)'s address are
     * appended to aot function parameters. */
    if (aot_func_type->result_count > 1)
        param_count += aot_func_type->result_count - 1;

    /* Initialize parameter types of the LLVM function */
    size = sizeof(LLVMTypeRef) * ((uint64)param_count);
    if (size >= UINT32_MAX
        || !(param_types = wasm_runtime_malloc((uint32)size))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }

    /* exec env as first parameter */
    param_types[j++] = comp_ctx->exec_env_type;
    for (i = 0; i < aot_func_type->param_count; i++)
        param_types[j++] = TO_LLVM_TYPE(aot_func_type->types[i]);
    /* Extra results' address */
    for (i = 1; i < aot_func_type->result_count; i++, j++) {
        param_types[j] =
            TO_LLVM_TYPE(aot_func_type->types[aot_func_type->param_count + i]);
        if (!(param_types[j] = LLVMPointerType(param_types[j], 0))) {
            aot_set_last_error("llvm get pointer type failed.");
            goto fail;
        }
    }

    /* Resolve return type of the LLVM function */
    if (aot_func_type->result_count)
        ret_type =
            TO_LLVM_TYPE(aot_func_type->types[aot_func_type->param_count]);
    else
        ret_type = VOID_TYPE;

    /* Resolve function prototype */
    if (!(func_type =
              LLVMFunctionType(ret_type, param_types, param_count, false))) {
        aot_set_last_error("create LLVM function type failed.");
        goto fail;
    }

    bh_assert(func_index < comp_ctx->func_ctx_count);
    bh_assert(LLVMGetReturnType(func_type) == ret_type);

    const char *prefix = AOT_FUNC_PREFIX;
    const bool need_precheck =
        comp_ctx->enable_stack_bound_check || comp_ctx->enable_stack_estimation;
    LLVMValueRef precheck_func = NULL;

    if (need_precheck) {
        precheck_func = aot_add_llvm_func1(comp_ctx, module, func_index,
                                           aot_func_type->param_count,
                                           func_type, AOT_FUNC_PREFIX);
        if (!precheck_func) {
            goto fail;
        }
        /*
         * REVISIT: probably this breaks windows hw bound check
         * (the RtlAddFunctionTable stuff)
         */
        prefix = AOT_FUNC_INTERNAL_PREFIX;
    }
    if (!(func = aot_add_llvm_func1(comp_ctx, module, func_index,
                                    aot_func_type->param_count, func_type,
                                    prefix)))
        goto fail;

    if (comp_ctx->disable_llvm_jump_tables) {
        LLVMAttributeRef attr_no_jump_tables = LLVMCreateStringAttribute(
            comp_ctx->context, "no-jump-tables",
            (uint32)strlen("no-jump-tables"), "true", (uint32)strlen("true"));
        LLVMAddAttributeAtIndex(func, LLVMAttributeFunctionIndex,
                                attr_no_jump_tables);
    }

    /* spread fp.all to every function */
    if (comp_ctx->emit_frame_pointer) {
        const char *key = "frame-pointer";
        const char *val = "all";
        LLVMAttributeRef no_omit_fp = LLVMCreateStringAttribute(
            comp_ctx->context, key, (unsigned)strlen(key), val,
            (unsigned)strlen(val));
        if (!no_omit_fp) {
            aot_set_last_error("create LLVM attribute (frame-pointer) failed.");
            goto fail;
        }
        LLVMAddAttributeAtIndex(func, LLVMAttributeFunctionIndex, no_omit_fp);
    }

    if (need_precheck) {
        if (!comp_ctx->is_jit_mode)
            LLVMSetLinkage(func, LLVMInternalLinkage);
        unsigned int kind =
            LLVMGetEnumAttributeKindForName("noinline", strlen("noinline"));
        LLVMAttributeRef attr_noinline =
            LLVMCreateEnumAttribute(comp_ctx->context, kind, 0);
        LLVMAddAttributeAtIndex(func, LLVMAttributeFunctionIndex,
                                attr_noinline);
        if (!strcmp(comp_ctx->target_arch, "xtensa")) {
            /* Because "func" is only called by "precheck_func", short-call
             * should be ok. We prefer short-call because it's smaller
             * and more importantly doesn't involve relocations.
             */
            LLVMAttributeRef attr_short_call = LLVMCreateStringAttribute(
                comp_ctx->context, "short-call", (unsigned)strlen("short-call"),
                "", 0);
            LLVMAddAttributeAtIndex(func, LLVMAttributeFunctionIndex,
                                    attr_short_call);
        }
        if (!aot_build_precheck_function(comp_ctx, module, precheck_func,
                                         func_index, func_type, func))
            goto fail;
        LLVMAddAttributeAtIndex(precheck_func, LLVMAttributeFunctionIndex,
                                attr_noinline);
        *p_precheck_func = precheck_func;
    }
    else {
        *p_precheck_func = func;
    }

    if (p_func_type)
        *p_func_type = func_type;

    backend_thread_num = WASM_ORC_JIT_BACKEND_THREAD_NUM;
    compile_thread_num = WASM_ORC_JIT_COMPILE_THREAD_NUM;

    /* Add the jit wrapper function with simple prototype, so that we
       can easily call it to trigger its compilation and let LLVM JIT
       compile the actual jit functions by adding them into the function
       list in the PartitionFunction callback */
    if (comp_ctx->is_jit_mode
        && (func_index % (backend_thread_num * compile_thread_num)
            < backend_thread_num)) {
        func_type_wrapper = LLVMFunctionType(VOID_TYPE, NULL, 0, false);
        if (!func_type_wrapper) {
            aot_set_last_error("create LLVM function type failed.");
            goto fail;
        }

        snprintf(func_name, sizeof(func_name), "%s%d%s", AOT_FUNC_PREFIX,
                 func_index, "_wrapper");
        if (!(func_wrapper =
                  LLVMAddFunction(module, func_name, func_type_wrapper))) {
            aot_set_last_error("add LLVM function failed.");
            goto fail;
        }

        if (!(func_begin = LLVMAppendBasicBlockInContext(
                  comp_ctx->context, func_wrapper, "func_begin"))) {
            aot_set_last_error("add LLVM basic block failed.");
            goto fail;
        }

        LLVMPositionBuilderAtEnd(comp_ctx->builder, func_begin);
        if (!LLVMBuildRetVoid(comp_ctx->builder)) {
            aot_set_last_error("llvm build ret failed.");
            goto fail;
        }
    }

fail:
    wasm_runtime_free(param_types);
    return func;
}

static void
free_block_memory(AOTBlock *block)
{
    if (block->param_types)
        wasm_runtime_free(block->param_types);
    if (block->result_types)
        wasm_runtime_free(block->result_types);
    wasm_runtime_free(block);
}

/**
 * Create first AOTBlock, or function block for the function
 */
static AOTBlock *
aot_create_func_block(const AOTCompContext *comp_ctx,
                      const AOTFuncContext *func_ctx, const AOTFunc *func,
                      const AOTFuncType *aot_func_type)
{
    AOTBlock *aot_block;
    uint32 param_count = aot_func_type->param_count,
           result_count = aot_func_type->result_count;

    /* Allocate memory */
    if (!(aot_block = wasm_runtime_malloc(sizeof(AOTBlock)))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }
    memset(aot_block, 0, sizeof(AOTBlock));
    if (param_count
        && !(aot_block->param_types = wasm_runtime_malloc(param_count))) {
        aot_set_last_error("allocate memory failed.");
        goto fail;
    }
    if (result_count) {
        if (!(aot_block->result_types = wasm_runtime_malloc(result_count))) {
            aot_set_last_error("allocate memory failed.");
            goto fail;
        }
    }

    /* Set block data */
    aot_block->label_type = LABEL_TYPE_FUNCTION;
    aot_block->param_count = param_count;
    if (param_count) {
        bh_memcpy_s(aot_block->param_types, param_count, aot_func_type->types,
                    param_count);
    }
    aot_block->result_count = result_count;
    if (result_count) {
        bh_memcpy_s(aot_block->result_types, result_count,
                    aot_func_type->types + param_count, result_count);
    }
    aot_block->wasm_code_end = func->code + func->code_size;

    /* Add function entry block */
    if (!(aot_block->llvm_entry_block = LLVMAppendBasicBlockInContext(
              comp_ctx->context, func_ctx->func, "func_begin"))) {
        aot_set_last_error("add LLVM basic block failed.");
        goto fail;
    }

    return aot_block;

fail:
    free_block_memory(aot_block);
    return NULL;
}

static bool
create_argv_buf(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef argv_buf_offset = I32_THREE, argv_buf_addr;
    LLVMTypeRef int32_ptr_type;

    /* Get argv buffer address */
    if (!(argv_buf_addr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env,
              &argv_buf_offset, 1, "argv_buf_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }

    if (!(int32_ptr_type = LLVMPointerType(INT32_PTR_TYPE, 0))) {
        aot_set_last_error("llvm add pointer type failed");
        return false;
    }

    /* Convert to int32 pointer type */
    if (!(argv_buf_addr = LLVMBuildBitCast(comp_ctx->builder, argv_buf_addr,
                                           int32_ptr_type, "argv_buf_ptr"))) {
        aot_set_last_error("llvm build load failed");
        return false;
    }

    if (!(func_ctx->argv_buf = LLVMBuildLoad2(comp_ctx->builder, INT32_PTR_TYPE,
                                              argv_buf_addr, "argv_buf"))) {
        aot_set_last_error("llvm build load failed");
        return false;
    }

    return true;
}

static bool
create_native_stack_bound(const AOTCompContext *comp_ctx,
                          AOTFuncContext *func_ctx)
{
    LLVMValueRef stack_bound_offset = I32_FOUR, stack_bound_addr;

    if (!(stack_bound_addr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env,
              &stack_bound_offset, 1, "stack_bound_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }

    if (!(func_ctx->native_stack_bound =
              LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE, stack_bound_addr,
                             "native_stack_bound"))) {
        aot_set_last_error("llvm build load failed");
        return false;
    }

    return true;
}

static bool
create_native_stack_top_min(const AOTCompContext *comp_ctx,
                            AOTFuncContext *func_ctx)
{
    LLVMValueRef offset = I32_NINE;

    if (!(func_ctx->native_stack_top_min_addr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env, &offset, 1,
              "native_stack_top_min_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }

    return true;
}

static bool
create_aux_stack_info(const AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef aux_stack_bound_offset = I32_SIX, aux_stack_bound_addr;
    LLVMValueRef aux_stack_bottom_offset = I32_SEVEN, aux_stack_bottom_addr;

    /* Get aux stack boundary address */
    if (!(aux_stack_bound_addr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env,
              &aux_stack_bound_offset, 1, "aux_stack_bound_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }

    if (!(aux_stack_bound_addr =
              LLVMBuildBitCast(comp_ctx->builder, aux_stack_bound_addr,
                               INTPTR_T_PTR_TYPE, "aux_stack_bound_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }

    if (!(func_ctx->aux_stack_bound =
              LLVMBuildLoad2(comp_ctx->builder, INTPTR_T_TYPE,
                             aux_stack_bound_addr, "aux_stack_bound_intptr"))) {
        aot_set_last_error("llvm build load failed");
        return false;
    }
    if (!(func_ctx->aux_stack_bound =
              LLVMBuildZExt(comp_ctx->builder, func_ctx->aux_stack_bound,
                            I64_TYPE, "aux_stack_bound_i64"))) {
        aot_set_last_error("llvm build truncOrBitCast failed.");
        return false;
    }

    /* Get aux stack bottom address */
    if (!(aux_stack_bottom_addr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env,
              &aux_stack_bottom_offset, 1, "aux_stack_bottom_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }

    if (!(aux_stack_bottom_addr =
              LLVMBuildBitCast(comp_ctx->builder, aux_stack_bottom_addr,
                               INTPTR_T_PTR_TYPE, "aux_stack_bottom_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }

    if (!(func_ctx->aux_stack_bottom =
              LLVMBuildLoad2(comp_ctx->builder, INTPTR_T_TYPE,
                             aux_stack_bottom_addr, "aux_stack_bottom"))) {
        aot_set_last_error("llvm build load failed");
        return false;
    }
    if (!(func_ctx->aux_stack_bottom =
              LLVMBuildZExt(comp_ctx->builder, func_ctx->aux_stack_bottom,
                            I64_TYPE, "aux_stack_bottom_i64"))) {
        aot_set_last_error("llvm build truncOrBitCast failed.");
        return false;
    }

    return true;
}

static bool
create_aux_stack_frame(const AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef wasm_stack_top_bound_ptr, offset;

    offset = I32_ONE;
    if (!(func_ctx->cur_frame_ptr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env, &offset, 1,
              "cur_frame_ptr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }

    if (!(func_ctx->cur_frame =
              LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE,
                             func_ctx->cur_frame_ptr, "cur_frame"))) {
        aot_set_last_error("llvm build load failed");
        return false;
    }

    /* Get exec_env->wasm_stack.top_boundary and its address */
    offset = I32_TEN;
    if (!(wasm_stack_top_bound_ptr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env, &offset, 1,
              "wasm_stack_top_bound_ptr"))
        || !(func_ctx->wasm_stack_top_bound = LLVMBuildLoad2(
                 comp_ctx->builder, INT8_PTR_TYPE, wasm_stack_top_bound_ptr,
                 "wasm_stack_top_bound"))) {
        aot_set_last_error("load wasm_stack.top_boundary failed");
        return false;
    }

    offset = I32_ELEVEN;
    if (!(func_ctx->wasm_stack_top_ptr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env, &offset, 1,
              "wasm_stack_top_ptr"))) {
        aot_set_last_error("llvm build inbounds gep failed");
        return false;
    }

    return true;
}

static bool
create_native_symbol(const AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef native_symbol_offset = I32_EIGHT, native_symbol_addr;

    if (!(native_symbol_addr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env,
              &native_symbol_offset, 1, "native_symbol_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }

    if (!(func_ctx->native_symbol =
              LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE,
                             native_symbol_addr, "native_symbol_tmp"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }

    if (!(func_ctx->native_symbol =
              LLVMBuildBitCast(comp_ctx->builder, func_ctx->native_symbol,
                               comp_ctx->exec_env_type, "native_symbol"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }

    return true;
}

static bool
create_local_variables(const AOTCompData *comp_data,
                       const AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                       const AOTFunc *func)
{
    AOTFuncType *aot_func_type =
        (AOTFuncType *)comp_data->types[func->func_type_index];
    char local_name[32];
    uint32 i, j = 1;

    for (i = 0; i < aot_func_type->param_count; i++, j++) {
        snprintf(local_name, sizeof(local_name), "l%d", i);
        func_ctx->locals[i] =
            LLVMBuildAlloca(comp_ctx->builder,
                            TO_LLVM_TYPE(aot_func_type->types[i]), local_name);
        if (!func_ctx->locals[i]) {
            aot_set_last_error("llvm build alloca failed.");
            return false;
        }
        if (!LLVMBuildStore(comp_ctx->builder, LLVMGetParam(func_ctx->func, j),
                            func_ctx->locals[i])) {
            aot_set_last_error("llvm build store failed.");
            return false;
        }
    }

    for (i = 0; i < func->local_count; i++) {
        LLVMTypeRef local_type;
        LLVMValueRef local_value = NULL;
        snprintf(local_name, sizeof(local_name), "l%d",
                 aot_func_type->param_count + i);
        local_type = TO_LLVM_TYPE(func->local_types_wp[i]);
        func_ctx->locals[aot_func_type->param_count + i] =
            LLVMBuildAlloca(comp_ctx->builder, local_type, local_name);
        if (!func_ctx->locals[aot_func_type->param_count + i]) {
            aot_set_last_error("llvm build alloca failed.");
            return false;
        }
        switch (func->local_types_wp[i]) {
            case VALUE_TYPE_I32:
                local_value = I32_ZERO;
                break;
            case VALUE_TYPE_I64:
                local_value = I64_ZERO;
                break;
            case VALUE_TYPE_F32:
                local_value = F32_ZERO;
                break;
            case VALUE_TYPE_F64:
                local_value = F64_ZERO;
                break;
            case VALUE_TYPE_V128:
                local_value = V128_i64x2_ZERO;
                break;
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
                if (!comp_ctx->enable_gc)
                    local_value = REF_NULL;
                else
                    local_value = GC_REF_NULL;
                break;
#if WASM_ENABLE_GC != 0
            case REF_TYPE_NULLFUNCREF:
            case REF_TYPE_NULLEXTERNREF:
            case REF_TYPE_NULLREF:
            /* case REF_TYPE_FUNCREF: */
            /* case REF_TYPE_EXTERNREF: */
            case REF_TYPE_ANYREF:
            case REF_TYPE_EQREF:
            case REF_TYPE_HT_NULLABLE:
            case REF_TYPE_HT_NON_NULLABLE:
            case REF_TYPE_I31REF:
            case REF_TYPE_STRUCTREF:
            case REF_TYPE_ARRAYREF:
#if WASM_ENABLE_STRINGREF != 0
            case REF_TYPE_STRINGREF:
            case REF_TYPE_STRINGVIEWWTF8:
            case REF_TYPE_STRINGVIEWWTF16:
            case REF_TYPE_STRINGVIEWITER:
#endif
                local_value = GC_REF_NULL;
                break;
#endif
            default:
                bh_assert(0);
                break;
        }
        if (!LLVMBuildStore(comp_ctx->builder, local_value,
                            func_ctx->locals[aot_func_type->param_count + i])) {
            aot_set_last_error("llvm build store failed.");
            return false;
        }
    }

    return true;
}

static bool
create_memory_info(const AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                   LLVMTypeRef int8_ptr_type, uint32 func_index)
{
    LLVMValueRef offset, mem_info_base;
    uint32 memory_count;
    WASMModule *module = comp_ctx->comp_data->wasm_module;
    WASMFunction *func = module->functions[func_index];
    LLVMTypeRef bound_check_type;
    bool mem_space_unchanged =
        (!func->has_op_memory_grow && !func->has_op_func_call)
        || (!module->possible_memory_grow);
#if WASM_ENABLE_SHARED_MEMORY != 0
    bool is_shared_memory;
#endif

    func_ctx->mem_space_unchanged = mem_space_unchanged;

    memory_count = module->memory_count + module->import_memory_count;
    /* If the module doesn't have memory, reserve
        one mem_info space with empty content */
    if (memory_count == 0)
        memory_count = 1;

    if (!(func_ctx->mem_info =
              wasm_runtime_malloc(sizeof(AOTMemInfo) * memory_count))) {
        return false;
    }
    memset(func_ctx->mem_info, 0, sizeof(AOTMemInfo));

    /* Currently we only create memory info for memory 0 */
    /* Load memory base address */
#if WASM_ENABLE_SHARED_MEMORY != 0
    is_shared_memory =
        comp_ctx->comp_data->memories[0].flags & 0x02 ? true : false;
    if (is_shared_memory) {
        LLVMValueRef shared_mem_addr;
        offset = I32_CONST(offsetof(AOTModuleInstance, memories));
        if (!offset) {
            aot_set_last_error("create llvm const failed.");
            return false;
        }

        /* aot_inst->memories */
        if (!(shared_mem_addr = LLVMBuildInBoundsGEP2(
                  comp_ctx->builder, INT8_TYPE, func_ctx->aot_inst, &offset, 1,
                  "shared_mem_addr_offset"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }
        if (!(shared_mem_addr =
                  LLVMBuildBitCast(comp_ctx->builder, shared_mem_addr,
                                   int8_ptr_type, "shared_mem_addr_ptr"))) {
            aot_set_last_error("llvm build bit cast failed");
            return false;
        }
        /* aot_inst->memories[0] */
        if (!(shared_mem_addr =
                  LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE,
                                 shared_mem_addr, "shared_mem_addr"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
        if (!(shared_mem_addr =
                  LLVMBuildBitCast(comp_ctx->builder, shared_mem_addr,
                                   int8_ptr_type, "shared_mem_addr_ptr"))) {
            aot_set_last_error("llvm build bit cast failed");
            return false;
        }
        if (!(shared_mem_addr =
                  LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE,
                                 shared_mem_addr, "shared_mem_addr"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
        /* memories[0]->memory_data */
        offset = I32_CONST(offsetof(AOTMemoryInstance, memory_data));
        if (!(func_ctx->mem_info[0].mem_base_addr = LLVMBuildInBoundsGEP2(
                  comp_ctx->builder, INT8_TYPE, shared_mem_addr, &offset, 1,
                  "mem_base_addr_offset"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }
        /* memories[0]->cur_page_count */
        offset = I32_CONST(offsetof(AOTMemoryInstance, cur_page_count));
        if (!(func_ctx->mem_info[0].mem_cur_page_count_addr =
                  LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE,
                                        shared_mem_addr, &offset, 1,
                                        "mem_cur_page_offset"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }
        /* memories[0]->memory_data_size */
        offset = I32_CONST(offsetof(AOTMemoryInstance, memory_data_size));
        if (!(func_ctx->mem_info[0].mem_data_size_addr = LLVMBuildInBoundsGEP2(
                  comp_ctx->builder, INT8_TYPE, shared_mem_addr, &offset, 1,
                  "mem_data_size_offset"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }
    }
    else
#endif
    {
        uint32 offset_of_global_table_data;

        if (comp_ctx->is_jit_mode)
            offset_of_global_table_data =
                offsetof(WASMModuleInstance, global_table_data);
        else
            offset_of_global_table_data =
                offsetof(AOTModuleInstance, global_table_data);

        offset = I32_CONST(offset_of_global_table_data
                           + offsetof(AOTMemoryInstance, memory_data));
        if (!(func_ctx->mem_info[0].mem_base_addr = LLVMBuildInBoundsGEP2(
                  comp_ctx->builder, INT8_TYPE, func_ctx->aot_inst, &offset, 1,
                  "mem_base_addr_offset"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }
        offset = I32_CONST(offset_of_global_table_data
                           + offsetof(AOTMemoryInstance, cur_page_count));
        if (!(func_ctx->mem_info[0].mem_cur_page_count_addr =
                  LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE,
                                        func_ctx->aot_inst, &offset, 1,
                                        "mem_cur_page_offset"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }
        offset = I32_CONST(offset_of_global_table_data
                           + offsetof(AOTMemoryInstance, memory_data_size));
        if (!(func_ctx->mem_info[0].mem_data_size_addr = LLVMBuildInBoundsGEP2(
                  comp_ctx->builder, INT8_TYPE, func_ctx->aot_inst, &offset, 1,
                  "mem_data_size_offset"))) {
            aot_set_last_error("llvm build in bounds gep failed");
            return false;
        }
    }
    /* Store mem info base address before cast */
    mem_info_base = func_ctx->mem_info[0].mem_base_addr;

    if (!(func_ctx->mem_info[0].mem_base_addr = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_base_addr,
              int8_ptr_type, "mem_base_addr_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (!(func_ctx->mem_info[0].mem_cur_page_count_addr = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_cur_page_count_addr,
              INT32_PTR_TYPE, "mem_cur_page_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (!(func_ctx->mem_info[0].mem_data_size_addr = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_data_size_addr,
              INT64_PTR_TYPE, "mem_data_size_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (mem_space_unchanged) {
        if (!(func_ctx->mem_info[0].mem_base_addr = LLVMBuildLoad2(
                  comp_ctx->builder, OPQ_PTR_TYPE,
                  func_ctx->mem_info[0].mem_base_addr, "mem_base_addr"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
        if (!(func_ctx->mem_info[0].mem_cur_page_count_addr =
                  LLVMBuildLoad2(comp_ctx->builder, I32_TYPE,
                                 func_ctx->mem_info[0].mem_cur_page_count_addr,
                                 "mem_cur_page_count"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
        if (!(func_ctx->mem_info[0].mem_data_size_addr = LLVMBuildLoad2(
                  comp_ctx->builder, I64_TYPE,
                  func_ctx->mem_info[0].mem_data_size_addr, "mem_data_size"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
    }
#if WASM_ENABLE_SHARED_MEMORY != 0
    else if (is_shared_memory) {
        /* The base address for shared memory will never changed,
            we can load the value here */
        if (!(func_ctx->mem_info[0].mem_base_addr = LLVMBuildLoad2(
                  comp_ctx->builder, OPQ_PTR_TYPE,
                  func_ctx->mem_info[0].mem_base_addr, "mem_base_addr"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
    }
#endif

    bound_check_type = (comp_ctx->pointer_size == sizeof(uint64))
                           ? INT64_PTR_TYPE
                           : INT32_PTR_TYPE;

    /* Load memory bound check constants */
    offset = I32_CONST(offsetof(AOTMemoryInstance, mem_bound_check_1byte)
                       - offsetof(AOTMemoryInstance, memory_data));
    if (!(func_ctx->mem_info[0].mem_bound_check_1byte =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, mem_info_base,
                                    &offset, 1, "bound_check_1byte_offset"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }
    if (!(func_ctx->mem_info[0].mem_bound_check_1byte = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_bound_check_1byte,
              bound_check_type, "bound_check_1byte_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (mem_space_unchanged) {
        if (!(func_ctx->mem_info[0].mem_bound_check_1byte = LLVMBuildLoad2(
                  comp_ctx->builder,
                  (comp_ctx->pointer_size == sizeof(uint64)) ? I64_TYPE
                                                             : I32_TYPE,
                  func_ctx->mem_info[0].mem_bound_check_1byte,
                  "bound_check_1byte"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
    }

    offset = I32_CONST(offsetof(AOTMemoryInstance, mem_bound_check_2bytes)
                       - offsetof(AOTMemoryInstance, memory_data));
    if (!(func_ctx->mem_info[0].mem_bound_check_2bytes =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, mem_info_base,
                                    &offset, 1, "bound_check_2bytes_offset"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }
    if (!(func_ctx->mem_info[0].mem_bound_check_2bytes = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_bound_check_2bytes,
              bound_check_type, "bound_check_2bytes_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (mem_space_unchanged) {
        if (!(func_ctx->mem_info[0].mem_bound_check_2bytes = LLVMBuildLoad2(
                  comp_ctx->builder,
                  (comp_ctx->pointer_size == sizeof(uint64)) ? I64_TYPE
                                                             : I32_TYPE,
                  func_ctx->mem_info[0].mem_bound_check_2bytes,
                  "bound_check_2bytes"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
    }

    offset = I32_CONST(offsetof(AOTMemoryInstance, mem_bound_check_4bytes)
                       - offsetof(AOTMemoryInstance, memory_data));
    if (!(func_ctx->mem_info[0].mem_bound_check_4bytes =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, mem_info_base,
                                    &offset, 1, "bound_check_4bytes_offset"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }
    if (!(func_ctx->mem_info[0].mem_bound_check_4bytes = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_bound_check_4bytes,
              bound_check_type, "bound_check_4bytes_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (mem_space_unchanged) {
        if (!(func_ctx->mem_info[0].mem_bound_check_4bytes = LLVMBuildLoad2(
                  comp_ctx->builder,
                  (comp_ctx->pointer_size == sizeof(uint64)) ? I64_TYPE
                                                             : I32_TYPE,
                  func_ctx->mem_info[0].mem_bound_check_4bytes,
                  "bound_check_4bytes"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
    }

    offset = I32_CONST(offsetof(AOTMemoryInstance, mem_bound_check_8bytes)
                       - offsetof(AOTMemoryInstance, memory_data));
    if (!(func_ctx->mem_info[0].mem_bound_check_8bytes =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, mem_info_base,
                                    &offset, 1, "bound_check_8bytes_offset"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }
    if (!(func_ctx->mem_info[0].mem_bound_check_8bytes = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_bound_check_8bytes,
              bound_check_type, "bound_check_8bytes_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (mem_space_unchanged) {
        if (!(func_ctx->mem_info[0].mem_bound_check_8bytes = LLVMBuildLoad2(
                  comp_ctx->builder,
                  (comp_ctx->pointer_size == sizeof(uint64)) ? I64_TYPE
                                                             : I32_TYPE,
                  func_ctx->mem_info[0].mem_bound_check_8bytes,
                  "bound_check_8bytes"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
    }

    offset = I32_CONST(offsetof(AOTMemoryInstance, mem_bound_check_16bytes)
                       - offsetof(AOTMemoryInstance, memory_data));
    if (!(func_ctx->mem_info[0].mem_bound_check_16bytes = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, INT8_TYPE, mem_info_base, &offset, 1,
              "bound_check_16bytes_offset"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }
    if (!(func_ctx->mem_info[0].mem_bound_check_16bytes = LLVMBuildBitCast(
              comp_ctx->builder, func_ctx->mem_info[0].mem_bound_check_16bytes,
              bound_check_type, "bound_check_16bytes_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }
    if (mem_space_unchanged) {
        if (!(func_ctx->mem_info[0].mem_bound_check_16bytes = LLVMBuildLoad2(
                  comp_ctx->builder,
                  (comp_ctx->pointer_size == sizeof(uint64)) ? I64_TYPE
                                                             : I32_TYPE,
                  func_ctx->mem_info[0].mem_bound_check_16bytes,
                  "bound_check_16bytes"))) {
            aot_set_last_error("llvm build load failed");
            return false;
        }
    }

    return true;
}

#define BUILD_IS_NOT_NULL(value, res, name)                                \
    do {                                                                   \
        if (!(res = LLVMBuildIsNotNull(comp_ctx->builder, value, name))) { \
            aot_set_last_error("llvm build is not null failed.");          \
            goto fail;                                                     \
        }                                                                  \
    } while (0)

#define get_module_extra_field_offset(field)                        \
    do {                                                            \
        offset_u32 = get_module_inst_extra_offset(comp_ctx);        \
        if (comp_ctx->is_jit_mode)                                  \
            offset_u32 += offsetof(WASMModuleInstanceExtra, field); \
        else                                                        \
            offset_u32 += offsetof(AOTModuleInstanceExtra, field);  \
    } while (0)

#define LOAD_MODULE_EXTRA_FIELD_AND_ALLOCA(field, type)                        \
    do {                                                                       \
        get_module_extra_field_offset(field);                                  \
        offset = I32_CONST(offset_u32);                                        \
        CHECK_LLVM_CONST(offset);                                              \
        if (!(field_p = LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE,    \
                                              func_ctx->aot_inst, &offset, 1,  \
                                              #field "_p"))) {                 \
            aot_set_last_error("llvm build inbounds gep failed");              \
            goto fail;                                                         \
        }                                                                      \
        if (!(load_val =                                                       \
                  LLVMBuildLoad2(comp_ctx->builder, type, field_p, #field))) { \
            aot_set_last_error("llvm build load failed");                      \
            goto fail;                                                         \
        }                                                                      \
        if (!(func_ctx->field =                                                \
                  LLVMBuildAlloca(comp_ctx->builder, type, #field))) {         \
            aot_set_last_error("llvm build alloca failed");                    \
            goto fail;                                                         \
        }                                                                      \
        if (!LLVMBuildStore(comp_ctx->builder, load_val, func_ctx->field)) {   \
            aot_set_last_error("llvm build store failed");                     \
            goto fail;                                                         \
        }                                                                      \
    } while (0)

static bool
create_shared_heap_info(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
#if WASM_ENABLE_SHARED_HEAP != 0
    LLVMValueRef offset, field_p, load_val, shared_heap_head_p,
        shared_heap_head, cmp, field_p_or_default, shared_heap_head_start_off,
        shared_heap_head_start_off_minus_one;
    LLVMTypeRef shared_heap_offset_type;
    uint32 offset_u32;
#if WASM_ENABLE_MEMORY64 == 0
    bool is_memory64 = false;
#else
    bool is_memory64 = IS_MEMORY64;
#endif

    shared_heap_offset_type =
        comp_ctx->pointer_size == sizeof(uint64) ? I64_TYPE : I32_TYPE;

    /* shared_heap_base_addr_adj, shared_heap_start_off, and
     * shared_heap_end_off can be updated later, use local variable to
     * represent them */
    LOAD_MODULE_EXTRA_FIELD_AND_ALLOCA(shared_heap_base_addr_adj,
                                       INT8_PTR_TYPE);
    LOAD_MODULE_EXTRA_FIELD_AND_ALLOCA(shared_heap_start_off,
                                       shared_heap_offset_type);
    LOAD_MODULE_EXTRA_FIELD_AND_ALLOCA(shared_heap_end_off,
                                       shared_heap_offset_type);

    /* Shared Heap head start off won't be updated, no need to alloca */
    get_module_extra_field_offset(shared_heap);
    offset = I32_CONST(offset_u32);
    CHECK_LLVM_CONST(offset);
    if (!(shared_heap_head_p = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, INT8_TYPE, func_ctx->aot_inst, &offset, 1,
              "shared_heap_head_p"))) {
        aot_set_last_error("llvm build inbounds gep failed");
        goto fail;
    }
    if (!(shared_heap_head =
              LLVMBuildLoad2(comp_ctx->builder, INT8_PTR_TYPE,
                             shared_heap_head_p, "shared_heap_head"))) {
        aot_set_last_error("llvm build load failed");
        goto fail;
    }
    BUILD_IS_NOT_NULL(shared_heap_head, cmp, "has_shared_heap");

    if (is_memory64) {
        offset_u32 = offsetof(WASMSharedHeap, start_off_mem64);
    }
    else {
        offset_u32 = offsetof(WASMSharedHeap, start_off_mem32);
    }
    offset = I32_CONST(offset_u32);
    CHECK_LLVM_CONST(offset);
    if (!(field_p = LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE,
                                          shared_heap_head, &offset, 1,
                                          "head_start_off_p"))) {
        aot_set_last_error("llvm build inbounds gep failed");
        goto fail;
    }

    /* Select a valid shared heap head ptr or safe alloca ptr stores
     * shared_heap_start_off(UINT32_MAX/UINT64_MAX) */
    if (!(field_p_or_default = LLVMBuildSelect(comp_ctx->builder, cmp, field_p,
                                               func_ctx->shared_heap_start_off,
                                               "ptr_or_default"))) {
        aot_set_last_error("llvm build select failed");
        goto fail;
    }

    if (!(shared_heap_head_start_off = LLVMBuildLoad2(
              comp_ctx->builder, shared_heap_offset_type, field_p_or_default,
              "shared_heap_head_start_off"))) {
        aot_set_last_error("llvm build load failed");
        goto fail;
    }
    if (!(shared_heap_head_start_off_minus_one = LLVMBuildAdd(
              comp_ctx->builder, shared_heap_head_start_off,
              comp_ctx->pointer_size == sizeof(uint64) ? I64_NEG_ONE
                                                       : I32_NEG_ONE,
              "head_start_off_minus_one"))) {
        aot_set_last_error("llvm build load failed");
        goto fail;
    }

    /* if there is attached shared heap(s), the value will be valid start_off-1,
     * otherwise it will be UINT32_MAX/UINT64_MAX, so during the bounds checks,
     * when has attached shared heap:
     *   offset > start_off - 1 => offset >= start_off
     * when no attached shared heap:
     *   offset > UINT32_MAX/UINT64_MAX is always false
     * */
    if (!(func_ctx->shared_heap_head_start_off = LLVMBuildSelect(
              comp_ctx->builder, cmp, shared_heap_head_start_off_minus_one,
              shared_heap_head_start_off, "head_start_off"))) {
        aot_set_last_error("llvm build select failed");
        goto fail;
    }
    return true;
fail:
    return false;
#else  /* else of WASM_ENABLE_SHARED_HEAP != 0 */
    return true;
#endif /* end of WASM_ENABLE_SHARED_HEAP != 0 */
}

static bool
create_cur_exception(const AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef offset;

    offset = I32_CONST(offsetof(AOTModuleInstance, cur_exception));
    func_ctx->cur_exception =
        LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, func_ctx->aot_inst,
                              &offset, 1, "cur_exception");
    if (!func_ctx->cur_exception) {
        aot_set_last_error("llvm build in bounds gep failed.");
        return false;
    }
    return true;
}

static bool
create_func_type_indexes(const AOTCompContext *comp_ctx,
                         AOTFuncContext *func_ctx)
{
    LLVMValueRef offset, func_type_indexes_ptr;
    LLVMTypeRef int32_ptr_type;

    offset = I32_CONST(offsetof(AOTModuleInstance, func_type_indexes));
    func_type_indexes_ptr =
        LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, func_ctx->aot_inst,
                              &offset, 1, "func_type_indexes_ptr");
    if (!func_type_indexes_ptr) {
        aot_set_last_error("llvm build add failed.");
        return false;
    }

    if (!(int32_ptr_type = LLVMPointerType(INT32_PTR_TYPE, 0))) {
        aot_set_last_error("llvm get pointer type failed.");
        return false;
    }

    func_ctx->func_type_indexes =
        LLVMBuildBitCast(comp_ctx->builder, func_type_indexes_ptr,
                         int32_ptr_type, "func_type_indexes_tmp");
    if (!func_ctx->func_type_indexes) {
        aot_set_last_error("llvm build bit cast failed.");
        return false;
    }

    func_ctx->func_type_indexes =
        LLVMBuildLoad2(comp_ctx->builder, INT32_PTR_TYPE,
                       func_ctx->func_type_indexes, "func_type_indexes");
    if (!func_ctx->func_type_indexes) {
        aot_set_last_error("llvm build load failed.");
        return false;
    }
    return true;
}

static bool
create_func_ptrs(const AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef offset;

    offset = I32_CONST(offsetof(AOTModuleInstance, func_ptrs));
    func_ctx->func_ptrs =
        LLVMBuildInBoundsGEP2(comp_ctx->builder, INT8_TYPE, func_ctx->aot_inst,
                              &offset, 1, "func_ptrs_offset");
    if (!func_ctx->func_ptrs) {
        aot_set_last_error("llvm build in bounds gep failed.");
        return false;
    }
    func_ctx->func_ptrs =
        LLVMBuildBitCast(comp_ctx->builder, func_ctx->func_ptrs,
                         comp_ctx->exec_env_type, "func_ptrs_tmp");
    if (!func_ctx->func_ptrs) {
        aot_set_last_error("llvm build bit cast failed.");
        return false;
    }

    func_ctx->func_ptrs = LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE,
                                         func_ctx->func_ptrs, "func_ptrs_ptr");
    if (!func_ctx->func_ptrs) {
        aot_set_last_error("llvm build load failed.");
        return false;
    }

    func_ctx->func_ptrs =
        LLVMBuildBitCast(comp_ctx->builder, func_ctx->func_ptrs,
                         comp_ctx->exec_env_type, "func_ptrs");
    if (!func_ctx->func_ptrs) {
        aot_set_last_error("llvm build bit cast failed.");
        return false;
    }

    return true;
}

const char *aot_stack_sizes_name = AOT_STACK_SIZES_NAME;
const char *aot_stack_sizes_alias_name = AOT_STACK_SIZES_ALIAS_NAME;
const char *aot_stack_sizes_section_name = AOT_STACK_SIZES_SECTION_NAME;

static bool
aot_create_stack_sizes(const AOTCompData *comp_data, AOTCompContext *comp_ctx)
{
    LLVMValueRef stack_sizes, *values, array, alias;
    LLVMTypeRef stack_sizes_type;
#if LLVM_VERSION_MAJOR <= 13
    LLVMTypeRef alias_type;
#endif
    uint64 size;
    uint32 i;

    stack_sizes_type = LLVMArrayType(I32_TYPE, comp_data->func_count);
    if (!stack_sizes_type) {
        aot_set_last_error("failed to create stack_sizes type.");
        return false;
    }

    stack_sizes =
        LLVMAddGlobal(comp_ctx->module, stack_sizes_type, aot_stack_sizes_name);
    if (!stack_sizes) {
        aot_set_last_error("failed to create stack_sizes global.");
        return false;
    }

    size = sizeof(LLVMValueRef) * comp_data->func_count;
    if (size >= UINT32_MAX || !(values = wasm_runtime_malloc((uint32)size))) {
        aot_set_last_error("allocate memory failed.");
        return false;
    }

    for (i = 0; i < comp_data->func_count; i++) {
        /*
         * This value is a placeholder, which will be replaced
         * after the corresponding functions are compiled.
         *
         * Don't use zeros because LLVM can optimize them to
         * zeroinitializer.
         */
        values[i] = I32_NEG_ONE;
    }

    array = LLVMConstArray(I32_TYPE, values, comp_data->func_count);
    wasm_runtime_free(values);
    if (!array) {
        aot_set_last_error("failed to create stack_sizes initializer.");
        return false;
    }
    LLVMSetInitializer(stack_sizes, array);

    /*
     * create an alias so that aot_resolve_stack_sizes can find it.
     */
#if LLVM_VERSION_MAJOR > 13
    alias = LLVMAddAlias2(comp_ctx->module, stack_sizes_type, 0, stack_sizes,
                          aot_stack_sizes_alias_name);
#else
    alias_type = LLVMPointerType(stack_sizes_type, 0);
    if (!alias_type) {
        aot_set_last_error("failed to create alias type.");
        return false;
    }
    alias = LLVMAddAlias(comp_ctx->module, alias_type, stack_sizes,
                         aot_stack_sizes_alias_name);
#endif
    if (!alias) {
        aot_set_last_error("failed to create stack_sizes alias.");
        return false;
    }

    /*
     * make the original symbol internal. we mainly use this version to
     * avoid creating extra relocations in the precheck functions.
     */
    LLVMSetLinkage(stack_sizes, LLVMInternalLinkage);
    /*
     * for AOT, place it into a dedicated section for the convenience
     * of the AOT file generation and symbol resolutions.
     *
     * for JIT, it doesn't matter.
     */
    if (!comp_ctx->is_jit_mode) {
        LLVMSetSection(stack_sizes, aot_stack_sizes_section_name);
    }
    comp_ctx->stack_sizes_type = stack_sizes_type;
    comp_ctx->stack_sizes = stack_sizes;
    return true;
}

/**
 * Create function compiler context
 */
static AOTFuncContext *
aot_create_func_context(const AOTCompData *comp_data, AOTCompContext *comp_ctx,
                        AOTFunc *func, uint32 func_index)
{
    AOTFuncContext *func_ctx;
    AOTFuncType *aot_func_type =
        (AOTFuncType *)comp_data->types[func->func_type_index];
    WASMModule *module = comp_ctx->comp_data->wasm_module;
    WASMFunction *wasm_func = module->functions[func_index];
    AOTBlock *aot_block;
    LLVMTypeRef int8_ptr_type;
    uint64 size;

    /* Allocate memory for the function context */
    size = offsetof(AOTFuncContext, locals)
           + sizeof(LLVMValueRef)
                 * ((uint64)aot_func_type->param_count + func->local_count);
    if (size >= UINT32_MAX || !(func_ctx = wasm_runtime_malloc((uint32)size))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }

    memset(func_ctx, 0, (uint32)size);
    func_ctx->aot_func = func;

    func_ctx->module = comp_ctx->module;

    /* Add LLVM function */
    if (!(func_ctx->func = aot_add_llvm_func(
              comp_ctx, func_ctx->module, aot_func_type, func_index,
              &func_ctx->func_type, &func_ctx->precheck_func))) {
        goto fail;
    }

    /* Create function's first AOTBlock */
    if (!(aot_block =
              aot_create_func_block(comp_ctx, func_ctx, func, aot_func_type))) {
        goto fail;
    }

#if WASM_ENABLE_DEBUG_AOT != 0
    func_ctx->debug_func = dwarf_gen_func_info(comp_ctx, func_ctx);
#endif

    aot_block_stack_push(&func_ctx->block_stack, aot_block);

    /* Add local variables */
    LLVMPositionBuilderAtEnd(comp_ctx->builder, aot_block->llvm_entry_block);

    if (!create_basic_func_context(comp_ctx, func_ctx)) {
        goto fail;
    }

    /* Get argv buffer address */
    if (wasm_func->has_op_func_call && !create_argv_buf(comp_ctx, func_ctx)) {
        goto fail;
    }

    /* Get auxiliary stack info */
    if (wasm_func->has_op_set_global_aux_stack
        && !create_aux_stack_info(comp_ctx, func_ctx)) {
        goto fail;
    }

    if (comp_ctx->aux_stack_frame_type
        && !create_aux_stack_frame(comp_ctx, func_ctx)) {
        goto fail;
    }

    /* Create local variables */
    if (!create_local_variables(comp_data, comp_ctx, func_ctx, func)) {
        goto fail;
    }

    if (!(int8_ptr_type = LLVMPointerType(INT8_PTR_TYPE, 0))) {
        aot_set_last_error("llvm add pointer type failed.");
        goto fail;
    }

    /* Create base addr, end addr, data size of mem, heap */
    if (wasm_func->has_memory_operations
        && !create_memory_info(comp_ctx, func_ctx, int8_ptr_type, func_index)) {
        goto fail;
    }

    /* Load current exception */
    if (!create_cur_exception(comp_ctx, func_ctx)) {
        goto fail;
    }

    /* Load function type indexes */
    if (wasm_func->has_op_call_indirect
        && !create_func_type_indexes(comp_ctx, func_ctx)) {
        goto fail;
    }

    /* Load function pointers */
    if (!create_func_ptrs(comp_ctx, func_ctx)) {
        goto fail;
    }

    /* Load shared heap, shared heap start off mem32 or mem64 */
    if ((comp_ctx->enable_shared_heap || comp_ctx->enable_shared_chain)
        && !create_shared_heap_info(comp_ctx, func_ctx)) {
        goto fail;
    }

    return func_ctx;

fail:
    if (func_ctx->mem_info)
        wasm_runtime_free(func_ctx->mem_info);
    aot_block_stack_destroy(comp_ctx, &func_ctx->block_stack);
    wasm_runtime_free(func_ctx);
    return NULL;
}

static void
aot_destroy_func_contexts(AOTCompContext *comp_ctx, AOTFuncContext **func_ctxes,
                          uint32 count)
{
    uint32 i;

    for (i = 0; i < count; i++)
        if (func_ctxes[i]) {
            if (func_ctxes[i]->mem_info)
                wasm_runtime_free(func_ctxes[i]->mem_info);
            aot_block_stack_destroy(comp_ctx, &func_ctxes[i]->block_stack);
            aot_checked_addr_list_destroy(func_ctxes[i]);
            wasm_runtime_free(func_ctxes[i]);
        }
    wasm_runtime_free(func_ctxes);
}

/**
 * Create function compiler contexts
 */
static AOTFuncContext **
aot_create_func_contexts(const AOTCompData *comp_data, AOTCompContext *comp_ctx)
{
    AOTFuncContext **func_ctxes;
    uint64 size;
    uint32 i;

    if ((comp_ctx->enable_stack_bound_check
         || comp_ctx->enable_stack_estimation)
        && !aot_create_stack_sizes(comp_data, comp_ctx))
        return NULL;

    /* Allocate memory */
    size = sizeof(AOTFuncContext *) * (uint64)comp_data->func_count;
    if (size >= UINT32_MAX
        || !(func_ctxes = wasm_runtime_malloc((uint32)size))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }

    memset(func_ctxes, 0, size);

    /* Create each function context */
    for (i = 0; i < comp_data->func_count; i++) {
        AOTFunc *func = comp_data->funcs[i];
        if (!(func_ctxes[i] =
                  aot_create_func_context(comp_data, comp_ctx, func, i))) {
            aot_destroy_func_contexts(comp_ctx, func_ctxes,
                                      comp_data->func_count);
            return NULL;
        }
    }

    return func_ctxes;
}

static bool
aot_set_llvm_basic_types(AOTLLVMTypes *basic_types, LLVMContextRef context,
                         int pointer_size)
{
    basic_types->int1_type = LLVMInt1TypeInContext(context);
    basic_types->int8_type = LLVMInt8TypeInContext(context);
    basic_types->int16_type = LLVMInt16TypeInContext(context);
    basic_types->int32_type = LLVMInt32TypeInContext(context);
    basic_types->int64_type = LLVMInt64TypeInContext(context);
    basic_types->float32_type = LLVMFloatTypeInContext(context);
    basic_types->float64_type = LLVMDoubleTypeInContext(context);
    basic_types->void_type = LLVMVoidTypeInContext(context);

    basic_types->meta_data_type = LLVMMetadataTypeInContext(context);

    basic_types->int8_ptr_type = LLVMPointerType(basic_types->int8_type, 0);

    if (basic_types->int8_ptr_type) {
        basic_types->int8_pptr_type =
            LLVMPointerType(basic_types->int8_ptr_type, 0);
    }

    basic_types->int16_ptr_type = LLVMPointerType(basic_types->int16_type, 0);
    basic_types->int32_ptr_type = LLVMPointerType(basic_types->int32_type, 0);
    basic_types->int64_ptr_type = LLVMPointerType(basic_types->int64_type, 0);
    basic_types->float32_ptr_type =
        LLVMPointerType(basic_types->float32_type, 0);
    basic_types->float64_ptr_type =
        LLVMPointerType(basic_types->float64_type, 0);

    basic_types->i8x16_vec_type = LLVMVectorType(basic_types->int8_type, 16);
    basic_types->i16x8_vec_type = LLVMVectorType(basic_types->int16_type, 8);
    basic_types->i32x4_vec_type = LLVMVectorType(basic_types->int32_type, 4);
    basic_types->i64x2_vec_type = LLVMVectorType(basic_types->int64_type, 2);
    basic_types->f32x4_vec_type = LLVMVectorType(basic_types->float32_type, 4);
    basic_types->f64x2_vec_type = LLVMVectorType(basic_types->float64_type, 2);

    basic_types->v128_type = basic_types->i64x2_vec_type;
    basic_types->v128_ptr_type = LLVMPointerType(basic_types->v128_type, 0);

    basic_types->int8_ptr_type_gs =
        LLVMPointerType(basic_types->int8_type, 256);
    basic_types->int16_ptr_type_gs =
        LLVMPointerType(basic_types->int16_type, 256);
    basic_types->int32_ptr_type_gs =
        LLVMPointerType(basic_types->int32_type, 256);
    basic_types->int64_ptr_type_gs =
        LLVMPointerType(basic_types->int64_type, 256);
    basic_types->float32_ptr_type_gs =
        LLVMPointerType(basic_types->float32_type, 256);
    basic_types->float64_ptr_type_gs =
        LLVMPointerType(basic_types->float64_type, 256);
    basic_types->v128_ptr_type_gs =
        LLVMPointerType(basic_types->v128_type, 256);
    if (!basic_types->int8_ptr_type_gs || !basic_types->int16_ptr_type_gs
        || !basic_types->int32_ptr_type_gs || !basic_types->int64_ptr_type_gs
        || !basic_types->float32_ptr_type_gs
        || !basic_types->float64_ptr_type_gs
        || !basic_types->v128_ptr_type_gs) {
        return false;
    }

    basic_types->i1x2_vec_type = LLVMVectorType(basic_types->int1_type, 2);

    basic_types->funcref_type = LLVMInt32TypeInContext(context);
    basic_types->externref_type = LLVMInt32TypeInContext(context);

    if (pointer_size == 4) {
        basic_types->intptr_t_type = basic_types->int32_type;
        basic_types->intptr_t_ptr_type = basic_types->int32_ptr_type;
        basic_types->size_t_type = basic_types->int32_type;
    }
    else {
        basic_types->intptr_t_type = basic_types->int64_type;
        basic_types->intptr_t_ptr_type = basic_types->int64_ptr_type;
        basic_types->size_t_type = basic_types->int64_type;
    }

    basic_types->gc_ref_type = basic_types->int8_ptr_type;
    basic_types->gc_ref_ptr_type = basic_types->int8_pptr_type;

    return (basic_types->int8_ptr_type && basic_types->int8_pptr_type
            && basic_types->int16_ptr_type && basic_types->int32_ptr_type
            && basic_types->int64_ptr_type && basic_types->intptr_t_type
            && basic_types->intptr_t_ptr_type && basic_types->float32_ptr_type
            && basic_types->float64_ptr_type && basic_types->i8x16_vec_type
            && basic_types->i16x8_vec_type && basic_types->i32x4_vec_type
            && basic_types->i64x2_vec_type && basic_types->f32x4_vec_type
            && basic_types->f64x2_vec_type && basic_types->i1x2_vec_type
            && basic_types->meta_data_type && basic_types->funcref_type
            && basic_types->externref_type && basic_types->gc_ref_type
            && basic_types->gc_ref_ptr_type)
               ? true
               : false;
}

static bool
aot_create_llvm_consts(AOTLLVMConsts *consts, AOTCompContext *comp_ctx)
{
#define CREATE_I1_CONST(name, value)                                       \
    if (!(consts->i1_##name =                                              \
              LLVMConstInt(comp_ctx->basic_types.int1_type, value, true))) \
        return false;

    CREATE_I1_CONST(zero, 0)
    CREATE_I1_CONST(one, 1)
#undef CREATE_I1_CONST

    if (!(consts->i8_zero = I8_CONST(0)))
        return false;

    if (!(consts->i8_one = I8_CONST(1)))
        return false;

    if (!(consts->f32_zero = F32_CONST(0)))
        return false;

    if (!(consts->f64_zero = F64_CONST(0)))
        return false;

#define CREATE_I32_CONST(name, value)                                \
    if (!(consts->i32_##name = LLVMConstInt(I32_TYPE, value, true))) \
        return false;

    CREATE_I32_CONST(min, (uint32)INT32_MIN)
    CREATE_I32_CONST(neg_one, (uint32)-1)
    CREATE_I32_CONST(zero, 0)
    CREATE_I32_CONST(one, 1)
    CREATE_I32_CONST(two, 2)
    CREATE_I32_CONST(three, 3)
    CREATE_I32_CONST(four, 4)
    CREATE_I32_CONST(five, 5)
    CREATE_I32_CONST(six, 6)
    CREATE_I32_CONST(seven, 7)
    CREATE_I32_CONST(eight, 8)
    CREATE_I32_CONST(nine, 9)
    CREATE_I32_CONST(ten, 10)
    CREATE_I32_CONST(eleven, 11)
    CREATE_I32_CONST(twelve, 12)
    CREATE_I32_CONST(thirteen, 13)
    CREATE_I32_CONST(fourteen, 14)
    CREATE_I32_CONST(fifteen, 15)
    CREATE_I32_CONST(31, 31)
    CREATE_I32_CONST(32, 32)
#undef CREATE_I32_CONST

#define CREATE_I64_CONST(name, value)                                \
    if (!(consts->i64_##name = LLVMConstInt(I64_TYPE, value, true))) \
        return false;

    CREATE_I64_CONST(min, (uint64)INT64_MIN)
    CREATE_I64_CONST(neg_one, (uint64)-1)
    CREATE_I64_CONST(zero, 0)
    CREATE_I64_CONST(63, 63)
    CREATE_I64_CONST(64, 64)
#undef CREATE_I64_CONST

#define CREATE_V128_CONST(name, type)                     \
    if (!(consts->name##_vec_zero = LLVMConstNull(type))) \
        return false;                                     \
    if (!(consts->name##_undef = LLVMGetUndef(type)))     \
        return false;

    CREATE_V128_CONST(i8x16, V128_i8x16_TYPE)
    CREATE_V128_CONST(i16x8, V128_i16x8_TYPE)
    CREATE_V128_CONST(i32x4, V128_i32x4_TYPE)
    CREATE_V128_CONST(i64x2, V128_i64x2_TYPE)
    CREATE_V128_CONST(f32x4, V128_f32x4_TYPE)
    CREATE_V128_CONST(f64x2, V128_f64x2_TYPE)
#undef CREATE_V128_CONST

#define CREATE_VEC_ZERO_MASK(slot)                                       \
    {                                                                    \
        LLVMTypeRef type = LLVMVectorType(I32_TYPE, slot);               \
        if (!type || !(consts->i32x##slot##_zero = LLVMConstNull(type))) \
            return false;                                                \
    }

    CREATE_VEC_ZERO_MASK(16)
    CREATE_VEC_ZERO_MASK(8)
    CREATE_VEC_ZERO_MASK(4)
    CREATE_VEC_ZERO_MASK(2)
#undef CREATE_VEC_ZERO_MASK

    if (!(consts->gc_ref_null =
              LLVMConstNull(comp_ctx->basic_types.gc_ref_type)))
        return false;
    if (!(consts->i8_ptr_null =
              LLVMConstNull(comp_ctx->basic_types.int8_ptr_type)))
        return false;

    return true;
}

typedef struct ArchItem {
    char *arch;
    bool support_eb;
} ArchItem;

/* clang-format off */
static ArchItem valid_archs[] = {
    { "x86_64", false },
    { "i386", false },
    { "xtensa", false },
    { "mips", true },
    { "mipsel", false },
    { "aarch64v8", false },
    { "aarch64v8.1", false },
    { "aarch64v8.2", false },
    { "aarch64v8.3", false },
    { "aarch64v8.4", false },
    { "aarch64v8.5", false },
    { "aarch64_bev8", false }, /* big endian */
    { "aarch64_bev8.1", false },
    { "aarch64_bev8.2", false },
    { "aarch64_bev8.3", false },
    { "aarch64_bev8.4", false },
    { "aarch64_bev8.5", false },
    { "armv4", true },
    { "armv4t", true },
    { "armv5t", true },
    { "armv5te", true },
    { "armv5tej", true },
    { "armv6", true },
    { "armv6kz", true },
    { "armv6t2", true },
    { "armv6k", true },
    { "armv7", true },
    { "armv6m", true },
    { "armv6sm", true },
    { "armv7em", true },
    { "armv8a", true },
    { "armv8r", true },
    { "armv8m.base", true },
    { "armv8m.main", true },
    { "armv8.1m.main", true },
    { "thumbv4", true },
    { "thumbv4t", true },
    { "thumbv5t", true },
    { "thumbv5te", true },
    { "thumbv5tej", true },
    { "thumbv6", true },
    { "thumbv6kz", true },
    { "thumbv6t2", true },
    { "thumbv6k", true },
    { "thumbv7", true },
    { "thumbv6m", true },
    { "thumbv6sm", true },
    { "thumbv7em", true },
    { "thumbv8a", true },
    { "thumbv8r", true },
    { "thumbv8m.base", true },
    { "thumbv8m.main", true },
    { "thumbv8.1m.main", true },
    { "riscv32", true },
    { "riscv64", true },
    { "arc", true }
};

static const char *valid_abis[] = {
    "gnu",
    "eabi",
    "eabihf",
    "gnueabihf",
    "msvc",
    "ilp32",
    "ilp32f",
    "ilp32d",
    "lp64",
    "lp64f",
    "lp64d"
};
/* clang-format on */

static void
print_supported_targets()
{
    uint32 i;
    const char *target_name;

    os_printf("Supported targets:\n");
    /* over the list of all available targets */
    for (LLVMTargetRef target = LLVMGetFirstTarget(); target != NULL;
         target = LLVMGetNextTarget(target)) {
        target_name = LLVMGetTargetName(target);
        /* Skip mipsel, aarch64_be since prefix mips, aarch64 will cover them */
        if (strcmp(target_name, "mipsel") == 0)
            continue;
        else if (strcmp(target_name, "aarch64_be") == 0)
            continue;

        if (strcmp(target_name, "x86-64") == 0)
            os_printf("  x86_64\n");
        else if (strcmp(target_name, "x86") == 0)
            os_printf("  i386\n");
        else {
            for (i = 0; i < sizeof(valid_archs) / sizeof(ArchItem); i++) {
                /* If target_name is prefix for valid_archs[i].arch */
                if ((strncmp(target_name, valid_archs[i].arch,
                             strlen(target_name))
                     == 0))
                    os_printf("  %s\n", valid_archs[i].arch);
            }
        }
    }
}

static void
print_supported_abis()
{
    uint32 i;
    os_printf("Supported ABI: ");
    for (i = 0; i < sizeof(valid_abis) / sizeof(const char *); i++)
        os_printf("%s ", valid_abis[i]);
    os_printf("\n");
}

static bool
check_target_arch(const char *target_arch)
{
    uint32 i;
    char *arch;
    bool support_eb;

    for (i = 0; i < sizeof(valid_archs) / sizeof(ArchItem); i++) {
        arch = valid_archs[i].arch;
        support_eb = valid_archs[i].support_eb;

        if (!strncmp(target_arch, arch, strlen(arch))
            && ((support_eb
                 && (!strcmp(target_arch + strlen(arch), "eb")
                     || !strcmp(target_arch + strlen(arch), "")))
                || (!support_eb && !strcmp(target_arch + strlen(arch), "")))) {
            return true;
        }
    }
    return false;
}

static bool
check_target_abi(const char *target_abi)
{
    uint32 i;
    for (i = 0; i < sizeof(valid_abis) / sizeof(char *); i++) {
        if (!strcmp(target_abi, valid_abis[i]))
            return true;
    }
    return false;
}

static void
get_target_arch_from_triple(const char *triple, char *arch_buf, uint32 buf_size)
{
    uint32 i = 0;
    while (*triple != '-' && *triple != '\0' && i < buf_size - 1)
        arch_buf[i++] = *triple++;
    /* Make sure buffer is long enough */
    bh_assert(*triple == '-' || *triple == '\0');
}

static bool
is_baremetal_target(const char *target, const char *cpu, const char *abi)
{
    /* TODO: support more baremetal targets */
    if (target) {
        /* If target is thumbxxx, then it is baremetal target */
        if (!strncmp(target, "thumb", strlen("thumb")))
            return true;
    }
    return false;
}

void
aot_handle_llvm_errmsg(const char *string, LLVMErrorRef err)
{
    char *err_msg = LLVMGetErrorMessage(err);
    aot_set_last_error_v("%s: %s", string, err_msg);
    LLVMDisposeErrorMessage(err_msg);
}

static bool
create_target_machine_detect_host(AOTCompContext *comp_ctx)
{
    char *triple = NULL;
    LLVMTargetRef target = NULL;
    char *err_msg = NULL;
    char *cpu = NULL;
    char *features = NULL;
    LLVMTargetMachineRef target_machine = NULL;
    bool ret = false;

    triple = LLVMGetDefaultTargetTriple();
    if (triple == NULL) {
        aot_set_last_error("failed to get default target triple.");
        goto fail;
    }

    if (LLVMGetTargetFromTriple(triple, &target, &err_msg) != 0) {
        aot_set_last_error_v("failed to get llvm target from triple %s.",
                             err_msg);
        LLVMDisposeMessage(err_msg);
        goto fail;
    }

    if (!LLVMTargetHasJIT(target)) {
        aot_set_last_error("unsupported JIT on this platform.");
        goto fail;
    }

    cpu = LLVMGetHostCPUName();
    if (cpu == NULL) {
        aot_set_last_error("failed to get host cpu information.");
        goto fail;
    }

    features = LLVMGetHostCPUFeatures();
    if (features == NULL) {
        aot_set_last_error("failed to get host cpu features.");
        goto fail;
    }

    LOG_VERBOSE("LLVM ORCJIT detected CPU \"%s\", with features \"%s\"\n", cpu,
                features);

    /* create TargetMachine */
    target_machine = LLVMCreateTargetMachine(
        target, triple, cpu, features, LLVMCodeGenLevelDefault,
        LLVMRelocDefault, LLVMCodeModelJITDefault);
    if (!target_machine) {
        aot_set_last_error("failed to create target machine.");
        goto fail;
    }
    comp_ctx->target_machine = target_machine;

    /* Save target arch */
    get_target_arch_from_triple(triple, comp_ctx->target_arch,
                                sizeof(comp_ctx->target_arch));
    ret = true;

fail:
    if (triple)
        LLVMDisposeMessage(triple);
    if (features)
        LLVMDisposeMessage(features);
    if (cpu)
        LLVMDisposeMessage(cpu);

    return ret;
}

static void
jit_stack_size_callback(void *user_data, const char *name, size_t namelen,
                        size_t stack_size)
{
    AOTCompContext *comp_ctx = user_data;
    /*
     * Note: the longest name we care is
     * something like "aot_func_internal#4294967295".
     */
    char buf[64];
    uint32 func_idx;
    const AOTFuncContext *func_ctx;
    bool musttail;
    unsigned int stack_consumption_to_call_wrapped_func;
    unsigned int call_size;
    int ret;

    bh_assert(comp_ctx != NULL);
    bh_assert(comp_ctx->jit_stack_sizes != NULL);

    if (namelen >= sizeof(buf)) {
        LOG_DEBUG("too long name: %.*s", (int)namelen, name);
        return;
    }
    /* ensure NUL termination */
    bh_memcpy_s(buf, (uint32)sizeof(buf), name, (uint32)namelen);
    buf[namelen] = 0;

    ret = sscanf(buf, AOT_FUNC_INTERNAL_PREFIX "%" SCNu32, &func_idx);
    if (ret != 1) {
        return;
    }

    bh_assert(func_idx < comp_ctx->func_ctx_count);
    func_ctx = comp_ctx->func_ctxes[func_idx];
    call_size = func_ctx->stack_consumption_for_func_call;
    musttail = aot_target_precheck_can_use_musttail(comp_ctx);
    stack_consumption_to_call_wrapped_func =
        musttail ? 0
                 : aot_estimate_stack_usage_for_function_call(
                     comp_ctx, func_ctx->aot_func->func_type);
    LOG_VERBOSE("func %.*s stack %u + %zu + %u", (int)namelen, name,
                stack_consumption_to_call_wrapped_func, stack_size, call_size);

    /* Note: -1 == AOT_NEG_ONE from aot_create_stack_sizes */
    bh_assert(comp_ctx->jit_stack_sizes[func_idx] == (uint32)-1);
    comp_ctx->jit_stack_sizes[func_idx] = (uint32)stack_size + call_size;
}

static bool
orc_jit_create(AOTCompContext *comp_ctx)
{
    LLVMErrorRef err;
    LLVMOrcLLLazyJITRef orc_jit = NULL;
    LLVMOrcLLLazyJITBuilderRef builder = NULL;
    LLVMOrcJITTargetMachineBuilderRef jtmb = NULL;
    bool ret = false;

    builder = LLVMOrcCreateLLLazyJITBuilder();
    if (builder == NULL) {
        aot_set_last_error("failed to create jit builder.");
        goto fail;
    }

    if (comp_ctx->enable_stack_bound_check || comp_ctx->enable_stack_estimation)
        LLVMOrcLLJITBuilderSetCompileFunctionCreatorWithStackSizesCallback(
            builder, jit_stack_size_callback, comp_ctx);

    err = LLVMOrcJITTargetMachineBuilderDetectHost(&jtmb);
    if (err != LLVMErrorSuccess) {
        aot_handle_llvm_errmsg(
            "quited to create LLVMOrcJITTargetMachineBuilderRef", err);
        goto fail;
    }

    LLVMOrcLLLazyJITBuilderSetNumCompileThreads(
        builder, WASM_ORC_JIT_COMPILE_THREAD_NUM);

    /* Ownership transfer:
       LLVMOrcJITTargetMachineBuilderRef -> LLVMOrcLLJITBuilderRef */
    LLVMOrcLLLazyJITBuilderSetJITTargetMachineBuilder(builder, jtmb);
    err = LLVMOrcCreateLLLazyJIT(&orc_jit, builder);
    if (err != LLVMErrorSuccess) {
        aot_handle_llvm_errmsg("quited to create llvm lazy orcjit instance",
                               err);
        goto fail;
    }
    /* Ownership transfer: LLVMOrcLLJITBuilderRef -> LLVMOrcLLJITRef */
    builder = NULL;

#if WASM_ENABLE_LINUX_PERF != 0
    if (wasm_runtime_get_linux_perf()) {
        LOG_DEBUG("Enable linux perf support in JIT");
        LLVMOrcObjectLayerRef obj_linking_layer =
            (LLVMOrcObjectLayerRef)LLVMOrcLLLazyJITGetObjLinkingLayer(orc_jit);
        LLVMOrcRTDyldObjectLinkingLayerRegisterJITEventListener(
            obj_linking_layer, LLVMCreatePerfJITEventListener());
    }
#endif

    /* Ownership transfer: local -> AOTCompContext */
    comp_ctx->orc_jit = orc_jit;
    orc_jit = NULL;
    ret = true;

fail:
    if (builder)
        LLVMOrcDisposeLLLazyJITBuilder(builder);

    if (orc_jit)
        LLVMOrcDisposeLLLazyJIT(orc_jit);
    return ret;
}

bool
aot_compiler_init(void)
{
    /* Initialize LLVM environment */
#if LLVM_VERSION_MAJOR < 17
    LLVMInitializeCore(LLVMGetGlobalPassRegistry());
#endif

/* fuzzing only use host targets for simple */
#if WASM_ENABLE_WAMR_COMPILER != 0 && WASM_ENABLE_FUZZ_TEST == 0
    /* Init environment of all targets for AOT compiler */
    LLVMInitializeAllTargetInfos();
    LLVMInitializeAllTargets();
    LLVMInitializeAllTargetMCs();
    LLVMInitializeAllAsmPrinters();
#else
    /* Init environment of native for JIT compiler */
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeTarget();
    LLVMInitializeNativeAsmPrinter();
#endif

    return true;
}

void
aot_compiler_destroy(void)
{
    LLVMShutdown();
}

AOTCompContext *
aot_create_comp_context(const AOTCompData *comp_data, aot_comp_option_t option)
{
    AOTCompContext *comp_ctx, *ret = NULL;
    LLVMTargetRef target;
    char *triple = NULL, *triple_norm, *arch, *abi;
    char *cpu = NULL, *features, buf[128];
    char *triple_norm_new = NULL, *cpu_new = NULL;
    char *err = NULL, *fp_round = "round.tonearest",
         *fp_exce = "fpexcept.strict";
    char triple_buf[128] = { 0 }, features_buf[128] = { 0 };
    uint32 opt_level, size_level, i;
    LLVMCodeModel code_model;
    LLVMTargetDataRef target_data_ref;

    /* Allocate memory */
    if (!(comp_ctx = wasm_runtime_malloc(sizeof(AOTCompContext)))) {
        aot_set_last_error("allocate memory failed.");
        return NULL;
    }

    memset(comp_ctx, 0, sizeof(AOTCompContext));
    comp_ctx->comp_data = comp_data;

    /* Create LLVM context, module and builder */
    comp_ctx->orc_thread_safe_context = LLVMOrcCreateNewThreadSafeContext();
    if (!comp_ctx->orc_thread_safe_context) {
        aot_set_last_error("create LLVM ThreadSafeContext failed.");
        goto fail;
    }

    /* Get a reference to the underlying LLVMContext, note:
         different from non LAZY JIT mode, no need to dispose this context,
         if will be disposed when the thread safe context is disposed */
    if (!(comp_ctx->context = LLVMOrcThreadSafeContextGetContext(
              comp_ctx->orc_thread_safe_context))) {
        aot_set_last_error("get context from LLVM ThreadSafeContext failed.");
        goto fail;
    }

    if (!(comp_ctx->builder = LLVMCreateBuilderInContext(comp_ctx->context))) {
        aot_set_last_error("create LLVM builder failed.");
        goto fail;
    }

    /* Create LLVM module for each jit function, note:
       different from non ORC JIT mode, no need to dispose it,
       it will be disposed when the thread safe context is disposed */
    if (!(comp_ctx->module = LLVMModuleCreateWithNameInContext(
              "WASM Module", comp_ctx->context))) {
        aot_set_last_error("create LLVM module failed.");
        goto fail;
    }
#if LLVM_VERSION_MAJOR >= 19
    LLVMSetIsNewDbgInfoFormat(comp_ctx->module, true);
#endif

#if WASM_ENABLE_LINUX_PERF != 0
    if (wasm_runtime_get_linux_perf()) {
        /* FramePointerKind.All */
        LLVMMetadataRef val =
            LLVMValueAsMetadata(LLVMConstInt(LLVMInt32Type(), 2, false));
        const char *key = "frame-pointer";
        LLVMAddModuleFlag(comp_ctx->module, LLVMModuleFlagBehaviorWarning, key,
                          strlen(key), val);

        comp_ctx->emit_frame_pointer = true;
    }
#endif

    if (BH_LIST_ERROR == bh_list_init(&comp_ctx->native_symbols)) {
        goto fail;
    }

#if WASM_ENABLE_DEBUG_AOT != 0
    if (!(comp_ctx->debug_builder = LLVMCreateDIBuilder(comp_ctx->module))) {
        aot_set_last_error("create LLVM Debug Infor builder failed.");
        goto fail;
    }

    LLVMAddModuleFlag(
        comp_ctx->module, LLVMModuleFlagBehaviorWarning, "Debug Info Version",
        strlen("Debug Info Version"),
        LLVMValueAsMetadata(LLVMConstInt(LLVMInt32Type(), 3, false)));

    comp_ctx->debug_file = dwarf_gen_file_info(comp_ctx);
    if (!comp_ctx->debug_file) {
        aot_set_last_error("dwarf generate file info failed");
        goto fail;
    }
    comp_ctx->debug_comp_unit = dwarf_gen_comp_unit_info(comp_ctx);
    if (!comp_ctx->debug_comp_unit) {
        aot_set_last_error("dwarf generate compile unit info failed");
        goto fail;
    }
#endif

    if (option->enable_bulk_memory)
        comp_ctx->enable_bulk_memory = true;

    if (option->enable_thread_mgr)
        comp_ctx->enable_thread_mgr = true;

    if (option->enable_tail_call)
        comp_ctx->enable_tail_call = true;

    if (option->enable_ref_types)
        comp_ctx->enable_ref_types = true;

    comp_ctx->aux_stack_frame_type = option->aux_stack_frame_type;
    comp_ctx->call_stack_features = option->call_stack_features;

    if (option->enable_perf_profiling)
        comp_ctx->enable_perf_profiling = true;

    if (option->enable_memory_profiling)
        comp_ctx->enable_memory_profiling = true;

    if (option->enable_aux_stack_check)
        comp_ctx->enable_aux_stack_check = true;

    if (option->is_indirect_mode) {
        comp_ctx->is_indirect_mode = true;
        /* avoid LUT relocations ("switch-table") */
        comp_ctx->disable_llvm_jump_tables = true;
    }

    if (option->disable_llvm_intrinsics)
        comp_ctx->disable_llvm_intrinsics = true;

    if (option->disable_llvm_jump_tables)
        comp_ctx->disable_llvm_jump_tables = true;

    if (option->disable_llvm_lto)
        comp_ctx->disable_llvm_lto = true;

    if (option->enable_llvm_pgo)
        comp_ctx->enable_llvm_pgo = true;

    if (option->use_prof_file)
        comp_ctx->use_prof_file = option->use_prof_file;

    if (option->enable_stack_estimation)
        comp_ctx->enable_stack_estimation = true;

    if (option->quick_invoke_c_api_import)
        comp_ctx->quick_invoke_c_api_import = true;

    if (option->llvm_passes)
        comp_ctx->llvm_passes = option->llvm_passes;

    if (option->builtin_intrinsics)
        comp_ctx->builtin_intrinsics = option->builtin_intrinsics;

    if (option->enable_gc)
        comp_ctx->enable_gc = true;

    if (option->enable_shared_heap)
        comp_ctx->enable_shared_heap = true;

    if (option->enable_shared_chain)
        comp_ctx->enable_shared_chain = true;

    if (option->enable_extended_const)
        comp_ctx->enable_extended_const = true;

    comp_ctx->opt_level = option->opt_level;
    comp_ctx->size_level = option->size_level;

    comp_ctx->custom_sections_wp = option->custom_sections;
    comp_ctx->custom_sections_count = option->custom_sections_count;

    if (option->is_jit_mode) {
        comp_ctx->is_jit_mode = true;

#ifndef OS_ENABLE_HW_BOUND_CHECK
        comp_ctx->enable_bound_check = true;
        /* Always enable stack boundary check if `bounds-checks`
           is enabled */
        comp_ctx->enable_stack_bound_check = true;
#else
        comp_ctx->enable_bound_check = false;
        /* When `bounds-checks` is disabled, we set stack boundary
           check status according to the compilation option */
#if WASM_DISABLE_STACK_HW_BOUND_CHECK != 0
        /* Native stack overflow check with hardware trap is disabled,
           we need to enable the check by LLVM JITed/AOTed code */
        comp_ctx->enable_stack_bound_check = true;
#else
        /* Native stack overflow check with hardware trap is enabled,
           no need to enable the check by LLVM JITed/AOTed code */
        comp_ctx->enable_stack_bound_check = false;
#endif
#endif

        /* Create TargetMachine */
        if (!create_target_machine_detect_host(comp_ctx))
            goto fail;

        /* Create LLJIT Instance */
        if (!orc_jit_create(comp_ctx))
            goto fail;
    }
    else {
        /* Create LLVM target machine */
        if (!option->target_arch || !strstr(option->target_arch, "-")) {
            /* Retrieve the target triple based on user input */
            triple = NULL;
            arch = option->target_arch;
            abi = option->target_abi;
            cpu = option->target_cpu;
            features = option->cpu_features;
        }
        else {
            /* Form a target triple */
            triple = option->target_arch;
            arch = NULL;
            abi = NULL;
            cpu = NULL;
            features = NULL;
        }

        opt_level = option->opt_level;
        size_level = option->size_level;

        /* verify external llc compiler */
        comp_ctx->external_llc_compiler = getenv("WAMRC_LLC_COMPILER");
        if (comp_ctx->external_llc_compiler) {
            if (access(comp_ctx->external_llc_compiler, X_OK) != 0) {
                LOG_WARNING("WAMRC_LLC_COMPILER [%s] not found, fallback to "
                            "default pipeline",
                            comp_ctx->external_llc_compiler);
                comp_ctx->external_llc_compiler = NULL;
            }
            else {
                comp_ctx->llc_compiler_flags = getenv("WAMRC_LLC_FLAGS");
                LOG_VERBOSE("Using external LLC compiler [%s]",
                            comp_ctx->external_llc_compiler);
            }
        }

        /* verify external asm compiler */
        if (!comp_ctx->external_llc_compiler) {
            comp_ctx->external_asm_compiler = getenv("WAMRC_ASM_COMPILER");
            if (comp_ctx->external_asm_compiler) {
                if (access(comp_ctx->external_asm_compiler, X_OK) != 0) {
                    LOG_WARNING(
                        "WAMRC_ASM_COMPILER [%s] not found, fallback to "
                        "default pipeline",
                        comp_ctx->external_asm_compiler);
                    comp_ctx->external_asm_compiler = NULL;
                }
                else {
                    comp_ctx->asm_compiler_flags = getenv("WAMRC_ASM_FLAGS");
                    LOG_VERBOSE("Using external ASM compiler [%s]",
                                comp_ctx->external_asm_compiler);
                }
            }
        }

        if (arch) {
            /* Add default sub-arch if not specified */
            if (!strcmp(arch, "arm"))
                arch = "armv4";
            else if (!strcmp(arch, "armeb"))
                arch = "armv4eb";
            else if (!strcmp(arch, "thumb"))
                arch = "thumbv4t";
            else if (!strcmp(arch, "thumbeb"))
                arch = "thumbv4teb";
            else if (!strcmp(arch, "aarch64"))
                arch = "aarch64v8";
            else if (!strcmp(arch, "aarch64_be"))
                arch = "aarch64_bev8";
        }

        /* Check target arch */
        if (arch && !check_target_arch(arch)) {
            if (!strcmp(arch, "help"))
                print_supported_targets();
            else
                aot_set_last_error(
                    "Invalid target. "
                    "Use --target=help to list all supported targets");
            goto fail;
        }

        /* Check target ABI */
        if (abi && !check_target_abi(abi)) {
            if (!strcmp(abi, "help"))
                print_supported_abis();
            else
                aot_set_last_error(
                    "Invalid target ABI. "
                    "Use --target-abi=help to list all supported ABI");
            goto fail;
        }

        /* Set default abi for riscv target */
        if (arch && !strncmp(arch, "riscv", 5) && !abi) {
            if (!strcmp(arch, "riscv64"))
                abi = "lp64d";
            else
                abi = "ilp32d";
        }

#if defined(__APPLE__) || defined(__MACH__)
        if (!abi) {
            /* On MacOS platform, set abi to "gnu" to avoid generating
               object file of Mach-O binary format which is unsupported */
            abi = "gnu";
            if (!arch && !cpu && !features) {
                /* Get CPU name of the host machine to avoid checking
                   SIMD capability failed */
                if (!(cpu = cpu_new = LLVMGetHostCPUName())) {
                    aot_set_last_error("llvm get host cpu name failed.");
                    goto fail;
                }
            }
        }
#endif

        if (abi) {
            /* Construct target triple: <arch>-<vendor>-<sys>-<abi> */
            const char *vendor_sys;
            char *arch1 = arch, default_arch[32] = { 0 };

            if (!arch1) {
                char *default_triple = LLVMGetDefaultTargetTriple();

                if (!default_triple) {
                    aot_set_last_error(
                        "llvm get default target triple failed.");
                    goto fail;
                }

                vendor_sys = strstr(default_triple, "-");
                bh_assert(vendor_sys);
                bh_memcpy_s(default_arch, sizeof(default_arch), default_triple,
                            (uint32)(vendor_sys - default_triple));
                /**
                 * On Mac M[1-9]+ LLVM will report arm64 as the
                 * architecture, for the purposes of wamr this is the
                 * same as aarch64v8 so we'll normalize it here.
                 */
                if (!strcmp(default_arch, "arm64")) {
                    bh_strcpy_s(default_arch, sizeof(default_arch),
                                "aarch64v8");
                }
                arch1 = default_arch;

                LLVMDisposeMessage(default_triple);
            }

            /**
             * Set <vendor>-<sys> according to abi to generate the object file
             * with the correct file format which might be different from the
             * default object file format of the host, e.g., generating AOT file
             * for Windows/MacOS under Linux host, or generating AOT file for
             * Linux/MacOS under Windows host.
             */

            if (!strcmp(abi, "msvc")) {
                if (!strcmp(arch1, "i386"))
                    vendor_sys = "-pc-win32-";
                else
                    vendor_sys = "-pc-windows-";
            }
            else {
                if (is_baremetal_target(arch, cpu, abi))
                    vendor_sys = "-unknown-none-";
                else
                    vendor_sys = "-pc-linux-";
            }

            bh_assert(strlen(arch1) + strlen(vendor_sys) + strlen(abi)
                      < sizeof(triple_buf));
            bh_memcpy_s(triple_buf, (uint32)sizeof(triple_buf), arch1,
                        (uint32)strlen(arch1));
            bh_memcpy_s(triple_buf + strlen(arch1),
                        (uint32)(sizeof(triple_buf) - strlen(arch1)),
                        vendor_sys, (uint32)strlen(vendor_sys));
            bh_memcpy_s(triple_buf + strlen(arch1) + strlen(vendor_sys),
                        (uint32)(sizeof(triple_buf) - strlen(arch1)
                                 - strlen(vendor_sys)),
                        abi, (uint32)strlen(abi));
            triple = triple_buf;
        }
        else if (arch) {
            /* Construct target triple: <arch>-<vendor>-<sys>-<abi> */
            const char *vendor_sys;
            char *default_triple = LLVMGetDefaultTargetTriple();

            if (!default_triple) {
                aot_set_last_error("llvm get default target triple failed.");
                goto fail;
            }

            if (strstr(default_triple, "windows")) {
                vendor_sys = "-pc-windows-";
                if (!abi)
                    abi = "msvc";
            }
            else if (strstr(default_triple, "win32")) {
                vendor_sys = "-pc-win32-";
                if (!abi)
                    abi = "msvc";
            }
            else if (is_baremetal_target(arch, cpu, abi)) {
                vendor_sys = "-unknown-none-";
                if (!abi)
                    abi = "gnu";
            }
            else {
                vendor_sys = "-pc-linux-";
                if (!abi)
                    abi = "gnu";
            }

            LLVMDisposeMessage(default_triple);

            bh_assert(strlen(arch) + strlen(vendor_sys) + strlen(abi)
                      < sizeof(triple_buf));
            bh_memcpy_s(triple_buf, (uint32)sizeof(triple_buf), arch,
                        (uint32)strlen(arch));
            bh_memcpy_s(triple_buf + strlen(arch),
                        (uint32)(sizeof(triple_buf) - strlen(arch)), vendor_sys,
                        (uint32)strlen(vendor_sys));
            bh_memcpy_s(triple_buf + strlen(arch) + strlen(vendor_sys),
                        (uint32)(sizeof(triple_buf) - strlen(arch)
                                 - strlen(vendor_sys)),
                        abi, (uint32)strlen(abi));
            triple = triple_buf;
        }

        if (!cpu && features) {
            aot_set_last_error("cpu isn't specified for cpu features.");
            goto fail;
        }

        if (!triple && !cpu) {
            /* Get a triple for the host machine */
            if (!(triple_norm = triple_norm_new =
                      LLVMGetDefaultTargetTriple())) {
                aot_set_last_error("llvm get default target triple failed.");
                goto fail;
            }
            /* Get CPU name of the host machine */
            if (!(cpu = cpu_new = LLVMGetHostCPUName())) {
                aot_set_last_error("llvm get host cpu name failed.");
                goto fail;
            }
        }
        else if (triple) {
            /* Normalize a target triple */
            if (!(triple_norm = triple_norm_new =
                      LLVMNormalizeTargetTriple(triple))) {
                snprintf(buf, sizeof(buf),
                         "llvm normlalize target triple (%s) failed.", triple);
                aot_set_last_error(buf);
                goto fail;
            }
            LOG_VERBOSE("triple: %s => normailized: %s", triple, triple_norm);
            if (!cpu)
                cpu = "";
        }
        else {
            /* triple is NULL, cpu isn't NULL */
            snprintf(buf, sizeof(buf), "target isn't specified for cpu %s.",
                     cpu);
            aot_set_last_error(buf);
            goto fail;
        }

        /* Add module flag and cpu feature for riscv target */
        if (arch && !strncmp(arch, "riscv", 5)) {
            LLVMMetadataRef meta_target_abi;

            if (!(meta_target_abi = LLVMMDStringInContext2(comp_ctx->context,
                                                           abi, strlen(abi)))) {
                aot_set_last_error("create metadata string failed.");
                goto fail;
            }
            LLVMAddModuleFlag(comp_ctx->module, LLVMModuleFlagBehaviorError,
                              "target-abi", strlen("target-abi"),
                              meta_target_abi);

            if (!strcmp(abi, "lp64d") || !strcmp(abi, "ilp32d")) {
                if (features && !strstr(features, "+d")) {
                    snprintf(features_buf, sizeof(features_buf), "%s%s",
                             features, ",+d");
                    features = features_buf;
                }
                else if (!features) {
                    features = "+d";
                }
            }
        }

        if (!features)
            features = "";

        /* Get target with triple, note that LLVMGetTargetFromTriple()
           return 0 when success, but not true. */
        if (LLVMGetTargetFromTriple(triple_norm, &target, &err) != 0) {
            if (err) {
                LLVMDisposeMessage(err);
                err = NULL;
            }
            snprintf(buf, sizeof(buf),
                     "llvm get target from triple (%s) failed", triple_norm);
            aot_set_last_error(buf);
            goto fail;
        }

        /* Save target arch */
        get_target_arch_from_triple(triple_norm, comp_ctx->target_arch,
                                    sizeof(comp_ctx->target_arch));

        if (option->bounds_checks == 1 || option->bounds_checks == 0) {
            /* Set by the user */
            comp_ctx->enable_bound_check =
                (option->bounds_checks == 1) ? true : false;
        }
        else {
            /* Unset by the user, use the default value */
            if (strstr(comp_ctx->target_arch, "64")
                && !option->is_sgx_platform) {
                comp_ctx->enable_bound_check = false;
            }
            else {
                comp_ctx->enable_bound_check = true;
            }
        }

        if (option->stack_bounds_checks == 1
            || option->stack_bounds_checks == 0) {
            /* Set by the user */
            comp_ctx->enable_stack_bound_check =
                (option->stack_bounds_checks == 1) ? true : false;
        }
        else {
            /* Unset by the user, use the default value, it will be the same
             * value as the bound check */
            comp_ctx->enable_stack_bound_check = comp_ctx->enable_bound_check;
        }

        if ((comp_ctx->enable_stack_bound_check
             || comp_ctx->enable_stack_estimation)
            && option->stack_usage_file == NULL) {
            if (!aot_generate_tempfile_name(
                    "wamrc-su", "su", comp_ctx->stack_usage_temp_file,
                    sizeof(comp_ctx->stack_usage_temp_file)))
                goto fail;
            comp_ctx->stack_usage_file = comp_ctx->stack_usage_temp_file;
        }
        else {
            comp_ctx->stack_usage_file = option->stack_usage_file;
        }

        os_printf("Create AoT compiler with:\n");
        os_printf("  target:        %s\n", comp_ctx->target_arch);
        os_printf("  target cpu:    %s\n", cpu);
        os_printf("  target triple: %s\n", triple_norm);
        os_printf("  cpu features:  %s\n", features);
        os_printf("  opt level:     %d\n", opt_level);
        os_printf("  size level:    %d\n", size_level);
        switch (option->output_format) {
            case AOT_LLVMIR_UNOPT_FILE:
                os_printf("  output format: unoptimized LLVM IR\n");
                break;
            case AOT_LLVMIR_OPT_FILE:
                os_printf("  output format: optimized LLVM IR\n");
                break;
            case AOT_FORMAT_FILE:
                os_printf("  output format: AoT file\n");
                break;
            case AOT_OBJECT_FILE:
                os_printf("  output format: native object file\n");
                break;
        }

        LLVMSetTarget(comp_ctx->module, triple_norm);

        if (!LLVMTargetHasTargetMachine(target)) {
            snprintf(buf, sizeof(buf),
                     "no target machine for this target (%s).", triple_norm);
            aot_set_last_error(buf);
            goto fail;
        }

        /* Report error if target isn't arc and hasn't asm backend.
           For arc target, as it cannot emit to memory buffer of elf file
           currently, we let it emit to assembly file instead, and then call
           arc-gcc to compile
           asm file to elf file, and read elf file to memory buffer. */
        if (strncmp(comp_ctx->target_arch, "arc", 3)
            && !LLVMTargetHasAsmBackend(target)) {
            snprintf(buf, sizeof(buf), "no asm backend for this target (%s).",
                     LLVMGetTargetName(target));
            aot_set_last_error(buf);
            goto fail;
        }

        /* Set code model */
        if (size_level == 0)
            code_model = LLVMCodeModelLarge;
        else if (size_level == 1)
            code_model = LLVMCodeModelMedium;
        else if (size_level == 2)
            code_model = LLVMCodeModelKernel;
        else
            code_model = LLVMCodeModelSmall;

        /* Create the target machine */
        if (!(comp_ctx->target_machine = LLVMCreateTargetMachineWithOpts(
                  target, triple_norm, cpu, features, opt_level,
                  LLVMRelocStatic, code_model, false,
                  comp_ctx->stack_usage_file))) {
            aot_set_last_error("create LLVM target machine failed.");
            goto fail;
        }

        /* If only to create target machine for querying information, early stop
         */
        if ((arch && !strcmp(arch, "help")) || (abi && !strcmp(abi, "help"))
            || (cpu && !strcmp(cpu, "help"))
            || (features && !strcmp(features, "+help"))) {
            LOG_DEBUG(
                "create LLVM target machine only for printing help info.");
            goto fail;
        }
    }

    triple = LLVMGetTargetMachineTriple(comp_ctx->target_machine);
    if (!triple) {
        aot_set_last_error("get target machine triple failed.");
        goto fail;
    }
    if (strstr(triple, "linux") && !strcmp(comp_ctx->target_arch, "x86_64")) {
        if (option->segue_flags) {
            if (option->segue_flags & (1 << 0))
                comp_ctx->enable_segue_i32_load = true;
            if (option->segue_flags & (1 << 1))
                comp_ctx->enable_segue_i64_load = true;
            if (option->segue_flags & (1 << 2))
                comp_ctx->enable_segue_f32_load = true;
            if (option->segue_flags & (1 << 3))
                comp_ctx->enable_segue_f64_load = true;
            if (option->segue_flags & (1 << 4))
                comp_ctx->enable_segue_v128_load = true;
            if (option->segue_flags & (1 << 8))
                comp_ctx->enable_segue_i32_store = true;
            if (option->segue_flags & (1 << 9))
                comp_ctx->enable_segue_i64_store = true;
            if (option->segue_flags & (1 << 10))
                comp_ctx->enable_segue_f32_store = true;
            if (option->segue_flags & (1 << 11))
                comp_ctx->enable_segue_f64_store = true;
            if (option->segue_flags & (1 << 12))
                comp_ctx->enable_segue_v128_store = true;
        }
    }
    LLVMDisposeMessage(triple);

#if WASM_ENABLE_WAMR_COMPILER != 0
    WASMModule *wasm_module = (WASMModule *)comp_data->wasm_module;
    bool is_memory64 = false;

    /* TODO: multi-memories for now assuming the memory64 flag of a memory is
     * consistent across multi-memories */
    if (wasm_module->import_memory_count > 0)
        is_memory64 = !!(wasm_module->import_memories[0].u.memory.mem_type.flags
                         & MEMORY64_FLAG);
    else if (wasm_module->memory_count > 0)
        is_memory64 = !!(wasm_module->memories[0].flags & MEMORY64_FLAG);

    if (!(option->bounds_checks == 1 || option->bounds_checks == 0)
        && is_memory64) {
        /* For memory64, the boundary check default value is true */
        comp_ctx->enable_bound_check = true;
    }

    /* Return error if SIMD is disabled by command line but SIMD instructions
     * are used */
    if (!option->enable_simd && wasm_module->is_simd_used) {
        aot_set_last_error("SIMD is disabled by --disable-simd but SIMD "
                           "instructions are used in this module");
        goto fail;
    }

    /* Return error if ref-types and GC are disabled by command line but
       ref-types instructions are used */
    if (!option->enable_ref_types && !option->enable_gc
        && wasm_module->is_ref_types_used) {
        aot_set_last_error("ref-types instruction was found, "
                           "try removing --disable-ref-types option "
                           "or adding --enable-gc option.");
        goto fail;
    }

    /* Disable features when they are not actually used */
    if (!wasm_module->is_simd_used) {
        option->enable_simd = comp_ctx->enable_simd = false;
    }
    if (!wasm_module->is_ref_types_used) {
        option->enable_ref_types = comp_ctx->enable_ref_types = false;
    }
    if (!wasm_module->is_bulk_memory_used) {
        option->enable_bulk_memory = comp_ctx->enable_bulk_memory = false;
    }
#endif

    if (option->enable_simd && strcmp(comp_ctx->target_arch, "x86_64") != 0
        && strncmp(comp_ctx->target_arch, "aarch64", 7) != 0
        && strcmp(comp_ctx->target_arch, "arc") != 0) {
        /* Disable simd if it isn't supported by target arch */
        option->enable_simd = false;
    }

    if (option->enable_simd) {
        char *tmp;
        bool check_simd_ret;

        comp_ctx->enable_simd = true;

        if (!(tmp = LLVMGetTargetMachineCPU(comp_ctx->target_machine))) {
            aot_set_last_error("get CPU from Target Machine fail");
            goto fail;
        }

        check_simd_ret =
            aot_check_simd_compatibility(comp_ctx->target_arch, tmp);
        LLVMDisposeMessage(tmp);
        if (!check_simd_ret) {
            aot_set_last_error("SIMD compatibility check failed, "
                               "try adding --cpu=<cpu> to specify a cpu "
                               "or adding --disable-simd to disable SIMD");
            goto fail;
        }
    }

    if (!(target_data_ref =
              LLVMCreateTargetDataLayout(comp_ctx->target_machine))) {
        aot_set_last_error("create LLVM target data layout failed.");
        goto fail;
    }
    LLVMSetModuleDataLayout(comp_ctx->module, target_data_ref);
    comp_ctx->pointer_size = LLVMPointerSize(target_data_ref);
    LLVMDisposeTargetData(target_data_ref);

    comp_ctx->optimize = true;
    if (option->output_format == AOT_LLVMIR_UNOPT_FILE)
        comp_ctx->optimize = false;

    /* Create metadata for llvm float experimental constrained intrinsics */
    if (!(comp_ctx->fp_rounding_mode = LLVMMDStringInContext(
              comp_ctx->context, fp_round, (uint32)strlen(fp_round)))
        || !(comp_ctx->fp_exception_behavior = LLVMMDStringInContext(
                 comp_ctx->context, fp_exce, (uint32)strlen(fp_exce)))) {
        aot_set_last_error("create float llvm metadata failed.");
        goto fail;
    }

    if (!aot_set_llvm_basic_types(&comp_ctx->basic_types, comp_ctx->context,
                                  comp_ctx->pointer_size)) {
        aot_set_last_error("create LLVM basic types failed.");
        goto fail;
    }

    if (!aot_create_llvm_consts(&comp_ctx->llvm_consts, comp_ctx)) {
        aot_set_last_error("create LLVM const values failed.");
        goto fail;
    }

    /* set exec_env data type to int8** */
    comp_ctx->exec_env_type = comp_ctx->basic_types.int8_pptr_type;

    /* set aot_inst data type to int8* */
    comp_ctx->aot_inst_type = INT8_PTR_TYPE;

    /* Create function context for each function */
    comp_ctx->func_ctx_count = comp_data->func_count;
    if (comp_data->func_count > 0
        && !(comp_ctx->func_ctxes =
                 aot_create_func_contexts(comp_data, comp_ctx)))
        goto fail;

    if (cpu) {
        uint32 len = (uint32)strlen(cpu) + 1;
        if (!(comp_ctx->target_cpu = wasm_runtime_malloc(len))) {
            aot_set_last_error("allocate memory failed");
            goto fail;
        }
        bh_memcpy_s(comp_ctx->target_cpu, len, cpu, len);
    }

    if (comp_ctx->disable_llvm_intrinsics)
        aot_intrinsic_fill_capability_flags(comp_ctx);

    ret = comp_ctx;

fail:
    if (triple_norm_new)
        LLVMDisposeMessage(triple_norm_new);

    if (cpu_new)
        LLVMDisposeMessage(cpu_new);

    if (!ret)
        aot_destroy_comp_context(comp_ctx);

    (void)i;
    return ret;
}

void
aot_destroy_comp_context(AOTCompContext *comp_ctx)
{
    if (!comp_ctx)
        return;

    if (comp_ctx->stack_usage_file == comp_ctx->stack_usage_temp_file) {
        (void)unlink(comp_ctx->stack_usage_temp_file);
    }

    if (comp_ctx->target_machine)
        LLVMDisposeTargetMachine(comp_ctx->target_machine);

    if (comp_ctx->builder)
        LLVMDisposeBuilder(comp_ctx->builder);

#if WASM_ENABLE_DEBUG_AOT != 0
    if (comp_ctx->debug_builder)
        LLVMDisposeDIBuilder(comp_ctx->debug_builder);
#endif

    if (comp_ctx->orc_thread_safe_context)
        LLVMOrcDisposeThreadSafeContext(comp_ctx->orc_thread_safe_context);

    /* Note: don't dispose comp_ctx->context and comp_ctx->module as
       they are disposed when disposing the thread safe context */

    /* Has to be the last one */
    if (comp_ctx->orc_jit)
        LLVMOrcDisposeLLLazyJIT(comp_ctx->orc_jit);

    if (comp_ctx->func_ctxes)
        aot_destroy_func_contexts(comp_ctx, comp_ctx->func_ctxes,
                                  comp_ctx->func_ctx_count);

    if (bh_list_length(&comp_ctx->native_symbols) > 0) {
        AOTNativeSymbol *sym = bh_list_first_elem(&comp_ctx->native_symbols);
        while (sym) {
            AOTNativeSymbol *t = bh_list_elem_next(sym);
            bh_list_remove(&comp_ctx->native_symbols, sym);
            wasm_runtime_free(sym);
            sym = t;
        }
    }

    if (comp_ctx->target_cpu) {
        wasm_runtime_free(comp_ctx->target_cpu);
    }

    if (comp_ctx->aot_frame) {
        wasm_runtime_free(comp_ctx->aot_frame);
    }

    wasm_runtime_free(comp_ctx);
}

static bool
insert_native_symbol(AOTCompContext *comp_ctx, const char *symbol, int32 idx)
{
    AOTNativeSymbol *sym = wasm_runtime_malloc(sizeof(AOTNativeSymbol));
    int ret;

    if (!sym) {
        aot_set_last_error("alloc native symbol failed.");
        return false;
    }

    memset(sym, 0, sizeof(AOTNativeSymbol));
    bh_assert(strlen(symbol) <= sizeof(sym->symbol));
    ret = snprintf(sym->symbol, sizeof(sym->symbol), "%s", symbol);
    if (ret < 0 || ret + 1 > (int)sizeof(sym->symbol)) {
        wasm_runtime_free(sym);
        aot_set_last_error_v("symbol name too long: %s", symbol);
        return false;
    }
    sym->index = idx;

    if (BH_LIST_ERROR == bh_list_insert(&comp_ctx->native_symbols, sym)) {
        wasm_runtime_free(sym);
        aot_set_last_error("insert native symbol to list failed.");
        return false;
    }

    return true;
}

int32
aot_get_native_symbol_index(AOTCompContext *comp_ctx, const char *symbol)
{
    int32 idx = -1;
    AOTNativeSymbol *sym = NULL;

    sym = bh_list_first_elem(&comp_ctx->native_symbols);

    /* Lookup an existing symbol record */

    while (sym) {
        if (strcmp(sym->symbol, symbol) == 0) {
            idx = sym->index;
            break;
        }
        sym = bh_list_elem_next(sym);
    }

    /* Given symbol is not exist in list, then we alloc a new index for it */

    if (idx < 0) {
        if (comp_ctx->pointer_size == sizeof(uint32)
            && (!strncmp(symbol, "f64#", 4) || !strncmp(symbol, "i64#", 4))) {
            idx = bh_list_length(&comp_ctx->native_symbols);
            /* Add 4 bytes padding on 32-bit target to make sure that
               the f64 const is stored on 8-byte aligned address */
            if (idx & 1) {
                if (!insert_native_symbol(comp_ctx, "__ignore", idx)) {
                    return -1;
                }
            }
        }

        idx = bh_list_length(&comp_ctx->native_symbols);
        if (!insert_native_symbol(comp_ctx, symbol, idx)) {
            return -1;
        }

        if (comp_ctx->pointer_size == sizeof(uint32)
            && (!strncmp(symbol, "f64#", 4) || !strncmp(symbol, "i64#", 4))) {
            /* f64 const occupies 2 pointer slots on 32-bit target */
            if (!insert_native_symbol(comp_ctx, "__ignore", idx + 1)) {
                return -1;
            }
        }
    }

    return idx;
}

void
aot_value_stack_push(const AOTCompContext *comp_ctx, AOTValueStack *stack,
                     AOTValue *value)
{
    if (!stack->value_list_head)
        stack->value_list_head = stack->value_list_end = value;
    else {
        stack->value_list_end->next = value;
        value->prev = stack->value_list_end;
        stack->value_list_end = value;
    }

    if (comp_ctx->aot_frame) {
        switch (value->type) {
            case VALUE_TYPE_I32:
            case VALUE_TYPE_I1:
                push_i32(comp_ctx->aot_frame, value);
                break;
            case VALUE_TYPE_I64:
                push_i64(comp_ctx->aot_frame, value);
                break;
            case VALUE_TYPE_F32:
                push_f32(comp_ctx->aot_frame, value);
                break;
            case VALUE_TYPE_F64:
                push_f64(comp_ctx->aot_frame, value);
                break;
            case VALUE_TYPE_V128:
                push_v128(comp_ctx->aot_frame, value);
                break;
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
                push_ref(comp_ctx->aot_frame, value);
                break;
#if WASM_ENABLE_GC != 0
            case VALUE_TYPE_GC_REF:
                bh_assert(comp_ctx->enable_gc);
                push_gc_ref(comp_ctx->aot_frame, value);
                break;
#endif
            default:
                bh_assert(0);
                break;
        }
    }
}

AOTValue *
aot_value_stack_pop(const AOTCompContext *comp_ctx, AOTValueStack *stack)
{
    AOTValue *value = stack->value_list_end;

    bh_assert(stack->value_list_end);

    if (stack->value_list_head == stack->value_list_end)
        stack->value_list_head = stack->value_list_end = NULL;
    else {
        stack->value_list_end = stack->value_list_end->prev;
        stack->value_list_end->next = NULL;
        value->prev = NULL;
    }

    if (comp_ctx->aot_frame) {
        bh_assert(value);
        bh_assert(value->value == (comp_ctx->aot_frame->sp - 1)->value);
        bh_assert(value->type == (comp_ctx->aot_frame->sp - 1)->type);

        switch (value->type) {
            case VALUE_TYPE_I32:
            case VALUE_TYPE_I1:
                pop_i32(comp_ctx->aot_frame);
                break;
            case VALUE_TYPE_I64:
                pop_i64(comp_ctx->aot_frame);
                break;
            case VALUE_TYPE_F32:
                pop_f32(comp_ctx->aot_frame);
                break;
            case VALUE_TYPE_F64:
                pop_f64(comp_ctx->aot_frame);
                break;
            case VALUE_TYPE_V128:
                pop_v128(comp_ctx->aot_frame);
                break;
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
                pop_ref(comp_ctx->aot_frame);
                break;
#if WASM_ENABLE_GC != 0
            case VALUE_TYPE_GC_REF:
                bh_assert(comp_ctx->enable_gc);
                pop_gc_ref(comp_ctx->aot_frame);
                break;
#endif
            default:
                bh_assert(0);
                break;
        }
    }

    return value;
}

void
aot_value_stack_destroy(AOTCompContext *comp_ctx, AOTValueStack *stack)
{
    AOTValue *value = stack->value_list_head, *p;

    while (value) {
        p = value->next;
        wasm_runtime_free(value);
        value = p;
    }

    stack->value_list_head = NULL;
    stack->value_list_end = NULL;
}

void
aot_block_stack_push(AOTBlockStack *stack, AOTBlock *block)
{
    if (!stack->block_list_head)
        stack->block_list_head = stack->block_list_end = block;
    else {
        stack->block_list_end->next = block;
        block->prev = stack->block_list_end;
        stack->block_list_end = block;
    }
}

AOTBlock *
aot_block_stack_pop(AOTBlockStack *stack)
{
    AOTBlock *block = stack->block_list_end;

    bh_assert(stack->block_list_end);

    if (stack->block_list_head == stack->block_list_end)
        stack->block_list_head = stack->block_list_end = NULL;
    else {
        stack->block_list_end = stack->block_list_end->prev;
        stack->block_list_end->next = NULL;
        block->prev = NULL;
    }

    return block;
}

void
aot_block_stack_destroy(AOTCompContext *comp_ctx, AOTBlockStack *stack)
{
    AOTBlock *block = stack->block_list_head, *p;

    while (block) {
        p = block->next;
        aot_value_stack_destroy(comp_ctx, &block->value_stack);
        aot_block_destroy(comp_ctx, block);
        block = p;
    }

    stack->block_list_head = NULL;
    stack->block_list_end = NULL;
}

void
aot_block_destroy(AOTCompContext *comp_ctx, AOTBlock *block)
{
    aot_value_stack_destroy(comp_ctx, &block->value_stack);
    if (block->param_types)
        wasm_runtime_free(block->param_types);
    if (block->param_phis)
        wasm_runtime_free(block->param_phis);
    if (block->else_param_phis)
        wasm_runtime_free(block->else_param_phis);
    if (block->result_types)
        wasm_runtime_free(block->result_types);
    if (block->result_phis)
        wasm_runtime_free(block->result_phis);
    wasm_runtime_free(block);
}

bool
aot_checked_addr_list_add(AOTFuncContext *func_ctx, uint32 local_idx,
                          uint64 offset, uint32 bytes)
{
    AOTCheckedAddr *node = func_ctx->checked_addr_list;

    if (!(node = wasm_runtime_malloc(sizeof(AOTCheckedAddr)))) {
        aot_set_last_error("allocate memory failed.");
        return false;
    }

    node->local_idx = local_idx;
    node->offset = offset;
    node->bytes = bytes;

    node->next = func_ctx->checked_addr_list;
    func_ctx->checked_addr_list = node;
    return true;
}

void
aot_checked_addr_list_del(AOTFuncContext *func_ctx, uint32 local_idx)
{
    AOTCheckedAddr *node = func_ctx->checked_addr_list;
    AOTCheckedAddr *node_prev = NULL, *node_next;

    while (node) {
        node_next = node->next;

        if (node->local_idx == local_idx) {
            if (!node_prev)
                func_ctx->checked_addr_list = node_next;
            else
                node_prev->next = node_next;
            wasm_runtime_free(node);
        }
        else {
            node_prev = node;
        }

        node = node_next;
    }
}

bool
aot_checked_addr_list_find(AOTFuncContext *func_ctx, uint32 local_idx,
                           uint64 offset, uint32 bytes)
{
    AOTCheckedAddr *node = func_ctx->checked_addr_list;

    while (node) {
        if (node->local_idx == local_idx && node->offset == offset
            && node->bytes >= bytes) {
            return true;
        }
        node = node->next;
    }

    return false;
}

void
aot_checked_addr_list_destroy(AOTFuncContext *func_ctx)
{
    AOTCheckedAddr *node = func_ctx->checked_addr_list, *node_next;

    while (node) {
        node_next = node->next;
        wasm_runtime_free(node);
        node = node_next;
    }

    func_ctx->checked_addr_list = NULL;
}

bool
aot_build_zero_function_ret(const AOTCompContext *comp_ctx,
                            AOTFuncContext *func_ctx, AOTFuncType *func_type)
{
    LLVMValueRef ret = NULL;

    if (func_type->result_count) {
        switch (func_type->types[func_type->param_count]) {
            case VALUE_TYPE_I32:
                ret = LLVMBuildRet(comp_ctx->builder, I32_ZERO);
                break;
            case VALUE_TYPE_I64:
                ret = LLVMBuildRet(comp_ctx->builder, I64_ZERO);
                break;
            case VALUE_TYPE_F32:
                ret = LLVMBuildRet(comp_ctx->builder, F32_ZERO);
                break;
            case VALUE_TYPE_F64:
                ret = LLVMBuildRet(comp_ctx->builder, F64_ZERO);
                break;
            case VALUE_TYPE_V128:
                ret =
                    LLVMBuildRet(comp_ctx->builder, LLVM_CONST(i64x2_vec_zero));
                break;
            case VALUE_TYPE_FUNCREF:
            case VALUE_TYPE_EXTERNREF:
                if (comp_ctx->enable_ref_types)
                    ret = LLVMBuildRet(comp_ctx->builder, REF_NULL);
#if WASM_ENABLE_GC != 0
                else if (comp_ctx->enable_gc)
                    ret = LLVMBuildRet(comp_ctx->builder, GC_REF_NULL);
#endif
                else
                    bh_assert(0);
                break;
#if WASM_ENABLE_GC != 0
            case REF_TYPE_NULLFUNCREF:
            case REF_TYPE_NULLEXTERNREF:
            case REF_TYPE_NULLREF:
            /* case REF_TYPE_FUNCREF: */
            /* case REF_TYPE_EXTERNREF: */
            case REF_TYPE_ANYREF:
            case REF_TYPE_EQREF:
            case REF_TYPE_HT_NULLABLE:
            case REF_TYPE_HT_NON_NULLABLE:
            case REF_TYPE_I31REF:
            case REF_TYPE_STRUCTREF:
            case REF_TYPE_ARRAYREF:
#if WASM_ENABLE_STRINGREF != 0
            case REF_TYPE_STRINGREF:
            case REF_TYPE_STRINGVIEWWTF8:
            case REF_TYPE_STRINGVIEWWTF16:
            case REF_TYPE_STRINGVIEWITER:
#endif
                bh_assert(comp_ctx->enable_gc);
                ret = LLVMBuildRet(comp_ctx->builder, GC_REF_NULL);
                break;
#endif
            default:
                bh_assert(0);
        }
    }
    else {
        ret = LLVMBuildRetVoid(comp_ctx->builder);
    }

    if (!ret) {
        aot_set_last_error("llvm build ret failed.");
        return false;
    }
#if WASM_ENABLE_DEBUG_AOT != 0
    /* debug_func is NULL for precheck function */
    if (func_ctx->debug_func != NULL) {
        LLVMMetadataRef return_location =
            dwarf_gen_func_ret_location(comp_ctx, func_ctx);
        LLVMInstructionSetDebugLoc(ret, return_location);
    }
#endif
    return true;
}

static LLVMValueRef
__call_llvm_intrinsic(const AOTCompContext *comp_ctx,
                      const AOTFuncContext *func_ctx, const char *name,
                      LLVMTypeRef ret_type, LLVMTypeRef *param_types,
                      int param_count, LLVMValueRef *param_values)
{
    LLVMValueRef func, ret;
    LLVMTypeRef func_type;
    const char *symname;
    int32 func_idx;

    if (comp_ctx->disable_llvm_intrinsics
        && aot_intrinsic_check_capability(comp_ctx, name)) {
        if (func_ctx == NULL) {
            aot_set_last_error_v("invalid func_ctx for intrinsic: %s", name);
            return NULL;
        }

        if (!(func_type = LLVMFunctionType(ret_type, param_types,
                                           (uint32)param_count, false))) {
            aot_set_last_error("create LLVM intrinsic function type failed.");
            return NULL;
        }
        if (!(func_type = LLVMPointerType(func_type, 0))) {
            aot_set_last_error(
                "create LLVM intrinsic function pointer type failed.");
            return NULL;
        }

        if (!(symname = aot_intrinsic_get_symbol(name))) {
            aot_set_last_error_v("runtime intrinsic not implemented: %s\n",
                                 name);
            return NULL;
        }

        func_idx =
            aot_get_native_symbol_index((AOTCompContext *)comp_ctx, symname);
        if (func_idx < 0) {
            aot_set_last_error_v("get runtime intrinsc index failed: %s\n",
                                 name);
            return NULL;
        }

        if (!(func = aot_get_func_from_table(comp_ctx, func_ctx->native_symbol,
                                             func_type, func_idx))) {
            aot_set_last_error_v("get runtime intrinsc failed: %s\n", name);
            return NULL;
        }
    }
    else {
        /* Declare llvm intrinsic function if necessary */
        if (!(func = LLVMGetNamedFunction(func_ctx->module, name))) {
            if (!(func_type = LLVMFunctionType(ret_type, param_types,
                                               (uint32)param_count, false))) {
                aot_set_last_error(
                    "create LLVM intrinsic function type failed.");
                return NULL;
            }

            if (!(func = LLVMAddFunction(func_ctx->module, name, func_type))) {
                aot_set_last_error("add LLVM intrinsic function failed.");
                return NULL;
            }
        }
    }

#if LLVM_VERSION_MAJOR >= 14
    func_type =
        LLVMFunctionType(ret_type, param_types, (uint32)param_count, false);
#endif

    /* Call the LLVM intrinsic function */
    if (!(ret = LLVMBuildCall2(comp_ctx->builder, func_type, func, param_values,
                               (uint32)param_count, "call"))) {
        aot_set_last_error("llvm build intrinsic call failed.");
        return NULL;
    }

    return ret;
}

LLVMValueRef
aot_call_llvm_intrinsic(const AOTCompContext *comp_ctx,
                        const AOTFuncContext *func_ctx, const char *intrinsic,
                        LLVMTypeRef ret_type, LLVMTypeRef *param_types,
                        int param_count, ...)
{
    LLVMValueRef *param_values, ret;
    va_list argptr;
    uint64 total_size;
    int i = 0;

    /* Create param values */
    total_size = sizeof(LLVMValueRef) * (uint64)param_count;
    if (total_size >= UINT32_MAX
        || !(param_values = wasm_runtime_malloc((uint32)total_size))) {
        aot_set_last_error("allocate memory for param values failed.");
        return false;
    }

    /* Load each param value */
    va_start(argptr, param_count);
    while (i < param_count)
        param_values[i++] = va_arg(argptr, LLVMValueRef);
    va_end(argptr);

    ret = __call_llvm_intrinsic(comp_ctx, func_ctx, intrinsic, ret_type,
                                param_types, param_count, param_values);

    wasm_runtime_free(param_values);

    return ret;
}

LLVMValueRef
aot_call_llvm_intrinsic_v(const AOTCompContext *comp_ctx,
                          const AOTFuncContext *func_ctx, const char *intrinsic,
                          LLVMTypeRef ret_type, LLVMTypeRef *param_types,
                          int param_count, va_list param_value_list)
{
    LLVMValueRef *param_values, ret;
    uint64 total_size;
    int i = 0;

    /* Create param values */
    total_size = sizeof(LLVMValueRef) * (uint64)param_count;
    if (total_size >= UINT32_MAX
        || !(param_values = wasm_runtime_malloc((uint32)total_size))) {
        aot_set_last_error("allocate memory for param values failed.");
        return false;
    }

    /* Load each param value */
    while (i < param_count)
        param_values[i++] = va_arg(param_value_list, LLVMValueRef);

    ret = __call_llvm_intrinsic(comp_ctx, func_ctx, intrinsic, ret_type,
                                param_types, param_count, param_values);

    wasm_runtime_free(param_values);

    return ret;
}

LLVMValueRef
aot_get_func_from_table(const AOTCompContext *comp_ctx, LLVMValueRef base,
                        LLVMTypeRef func_type, int32 index)
{
    LLVMValueRef func;
    LLVMValueRef func_addr;

    if (!(func_addr = I32_CONST(index))) {
        aot_set_last_error("construct function index failed.");
        goto fail;
    }

    if (!(func_addr =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, OPQ_PTR_TYPE, base,
                                    &func_addr, 1, "func_addr"))) {
        aot_set_last_error("get function addr by index failed.");
        goto fail;
    }

    func =
        LLVMBuildLoad2(comp_ctx->builder, OPQ_PTR_TYPE, func_addr, "func_tmp");

    if (func == NULL) {
        aot_set_last_error("get function pointer failed.");
        goto fail;
    }

    if (!(func =
              LLVMBuildBitCast(comp_ctx->builder, func, func_type, "func"))) {
        aot_set_last_error("cast function failed.");
        goto fail;
    }

    return func;
fail:
    return NULL;
}

LLVMValueRef
aot_load_const_from_table(AOTCompContext *comp_ctx, LLVMValueRef base,
                          const WASMValue *value, uint8 value_type)
{
    LLVMValueRef const_index, const_addr, const_value;
    LLVMTypeRef const_ptr_type, const_type;
    char buf[128] = { 0 };
    int32 index;

    switch (value_type) {
        case VALUE_TYPE_I32:
            /* Store the raw int bits of i32 const as a hex string */
            snprintf(buf, sizeof(buf), "i32#%08" PRIX32, value->i32);
            const_ptr_type = INT32_PTR_TYPE;
            const_type = I32_TYPE;
            break;
        case VALUE_TYPE_I64:
            /* Store the raw int bits of i64 const as a hex string */
            snprintf(buf, sizeof(buf), "i64#%016" PRIX64, value->i64);
            const_ptr_type = INT64_PTR_TYPE;
            const_type = I64_TYPE;
            break;
        case VALUE_TYPE_F32:
            /* Store the raw int bits of f32 const as a hex string */
            snprintf(buf, sizeof(buf), "f32#%08" PRIX32, value->i32);
            const_ptr_type = F32_PTR_TYPE;
            const_type = F32_TYPE;
            break;
        case VALUE_TYPE_F64:
            /* Store the raw int bits of f64 const as a hex string */
            snprintf(buf, sizeof(buf), "f64#%016" PRIX64, value->i64);
            const_ptr_type = F64_PTR_TYPE;
            const_type = F64_TYPE;
            break;
        default:
            bh_assert(0);
            return NULL;
    }

    /* Load f32/f64 const from exec_env->native_symbol[index] */

    index = aot_get_native_symbol_index(comp_ctx, buf);
    if (index < 0) {
        return NULL;
    }

    if (!(const_index = I32_CONST(index))) {
        aot_set_last_error("construct const index failed.");
        return NULL;
    }

    if (!(const_addr =
              LLVMBuildInBoundsGEP2(comp_ctx->builder, OPQ_PTR_TYPE, base,
                                    &const_index, 1, "const_addr_tmp"))) {
        aot_set_last_error("get const addr by index failed.");
        return NULL;
    }

    if (!(const_addr = LLVMBuildBitCast(comp_ctx->builder, const_addr,
                                        const_ptr_type, "const_addr"))) {
        aot_set_last_error("cast const failed.");
        return NULL;
    }

    if (!(const_value = LLVMBuildLoad2(comp_ctx->builder, const_type,
                                       const_addr, "const_value"))) {
        aot_set_last_error("load const failed.");
        return NULL;
    }

    (void)const_type;
    return const_value;
}

bool
aot_set_cond_br_weights(AOTCompContext *comp_ctx, LLVMValueRef cond_br,
                        int32 weights_true, int32 weights_false)
{
    LLVMMetadataRef md_nodes[3], meta_data;
    LLVMValueRef meta_data_as_value;

    md_nodes[0] = LLVMMDStringInContext2(comp_ctx->context, "branch_weights",
                                         strlen("branch_weights"));
    md_nodes[1] = LLVMValueAsMetadata(I32_CONST(weights_true));
    md_nodes[2] = LLVMValueAsMetadata(I32_CONST(weights_false));

    meta_data = LLVMMDNodeInContext2(comp_ctx->context, md_nodes, 3);
    meta_data_as_value = LLVMMetadataAsValue(comp_ctx->context, meta_data);

    LLVMSetMetadata(cond_br, 2, meta_data_as_value);

    return true;
}
