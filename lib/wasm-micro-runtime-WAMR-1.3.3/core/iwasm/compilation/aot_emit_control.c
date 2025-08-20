/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "aot_emit_control.h"
#include "aot_compiler.h"
#include "aot_emit_exception.h"
#include "../aot/aot_runtime.h"
#include "../interpreter/wasm_loader.h"

#if WASM_ENABLE_DEBUG_AOT != 0
#include "debug/dwarf_extractor.h"
#endif

static char *block_name_prefix[] = { "block", "loop", "if" };
static char *block_name_suffix[] = { "begin", "else", "end" };

/* clang-format off */
enum {
    LABEL_BEGIN = 0,
    LABEL_ELSE,
    LABEL_END
};
/* clang-format on */

static void
format_block_name(char *name, uint32 name_size, uint32 block_index,
                  uint32 label_type, uint32 label_id)
{
    if (label_type != LABEL_TYPE_FUNCTION)
        snprintf(name, name_size, "%s%d%s%s", block_name_prefix[label_type],
                 block_index, "_", block_name_suffix[label_id]);
    else
        snprintf(name, name_size, "%s", "func_end");
}

#define CREATE_BLOCK(new_llvm_block, name)                      \
    do {                                                        \
        if (!(new_llvm_block = LLVMAppendBasicBlockInContext(   \
                  comp_ctx->context, func_ctx->func, name))) {  \
            aot_set_last_error("add LLVM basic block failed."); \
            goto fail;                                          \
        }                                                       \
    } while (0)

#define CURR_BLOCK() LLVMGetInsertBlock(comp_ctx->builder)

#define MOVE_BLOCK_AFTER(llvm_block, llvm_block_after) \
    LLVMMoveBasicBlockAfter(llvm_block, llvm_block_after)

#define MOVE_BLOCK_AFTER_CURR(llvm_block) \
    LLVMMoveBasicBlockAfter(llvm_block, CURR_BLOCK())

#define MOVE_BLOCK_BEFORE(llvm_block, llvm_block_before) \
    LLVMMoveBasicBlockBefore(llvm_block, llvm_block_before)

#define BUILD_BR(llvm_block)                               \
    do {                                                   \
        if (!LLVMBuildBr(comp_ctx->builder, llvm_block)) { \
            aot_set_last_error("llvm build br failed.");   \
            goto fail;                                     \
        }                                                  \
    } while (0)

#define BUILD_COND_BR(value_if, block_then, block_else)               \
    do {                                                              \
        if (!LLVMBuildCondBr(comp_ctx->builder, value_if, block_then, \
                             block_else)) {                           \
            aot_set_last_error("llvm build cond br failed.");         \
            goto fail;                                                \
        }                                                             \
    } while (0)

#define SET_BUILDER_POS(llvm_block) \
    LLVMPositionBuilderAtEnd(comp_ctx->builder, llvm_block)

#define CREATE_RESULT_VALUE_PHIS(block)                                     \
    do {                                                                    \
        if (block->result_count && !block->result_phis) {                   \
            uint32 _i;                                                      \
            uint64 _size;                                                   \
            LLVMBasicBlockRef _block_curr = CURR_BLOCK();                   \
            /* Allocate memory */                                           \
            _size = sizeof(LLVMValueRef) * (uint64)block->result_count;     \
            if (_size >= UINT32_MAX                                         \
                || !(block->result_phis =                                   \
                         wasm_runtime_malloc((uint32)_size))) {             \
                aot_set_last_error("allocate memory failed.");              \
                goto fail;                                                  \
            }                                                               \
            SET_BUILDER_POS(block->llvm_end_block);                         \
            for (_i = 0; _i < block->result_count; _i++) {                  \
                if (!(block->result_phis[_i] = LLVMBuildPhi(                \
                          comp_ctx->builder,                                \
                          TO_LLVM_TYPE(block->result_types[_i]), "phi"))) { \
                    aot_set_last_error("llvm build phi failed.");           \
                    goto fail;                                              \
                }                                                           \
            }                                                               \
            SET_BUILDER_POS(_block_curr);                                   \
        }                                                                   \
    } while (0)

#define ADD_TO_RESULT_PHIS(block, value, idx)                                  \
    do {                                                                       \
        LLVMBasicBlockRef _block_curr = CURR_BLOCK();                          \
        LLVMTypeRef phi_ty = LLVMTypeOf(block->result_phis[idx]);              \
        LLVMTypeRef value_ty = LLVMTypeOf(value);                              \
        bh_assert(LLVMGetTypeKind(phi_ty) == LLVMGetTypeKind(value_ty));       \
        bh_assert(LLVMGetTypeContext(phi_ty) == LLVMGetTypeContext(value_ty)); \
        LLVMAddIncoming(block->result_phis[idx], &value, &_block_curr, 1);     \
        (void)phi_ty;                                                          \
        (void)value_ty;                                                        \
    } while (0)

#define BUILD_ICMP(op, left, right, res, name)                                \
    do {                                                                      \
        if (!(res =                                                           \
                  LLVMBuildICmp(comp_ctx->builder, op, left, right, name))) { \
            aot_set_last_error("llvm build icmp failed.");                    \
            goto fail;                                                        \
        }                                                                     \
    } while (0)

#define ADD_TO_PARAM_PHIS(block, value, idx)                              \
    do {                                                                  \
        LLVMBasicBlockRef _block_curr = CURR_BLOCK();                     \
        LLVMAddIncoming(block->param_phis[idx], &value, &_block_curr, 1); \
    } while (0)

static LLVMBasicBlockRef
find_next_llvm_end_block(AOTBlock *block)
{
    block = block->prev;
    while (block && !block->llvm_end_block)
        block = block->prev;
    return block ? block->llvm_end_block : NULL;
}

static AOTBlock *
get_target_block(AOTFuncContext *func_ctx, uint32 br_depth)
{
    uint32 i = br_depth;
    AOTBlock *block = func_ctx->block_stack.block_list_end;

    while (i-- > 0 && block) {
        block = block->prev;
    }

    if (!block) {
        aot_set_last_error("WASM block stack underflow.");
        return NULL;
    }
    return block;
}

static bool
handle_next_reachable_block(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                            uint8 **p_frame_ip)
{
    AOTBlock *block = func_ctx->block_stack.block_list_end;
    AOTBlock *block_prev;
    uint8 *frame_ip = NULL;
    uint32 i;
    AOTFuncType *func_type;
    LLVMValueRef ret;
#if WASM_ENABLE_DEBUG_AOT != 0
    LLVMMetadataRef return_location;
#endif

    aot_checked_addr_list_destroy(func_ctx);
    bh_assert(block);

#if WASM_ENABLE_DEBUG_AOT != 0
    return_location = dwarf_gen_location(
        comp_ctx, func_ctx,
        (*p_frame_ip - 1) - comp_ctx->comp_data->wasm_module->buf_code);
#endif
    if (block->label_type == LABEL_TYPE_IF && block->llvm_else_block
        && *p_frame_ip <= block->wasm_code_else) {
        /* Clear value stack and start to translate else branch */
        aot_value_stack_destroy(&block->value_stack);
        /* Recover parameters of else branch */
        for (i = 0; i < block->param_count; i++)
            PUSH(block->else_param_phis[i], block->param_types[i]);
        SET_BUILDER_POS(block->llvm_else_block);
        *p_frame_ip = block->wasm_code_else + 1;
        return true;
    }

    while (block && !block->is_reachable) {
        block_prev = block->prev;
        block = aot_block_stack_pop(&func_ctx->block_stack);

        if (block->label_type == LABEL_TYPE_IF) {
            if (block->llvm_else_block && !block->skip_wasm_code_else
                && *p_frame_ip <= block->wasm_code_else) {
                /* Clear value stack and start to translate else branch */
                aot_value_stack_destroy(&block->value_stack);
                SET_BUILDER_POS(block->llvm_else_block);
                *p_frame_ip = block->wasm_code_else + 1;
                /* Push back the block */
                aot_block_stack_push(&func_ctx->block_stack, block);
                /* Recover parameters of else branch */
                for (i = 0; i < block->param_count; i++)
                    PUSH(block->else_param_phis[i], block->param_types[i]);
                return true;
            }
            else if (block->llvm_end_block) {
                /* Remove unreachable basic block */
                LLVMDeleteBasicBlock(block->llvm_end_block);
                block->llvm_end_block = NULL;
            }
        }

        frame_ip = block->wasm_code_end;
        aot_block_destroy(block);
        block = block_prev;
    }

    if (!block) {
        *p_frame_ip = frame_ip + 1;
        return true;
    }

    if (block->label_type == LABEL_TYPE_IF && block->llvm_else_block
        && !block->skip_wasm_code_else
        && *p_frame_ip <= block->wasm_code_else) {
        /* Clear value stack and start to translate else branch */
        aot_value_stack_destroy(&block->value_stack);
        /* Recover parameters of else branch */
        for (i = 0; i < block->param_count; i++)
            PUSH(block->else_param_phis[i], block->param_types[i]);
        SET_BUILDER_POS(block->llvm_else_block);
        *p_frame_ip = block->wasm_code_else + 1;
        return true;
    }

    *p_frame_ip = block->wasm_code_end + 1;
    SET_BUILDER_POS(block->llvm_end_block);

    /* Pop block, push its return value, and destroy the block */
    block = aot_block_stack_pop(&func_ctx->block_stack);
    func_type = func_ctx->aot_func->func_type;
    for (i = 0; i < block->result_count; i++) {
        bh_assert(block->result_phis[i]);
        if (block->label_type != LABEL_TYPE_FUNCTION) {
            PUSH(block->result_phis[i], block->result_types[i]);
        }
        else {
            /* Store extra return values to function parameters */
            if (i != 0) {
                LLVMValueRef res;
                uint32 param_index = func_type->param_count + i;
                if (!(res = LLVMBuildStore(
                          comp_ctx->builder, block->result_phis[i],
                          LLVMGetParam(func_ctx->func, param_index)))) {
                    aot_set_last_error("llvm build store failed.");
                    goto fail;
                }
                LLVMSetAlignment(res, 1);
            }
        }
    }
    if (block->label_type == LABEL_TYPE_FUNCTION) {
        if (block->result_count) {
            /* Return the first return value */
            if (!(ret =
                      LLVMBuildRet(comp_ctx->builder, block->result_phis[0]))) {
                aot_set_last_error("llvm build return failed.");
                goto fail;
            }
#if WASM_ENABLE_DEBUG_AOT != 0
            if (return_location != NULL) {
                LLVMInstructionSetDebugLoc(ret, return_location);
            }
#endif
        }
        else {
            if (!(ret = LLVMBuildRetVoid(comp_ctx->builder))) {
                aot_set_last_error("llvm build return void failed.");
                goto fail;
            }
#if WASM_ENABLE_DEBUG_AOT != 0
            if (return_location != NULL) {
                LLVMInstructionSetDebugLoc(ret, return_location);
            }
#endif
        }
    }
    aot_block_destroy(block);
    return true;
fail:
    return false;
}

static bool
push_aot_block_to_stack_and_pass_params(AOTCompContext *comp_ctx,
                                        AOTFuncContext *func_ctx,
                                        AOTBlock *block)
{
    uint32 i, param_index;
    LLVMValueRef value, br_inst;
    uint64 size;
    char name[32];
    LLVMBasicBlockRef block_curr = CURR_BLOCK();

    if (block->param_count) {
        size = sizeof(LLVMValueRef) * (uint64)block->param_count;
        if (size >= UINT32_MAX
            || !(block->param_phis = wasm_runtime_malloc((uint32)size))) {
            aot_set_last_error("allocate memory failed.");
            return false;
        }

        if (block->label_type == LABEL_TYPE_IF && !block->skip_wasm_code_else
            && !(block->else_param_phis = wasm_runtime_malloc((uint32)size))) {
            wasm_runtime_free(block->param_phis);
            block->param_phis = NULL;
            aot_set_last_error("allocate memory failed.");
            return false;
        }

        /* Create param phis */
        for (i = 0; i < block->param_count; i++) {
            SET_BUILDER_POS(block->llvm_entry_block);
            snprintf(name, sizeof(name), "%s%d_phi%d",
                     block_name_prefix[block->label_type], block->block_index,
                     i);
            if (!(block->param_phis[i] = LLVMBuildPhi(
                      comp_ctx->builder, TO_LLVM_TYPE(block->param_types[i]),
                      name))) {
                aot_set_last_error("llvm build phi failed.");
                goto fail;
            }

            if (block->label_type == LABEL_TYPE_IF
                && !block->skip_wasm_code_else && block->llvm_else_block) {
                /* Build else param phis */
                SET_BUILDER_POS(block->llvm_else_block);
                snprintf(name, sizeof(name), "else%d_phi%d", block->block_index,
                         i);
                if (!(block->else_param_phis[i] = LLVMBuildPhi(
                          comp_ctx->builder,
                          TO_LLVM_TYPE(block->param_types[i]), name))) {
                    aot_set_last_error("llvm build phi failed.");
                    goto fail;
                }
            }
        }

        /* At this point, the branch instruction was already built to jump to
         * the new BB, to avoid generating zext instruction from the popped
         * operand that would come after branch instruction, we should position
         * the builder before the last branch instruction */
        br_inst = LLVMGetLastInstruction(block_curr);
        bh_assert(LLVMGetInstructionOpcode(br_inst) == LLVMBr);
        LLVMPositionBuilderBefore(comp_ctx->builder, br_inst);

        /* Pop param values from current block's
         * value stack and add to param phis.
         */
        for (i = 0; i < block->param_count; i++) {
            param_index = block->param_count - 1 - i;
            POP(value, block->param_types[param_index]);
            if (block->llvm_entry_block)
                /* Only add incoming phis if the entry block was created */
                ADD_TO_PARAM_PHIS(block, value, param_index);
            if (block->label_type == LABEL_TYPE_IF
                && !block->skip_wasm_code_else) {
                if (block->llvm_else_block) {
                    /* has else branch, add to else param phis */
                    LLVMAddIncoming(block->else_param_phis[param_index], &value,
                                    &block_curr, 1);
                }
                else {
                    /* no else branch, add to result phis */
                    CREATE_RESULT_VALUE_PHIS(block);
                    ADD_TO_RESULT_PHIS(block, value, param_index);
                }
            }
        }
    }

    /* Push the new block to block stack */
    aot_block_stack_push(&func_ctx->block_stack, block);

    /* Push param phis to the new block */
    for (i = 0; i < block->param_count; i++) {
        if (block->llvm_entry_block)
            /* Push param phis if the entry basic block was created */
            PUSH(block->param_phis[i], block->param_types[i]);
        else {
            bh_assert(block->label_type == LABEL_TYPE_IF
                      && block->llvm_else_block && block->else_param_phis
                      && !block->skip_wasm_code_else);
            /* Push else param phis if we start to translate the
               else branch */
            PUSH(block->else_param_phis[i], block->param_types[i]);
        }
    }

    return true;

fail:
    if (block->param_phis) {
        wasm_runtime_free(block->param_phis);
        block->param_phis = NULL;
    }
    if (block->else_param_phis) {
        wasm_runtime_free(block->else_param_phis);
        block->else_param_phis = NULL;
    }
    return false;
}

bool
aot_compile_op_block(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                     uint8 **p_frame_ip, uint8 *frame_ip_end, uint32 label_type,
                     uint32 param_count, uint8 *param_types,
                     uint32 result_count, uint8 *result_types)
{
    BlockAddr block_addr_cache[BLOCK_ADDR_CACHE_SIZE][BLOCK_ADDR_CONFLICT_SIZE];
    AOTBlock *block;
    uint8 *else_addr, *end_addr;
    LLVMValueRef value;
    char name[32];

    /* Check block stack */
    if (!func_ctx->block_stack.block_list_end) {
        aot_set_last_error("WASM block stack underflow.");
        return false;
    }

    memset(block_addr_cache, 0, sizeof(block_addr_cache));

    /* Get block info */
    if (!(wasm_loader_find_block_addr(
            NULL, (BlockAddr *)block_addr_cache, *p_frame_ip, frame_ip_end,
            (uint8)label_type, &else_addr, &end_addr))) {
        aot_set_last_error("find block end addr failed.");
        return false;
    }

    /* Allocate memory */
    if (!(block = wasm_runtime_malloc(sizeof(AOTBlock)))) {
        aot_set_last_error("allocate memory failed.");
        return false;
    }
    memset(block, 0, sizeof(AOTBlock));
    if (param_count
        && !(block->param_types = wasm_runtime_malloc(param_count))) {
        aot_set_last_error("allocate memory failed.");
        goto fail;
    }
    if (result_count) {
        if (!(block->result_types = wasm_runtime_malloc(result_count))) {
            aot_set_last_error("allocate memory failed.");
            goto fail;
        }
    }

    /* Init aot block data */
    block->label_type = label_type;
    block->param_count = param_count;
    if (param_count) {
        bh_memcpy_s(block->param_types, param_count, param_types, param_count);
    }
    block->result_count = result_count;
    if (result_count) {
        bh_memcpy_s(block->result_types, result_count, result_types,
                    result_count);
    }
    block->wasm_code_else = else_addr;
    block->wasm_code_end = end_addr;
    block->block_index = func_ctx->block_stack.block_index[label_type];
    func_ctx->block_stack.block_index[label_type]++;

    if (label_type == LABEL_TYPE_BLOCK || label_type == LABEL_TYPE_LOOP) {
        /* Create block */
        format_block_name(name, sizeof(name), block->block_index, label_type,
                          LABEL_BEGIN);
        CREATE_BLOCK(block->llvm_entry_block, name);
        MOVE_BLOCK_AFTER_CURR(block->llvm_entry_block);
        /* Jump to the entry block */
        BUILD_BR(block->llvm_entry_block);
        if (!push_aot_block_to_stack_and_pass_params(comp_ctx, func_ctx, block))
            goto fail;
        /* Start to translate the block */
        SET_BUILDER_POS(block->llvm_entry_block);
        if (label_type == LABEL_TYPE_LOOP)
            aot_checked_addr_list_destroy(func_ctx);
    }
    else if (label_type == LABEL_TYPE_IF) {
        POP_COND(value);

        if (LLVMIsUndef(value)
#if LLVM_VERSION_NUMBER >= 12
            || LLVMIsPoison(value)
#endif
        ) {
            if (!(aot_emit_exception(comp_ctx, func_ctx, EXCE_INTEGER_OVERFLOW,
                                     false, NULL, NULL))) {
                goto fail;
            }
            aot_block_destroy(block);
            return aot_handle_next_reachable_block(comp_ctx, func_ctx,
                                                   p_frame_ip);
        }

        if (!LLVMIsEfficientConstInt(value)) {
            /* Compare value is not constant, create condition br IR */
            /* Create entry block */
            format_block_name(name, sizeof(name), block->block_index,
                              label_type, LABEL_BEGIN);
            CREATE_BLOCK(block->llvm_entry_block, name);
            MOVE_BLOCK_AFTER_CURR(block->llvm_entry_block);

            /* Create end block */
            format_block_name(name, sizeof(name), block->block_index,
                              label_type, LABEL_END);
            CREATE_BLOCK(block->llvm_end_block, name);
            MOVE_BLOCK_AFTER(block->llvm_end_block, block->llvm_entry_block);

            if (else_addr) {
                /* Create else block */
                format_block_name(name, sizeof(name), block->block_index,
                                  label_type, LABEL_ELSE);
                CREATE_BLOCK(block->llvm_else_block, name);
                MOVE_BLOCK_AFTER(block->llvm_else_block,
                                 block->llvm_entry_block);
                /* Create condition br IR */
                BUILD_COND_BR(value, block->llvm_entry_block,
                              block->llvm_else_block);
            }
            else {
                /* Create condition br IR */
                BUILD_COND_BR(value, block->llvm_entry_block,
                              block->llvm_end_block);
                block->is_reachable = true;
            }
            if (!push_aot_block_to_stack_and_pass_params(comp_ctx, func_ctx,
                                                         block))
                goto fail;
            /* Start to translate if branch of BLOCK if */
            SET_BUILDER_POS(block->llvm_entry_block);
        }
        else {
            if ((int32)LLVMConstIntGetZExtValue(value) != 0) {
                /* Compare value is not 0, condition is true, else branch of
                   BLOCK if cannot be reached */
                block->skip_wasm_code_else = true;
                /* Create entry block */
                format_block_name(name, sizeof(name), block->block_index,
                                  label_type, LABEL_BEGIN);
                CREATE_BLOCK(block->llvm_entry_block, name);
                MOVE_BLOCK_AFTER_CURR(block->llvm_entry_block);
                /* Jump to the entry block */
                BUILD_BR(block->llvm_entry_block);
                if (!push_aot_block_to_stack_and_pass_params(comp_ctx, func_ctx,
                                                             block))
                    goto fail;
                /* Start to translate the if branch */
                SET_BUILDER_POS(block->llvm_entry_block);
            }
            else {
                /* Compare value is not 0, condition is false, if branch of
                   BLOCK if cannot be reached */
                if (else_addr) {
                    /* Create else block */
                    format_block_name(name, sizeof(name), block->block_index,
                                      label_type, LABEL_ELSE);
                    CREATE_BLOCK(block->llvm_else_block, name);
                    MOVE_BLOCK_AFTER_CURR(block->llvm_else_block);
                    /* Jump to the else block */
                    BUILD_BR(block->llvm_else_block);
                    if (!push_aot_block_to_stack_and_pass_params(
                            comp_ctx, func_ctx, block))
                        goto fail;
                    /* Start to translate the else branch */
                    SET_BUILDER_POS(block->llvm_else_block);
                    *p_frame_ip = else_addr + 1;
                }
                else {
                    /* skip the block */
                    aot_block_destroy(block);
                    *p_frame_ip = end_addr + 1;
                }
            }
        }
    }
    else {
        aot_set_last_error("Invalid block type.");
        goto fail;
    }

    return true;
fail:
    aot_block_destroy(block);
    return false;
}

bool
aot_compile_op_else(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                    uint8 **p_frame_ip)
{
    AOTBlock *block = func_ctx->block_stack.block_list_end;
    LLVMValueRef value;
    char name[32];
    uint32 i, result_index;

    /* Check block */
    if (!block) {
        aot_set_last_error("WASM block stack underflow.");
        return false;
    }
    if (block->label_type != LABEL_TYPE_IF
        || (!block->skip_wasm_code_else && !block->llvm_else_block)) {
        aot_set_last_error("Invalid WASM block type.");
        return false;
    }

    /* Create end block if needed */
    if (!block->llvm_end_block) {
        format_block_name(name, sizeof(name), block->block_index,
                          block->label_type, LABEL_END);
        CREATE_BLOCK(block->llvm_end_block, name);
        if (block->llvm_else_block)
            MOVE_BLOCK_AFTER(block->llvm_end_block, block->llvm_else_block);
        else
            MOVE_BLOCK_AFTER_CURR(block->llvm_end_block);
    }

    block->is_reachable = true;

    /* Comes from the if branch of BLOCK if */
    CREATE_RESULT_VALUE_PHIS(block);
    for (i = 0; i < block->result_count; i++) {
        result_index = block->result_count - 1 - i;
        POP(value, block->result_types[result_index]);
        ADD_TO_RESULT_PHIS(block, value, result_index);
    }

    /* Jump to end block */
    BUILD_BR(block->llvm_end_block);

    if (!block->skip_wasm_code_else && block->llvm_else_block) {
        /* Clear value stack, recover param values
         * and start to translate else branch.
         */
        aot_value_stack_destroy(&block->value_stack);
        for (i = 0; i < block->param_count; i++)
            PUSH(block->else_param_phis[i], block->param_types[i]);
        SET_BUILDER_POS(block->llvm_else_block);
        aot_checked_addr_list_destroy(func_ctx);
        return true;
    }

    /* No else branch or no need to translate else branch */
    block->is_reachable = true;
    return handle_next_reachable_block(comp_ctx, func_ctx, p_frame_ip);
fail:
    return false;
}

bool
aot_compile_op_end(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                   uint8 **p_frame_ip)
{
    AOTBlock *block;
    LLVMValueRef value;
    LLVMBasicBlockRef next_llvm_end_block;
    char name[32];
    uint32 i, result_index;

    /* Check block stack */
    if (!(block = func_ctx->block_stack.block_list_end)) {
        aot_set_last_error("WASM block stack underflow.");
        return false;
    }

    /* Create the end block */
    if (!block->llvm_end_block) {
        format_block_name(name, sizeof(name), block->block_index,
                          block->label_type, LABEL_END);
        CREATE_BLOCK(block->llvm_end_block, name);
        if ((next_llvm_end_block = find_next_llvm_end_block(block)))
            MOVE_BLOCK_BEFORE(block->llvm_end_block, next_llvm_end_block);
    }

    /* Handle block result values */
    CREATE_RESULT_VALUE_PHIS(block);
    for (i = 0; i < block->result_count; i++) {
        value = NULL;
        result_index = block->result_count - 1 - i;
        POP(value, block->result_types[result_index]);
        bh_assert(value);
        ADD_TO_RESULT_PHIS(block, value, result_index);
    }

    /* Jump to the end block */
    BUILD_BR(block->llvm_end_block);

    block->is_reachable = true;
    return handle_next_reachable_block(comp_ctx, func_ctx, p_frame_ip);
fail:
    return false;
}

#if WASM_ENABLE_THREAD_MGR != 0
bool
check_suspend_flags(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx)
{
    LLVMValueRef terminate_addr, terminate_flags, flag, offset, res;
    LLVMBasicBlockRef terminate_block, non_terminate_block;
    AOTFuncType *aot_func_type = func_ctx->aot_func->func_type;
    bool is_shared_memory =
        comp_ctx->comp_data->memories[0].memory_flags & 0x02 ? true : false;

    /* Only need to check the suspend flags when memory is shared since
       shared memory must be enabled for multi-threading */
    if (!is_shared_memory) {
        return true;
    }

    /* Offset of suspend_flags */
    offset = I32_FIVE;

    if (!(terminate_addr = LLVMBuildInBoundsGEP2(
              comp_ctx->builder, OPQ_PTR_TYPE, func_ctx->exec_env, &offset, 1,
              "terminate_addr"))) {
        aot_set_last_error("llvm build in bounds gep failed");
        return false;
    }
    if (!(terminate_addr =
              LLVMBuildBitCast(comp_ctx->builder, terminate_addr,
                               INT32_PTR_TYPE, "terminate_addr_ptr"))) {
        aot_set_last_error("llvm build bit cast failed");
        return false;
    }

    if (!(terminate_flags =
              LLVMBuildLoad2(comp_ctx->builder, I32_TYPE, terminate_addr,
                             "terminate_flags"))) {
        aot_set_last_error("llvm build LOAD failed");
        return false;
    }
    /* Set terminate_flags memory accecc to volatile, so that the value
        will always be loaded from memory rather than register */
    LLVMSetVolatile(terminate_flags, true);

    if (!(flag = LLVMBuildAnd(comp_ctx->builder, terminate_flags, I32_ONE,
                              "termination_flag"))) {
        aot_set_last_error("llvm build AND failed");
        return false;
    }

    CREATE_BLOCK(non_terminate_block, "non_terminate");
    MOVE_BLOCK_AFTER_CURR(non_terminate_block);

    CREATE_BLOCK(terminate_block, "terminate");
    MOVE_BLOCK_AFTER_CURR(terminate_block);

    BUILD_ICMP(LLVMIntEQ, flag, I32_ZERO, res, "flag_terminate");
    BUILD_COND_BR(res, non_terminate_block, terminate_block);

    /* Move builder to terminate block */
    SET_BUILDER_POS(terminate_block);
    if (!aot_build_zero_function_ret(comp_ctx, func_ctx, aot_func_type)) {
        goto fail;
    }

    /* Move builder to non terminate block */
    SET_BUILDER_POS(non_terminate_block);
    return true;

fail:
    return false;
}
#endif /* End of WASM_ENABLE_THREAD_MGR */

bool
aot_compile_op_br(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                  uint32 br_depth, uint8 **p_frame_ip)
{
    AOTBlock *block_dst;
    LLVMValueRef value_ret, value_param;
    LLVMBasicBlockRef next_llvm_end_block;
    char name[32];
    uint32 i, param_index, result_index;

#if WASM_ENABLE_THREAD_MGR != 0
    /* Insert suspend check point */
    if (comp_ctx->enable_thread_mgr) {
        if (!check_suspend_flags(comp_ctx, func_ctx))
            return false;
    }
#endif

    if (!(block_dst = get_target_block(func_ctx, br_depth))) {
        return false;
    }

    if (block_dst->label_type == LABEL_TYPE_LOOP) {
        /* Dest block is Loop block */
        /* Handle Loop parameters */
        for (i = 0; i < block_dst->param_count; i++) {
            param_index = block_dst->param_count - 1 - i;
            POP(value_param, block_dst->param_types[param_index]);
            ADD_TO_PARAM_PHIS(block_dst, value_param, param_index);
        }
        BUILD_BR(block_dst->llvm_entry_block);
    }
    else {
        /* Dest block is Block/If/Function block */
        /* Create the end block */
        if (!block_dst->llvm_end_block) {
            format_block_name(name, sizeof(name), block_dst->block_index,
                              block_dst->label_type, LABEL_END);
            CREATE_BLOCK(block_dst->llvm_end_block, name);
            if ((next_llvm_end_block = find_next_llvm_end_block(block_dst)))
                MOVE_BLOCK_BEFORE(block_dst->llvm_end_block,
                                  next_llvm_end_block);
        }

        block_dst->is_reachable = true;

        /* Handle result values */
        CREATE_RESULT_VALUE_PHIS(block_dst);
        for (i = 0; i < block_dst->result_count; i++) {
            result_index = block_dst->result_count - 1 - i;
            POP(value_ret, block_dst->result_types[result_index]);
            ADD_TO_RESULT_PHIS(block_dst, value_ret, result_index);
        }
        /* Jump to the end block */
        BUILD_BR(block_dst->llvm_end_block);
    }

    return handle_next_reachable_block(comp_ctx, func_ctx, p_frame_ip);
fail:
    return false;
}

bool
aot_compile_op_br_if(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                     uint32 br_depth, uint8 **p_frame_ip)
{
    AOTBlock *block_dst;
    LLVMValueRef value_cmp, value, *values = NULL;
    LLVMBasicBlockRef llvm_else_block, next_llvm_end_block;
    char name[32];
    uint32 i, param_index, result_index;
    uint64 size;

#if WASM_ENABLE_THREAD_MGR != 0
    /* Insert suspend check point */
    if (comp_ctx->enable_thread_mgr) {
        if (!check_suspend_flags(comp_ctx, func_ctx))
            return false;
    }
#endif

    POP_COND(value_cmp);

    if (LLVMIsUndef(value_cmp)
#if LLVM_VERSION_NUMBER >= 12
        || LLVMIsPoison(value_cmp)
#endif
    ) {
        if (!(aot_emit_exception(comp_ctx, func_ctx, EXCE_INTEGER_OVERFLOW,
                                 false, NULL, NULL))) {
            goto fail;
        }
        return aot_handle_next_reachable_block(comp_ctx, func_ctx, p_frame_ip);
    }

    if (!LLVMIsEfficientConstInt(value_cmp)) {
        /* Compare value is not constant, create condition br IR */
        if (!(block_dst = get_target_block(func_ctx, br_depth))) {
            return false;
        }

        /* Create llvm else block */
        CREATE_BLOCK(llvm_else_block, "br_if_else");
        MOVE_BLOCK_AFTER_CURR(llvm_else_block);

        if (block_dst->label_type == LABEL_TYPE_LOOP) {
            /* Dest block is Loop block */
            /* Handle Loop parameters */
            if (block_dst->param_count) {
                size = sizeof(LLVMValueRef) * (uint64)block_dst->param_count;
                if (size >= UINT32_MAX
                    || !(values = wasm_runtime_malloc((uint32)size))) {
                    aot_set_last_error("allocate memory failed.");
                    goto fail;
                }
                for (i = 0; i < block_dst->param_count; i++) {
                    param_index = block_dst->param_count - 1 - i;
                    POP(value, block_dst->param_types[param_index]);
                    ADD_TO_PARAM_PHIS(block_dst, value, param_index);
                    values[param_index] = value;
                }
                for (i = 0; i < block_dst->param_count; i++) {
                    PUSH(values[i], block_dst->param_types[i]);
                }
                wasm_runtime_free(values);
                values = NULL;
            }

            BUILD_COND_BR(value_cmp, block_dst->llvm_entry_block,
                          llvm_else_block);

            /* Move builder to else block */
            SET_BUILDER_POS(llvm_else_block);
        }
        else {
            /* Dest block is Block/If/Function block */
            /* Create the end block */
            if (!block_dst->llvm_end_block) {
                format_block_name(name, sizeof(name), block_dst->block_index,
                                  block_dst->label_type, LABEL_END);
                CREATE_BLOCK(block_dst->llvm_end_block, name);
                if ((next_llvm_end_block = find_next_llvm_end_block(block_dst)))
                    MOVE_BLOCK_BEFORE(block_dst->llvm_end_block,
                                      next_llvm_end_block);
            }

            /* Set reachable flag and create condition br IR */
            block_dst->is_reachable = true;

            /* Handle result values */
            if (block_dst->result_count) {
                size = sizeof(LLVMValueRef) * (uint64)block_dst->result_count;
                if (size >= UINT32_MAX
                    || !(values = wasm_runtime_malloc((uint32)size))) {
                    aot_set_last_error("allocate memory failed.");
                    goto fail;
                }
                CREATE_RESULT_VALUE_PHIS(block_dst);
                for (i = 0; i < block_dst->result_count; i++) {
                    result_index = block_dst->result_count - 1 - i;
                    POP(value, block_dst->result_types[result_index]);
                    values[result_index] = value;
                    ADD_TO_RESULT_PHIS(block_dst, value, result_index);
                }
                for (i = 0; i < block_dst->result_count; i++) {
                    PUSH(values[i], block_dst->result_types[i]);
                }
                wasm_runtime_free(values);
                values = NULL;
            }

            /* Condition jump to end block */
            BUILD_COND_BR(value_cmp, block_dst->llvm_end_block,
                          llvm_else_block);

            /* Move builder to else block */
            SET_BUILDER_POS(llvm_else_block);
        }
    }
    else {
        if ((int32)LLVMConstIntGetZExtValue(value_cmp) != 0) {
            /* Compare value is not 0, condition is true, same as op_br */
            return aot_compile_op_br(comp_ctx, func_ctx, br_depth, p_frame_ip);
        }
        else {
            /* Compare value is not 0, condition is false, skip br_if */
            return true;
        }
    }
    return true;
fail:
    if (values)
        wasm_runtime_free(values);
    return false;
}

bool
aot_compile_op_br_table(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                        uint32 *br_depths, uint32 br_count, uint8 **p_frame_ip)
{
    uint32 i, j;
    LLVMValueRef value_switch, value_cmp, value_case, value, *values = NULL;
    LLVMBasicBlockRef default_llvm_block = NULL, target_llvm_block;
    LLVMBasicBlockRef next_llvm_end_block;
    AOTBlock *target_block;
    uint32 br_depth, depth_idx;
    uint32 param_index, result_index;
    uint64 size;
    char name[32];

#if WASM_ENABLE_THREAD_MGR != 0
    /* Insert suspend check point */
    if (comp_ctx->enable_thread_mgr) {
        if (!check_suspend_flags(comp_ctx, func_ctx))
            return false;
    }
#endif

    POP_I32(value_cmp);

    if (LLVMIsUndef(value_cmp)
#if LLVM_VERSION_NUMBER >= 12
        || LLVMIsPoison(value_cmp)
#endif
    ) {
        if (!(aot_emit_exception(comp_ctx, func_ctx, EXCE_INTEGER_OVERFLOW,
                                 false, NULL, NULL))) {
            goto fail;
        }
        return aot_handle_next_reachable_block(comp_ctx, func_ctx, p_frame_ip);
    }

    if (!LLVMIsEfficientConstInt(value_cmp)) {
        /* Compare value is not constant, create switch IR */
        for (i = 0; i <= br_count; i++) {
            target_block = get_target_block(func_ctx, br_depths[i]);
            if (!target_block)
                return false;

            if (target_block->label_type != LABEL_TYPE_LOOP) {
                /* Dest block is Block/If/Function block */
                /* Create the end block */
                if (!target_block->llvm_end_block) {
                    format_block_name(name, sizeof(name),
                                      target_block->block_index,
                                      target_block->label_type, LABEL_END);
                    CREATE_BLOCK(target_block->llvm_end_block, name);
                    if ((next_llvm_end_block =
                             find_next_llvm_end_block(target_block)))
                        MOVE_BLOCK_BEFORE(target_block->llvm_end_block,
                                          next_llvm_end_block);
                }
                /* Handle result values */
                if (target_block->result_count) {
                    size = sizeof(LLVMValueRef)
                           * (uint64)target_block->result_count;
                    if (size >= UINT32_MAX
                        || !(values = wasm_runtime_malloc((uint32)size))) {
                        aot_set_last_error("allocate memory failed.");
                        goto fail;
                    }
                    CREATE_RESULT_VALUE_PHIS(target_block);
                    for (j = 0; j < target_block->result_count; j++) {
                        result_index = target_block->result_count - 1 - j;
                        POP(value, target_block->result_types[result_index]);
                        values[result_index] = value;
                        ADD_TO_RESULT_PHIS(target_block, value, result_index);
                    }
                    for (j = 0; j < target_block->result_count; j++) {
                        PUSH(values[j], target_block->result_types[j]);
                    }
                    wasm_runtime_free(values);
                    values = NULL;
                }
                target_block->is_reachable = true;
                if (i == br_count)
                    default_llvm_block = target_block->llvm_end_block;
            }
            else {
                /* Handle Loop parameters */
                if (target_block->param_count) {
                    size = sizeof(LLVMValueRef)
                           * (uint64)target_block->param_count;
                    if (size >= UINT32_MAX
                        || !(values = wasm_runtime_malloc((uint32)size))) {
                        aot_set_last_error("allocate memory failed.");
                        goto fail;
                    }
                    for (j = 0; j < target_block->param_count; j++) {
                        param_index = target_block->param_count - 1 - j;
                        POP(value, target_block->param_types[param_index]);
                        values[param_index] = value;
                        ADD_TO_PARAM_PHIS(target_block, value, param_index);
                    }
                    for (j = 0; j < target_block->param_count; j++) {
                        PUSH(values[j], target_block->param_types[j]);
                    }
                    wasm_runtime_free(values);
                    values = NULL;
                }
                if (i == br_count)
                    default_llvm_block = target_block->llvm_entry_block;
            }
        }

        /* Create switch IR */
        if (!(value_switch = LLVMBuildSwitch(comp_ctx->builder, value_cmp,
                                             default_llvm_block, br_count))) {
            aot_set_last_error("llvm build switch failed.");
            return false;
        }

        /* Add each case for switch IR */
        for (i = 0; i < br_count; i++) {
            value_case = I32_CONST(i);
            CHECK_LLVM_CONST(value_case);
            target_block = get_target_block(func_ctx, br_depths[i]);
            if (!target_block)
                return false;
            target_llvm_block = target_block->label_type != LABEL_TYPE_LOOP
                                    ? target_block->llvm_end_block
                                    : target_block->llvm_entry_block;
            LLVMAddCase(value_switch, value_case, target_llvm_block);
        }

        return handle_next_reachable_block(comp_ctx, func_ctx, p_frame_ip);
    }
    else {
        /* Compare value is constant, create br IR */
        depth_idx = (uint32)LLVMConstIntGetZExtValue(value_cmp);
        br_depth = br_depths[br_count];
        if (depth_idx < br_count) {
            br_depth = br_depths[depth_idx];
        }
        return aot_compile_op_br(comp_ctx, func_ctx, br_depth, p_frame_ip);
    }
fail:
    if (values)
        wasm_runtime_free(values);
    return false;
}

bool
aot_compile_op_return(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                      uint8 **p_frame_ip)
{
    AOTBlock *block_func = func_ctx->block_stack.block_list_head;
    LLVMValueRef value;
    LLVMValueRef ret;
    AOTFuncType *func_type;
    uint32 i, param_index, result_index;
#if WASM_ENABLE_DEBUG_AOT != 0
    LLVMMetadataRef return_location;
#endif

    bh_assert(block_func);
    func_type = func_ctx->aot_func->func_type;

#if WASM_ENABLE_DEBUG_AOT != 0
    return_location = dwarf_gen_location(
        comp_ctx, func_ctx,
        (*p_frame_ip - 1) - comp_ctx->comp_data->wasm_module->buf_code);
#endif
    if (block_func->result_count) {
        /* Store extra result values to function parameters */
        for (i = 0; i < block_func->result_count - 1; i++) {
            LLVMValueRef res;
            result_index = block_func->result_count - 1 - i;
            POP(value, block_func->result_types[result_index]);
            param_index = func_type->param_count + result_index;
            if (!(res = LLVMBuildStore(
                      comp_ctx->builder, value,
                      LLVMGetParam(func_ctx->func, param_index)))) {
                aot_set_last_error("llvm build store failed.");
                goto fail;
            }
            LLVMSetAlignment(res, 1);
        }
        /* Return the first result value */
        POP(value, block_func->result_types[0]);
        if (!(ret = LLVMBuildRet(comp_ctx->builder, value))) {
            aot_set_last_error("llvm build return failed.");
            goto fail;
        }
#if WASM_ENABLE_DEBUG_AOT != 0
        LLVMInstructionSetDebugLoc(ret, return_location);
#endif
    }
    else {
        if (!(ret = LLVMBuildRetVoid(comp_ctx->builder))) {
            aot_set_last_error("llvm build return void failed.");
            goto fail;
        }
#if WASM_ENABLE_DEBUG_AOT != 0
        LLVMInstructionSetDebugLoc(ret, return_location);
#endif
    }

    return handle_next_reachable_block(comp_ctx, func_ctx, p_frame_ip);
fail:
    return false;
}

bool
aot_compile_op_unreachable(AOTCompContext *comp_ctx, AOTFuncContext *func_ctx,
                           uint8 **p_frame_ip)
{
    if (!aot_emit_exception(comp_ctx, func_ctx, EXCE_UNREACHABLE, false, NULL,
                            NULL))
        return false;

    return handle_next_reachable_block(comp_ctx, func_ctx, p_frame_ip);
}

bool
aot_handle_next_reachable_block(AOTCompContext *comp_ctx,
                                AOTFuncContext *func_ctx, uint8 **p_frame_ip)
{
    return handle_next_reachable_block(comp_ctx, func_ctx, p_frame_ip);
}
