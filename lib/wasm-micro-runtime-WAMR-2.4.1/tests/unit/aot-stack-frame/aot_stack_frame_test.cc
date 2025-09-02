/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "gtest/gtest.h"
#include "bh_platform.h"
#include "wasm_runtime_common.h"
#include "aot_runtime.h"
#include "test_helper.h"

#ifndef __aligned
#define __aligned(n)
#endif
#include "wasm-apps/test_aot.h"

typedef struct MyAOTFrame {
    uintptr_t func_index;

    /* Instruction pointer: offset to the bytecode array */
    uintptr_t ip_offset;

    /* Operand stack top pointer of the current frame */
    uint32 *sp;

#if WASM_ENABLE_GC != 0
    /* Frame ref flags (GC only) */
    uint8 *frame_ref;
#endif

    uint32 lp[1];
} MyAOTFrame;

class AOTStackFrameTest : public testing::Test
{
  protected:
    virtual void SetUp()
    {
        memset(&init_args, 0, sizeof(RuntimeInitArgs));

        init_args.mem_alloc_type = Alloc_With_Pool;
        init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
        init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);

        ASSERT_EQ(wasm_runtime_full_init(&init_args), true);
    }

    virtual void TearDown()
    {
        DestroyFrames();
        wasm_runtime_destroy();
    }

  public:
    static void DestroyFrames()
    {
        if (my_frames) {
            for (uint32 i = 0; i < my_frame_num; i++) {
                if (my_frames[i])
                    wasm_runtime_free(my_frames[i]);
            }
            wasm_runtime_free(my_frames);
            my_frames = NULL;
            my_frame_num = 0;
        }
    }

  public:
    RuntimeInitArgs init_args;
    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    wasm_function_inst_t func_inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    static MyAOTFrame **my_frames;
    static uint32 my_frame_num;
    char error_buf[128];
    char global_heap_buf[512 * 1024];
    unsigned char test_aot_buf[16 * 1024];
    unsigned argv[8];
};

MyAOTFrame **AOTStackFrameTest::my_frames = NULL;
uint32 AOTStackFrameTest::my_frame_num = 0;

extern "C" {

typedef void (*stack_frame_callback_t)(struct WASMExecEnv *exec_env);

void
aot_set_stack_frame_callback(stack_frame_callback_t callback);

void
aot_stack_frame_cb(struct WASMExecEnv *exec_env)
{
    AOTModuleInstance *module_inst = (AOTModuleInstance *)exec_env->module_inst;
    AOTModule *module = (AOTModule *)module_inst->module;
    AOTFrame *frame = (AOTFrame *)exec_env->cur_frame;
    MyAOTFrame *my_frame, **my_frames;
    uint32 all_cell_num, max_local_cell_num, max_stack_cell_num;
    uint32 frame_size_old, frame_size, i, frame_num = 0, aot_func_idx;

    AOTStackFrameTest::DestroyFrames();

    while (frame) {
        frame_num++;
        frame = frame->prev_frame;
    }

    my_frames =
        (MyAOTFrame **)wasm_runtime_malloc(sizeof(MyAOTFrame *) * frame_num);
    bh_assert(my_frames);

    frame = (AOTFrame *)exec_env->cur_frame;
    for (i = 0; i < frame_num; i++) {
        aot_func_idx = frame->func_index;
        max_local_cell_num = module->max_local_cell_nums[aot_func_idx];
        max_stack_cell_num = module->max_stack_cell_nums[aot_func_idx];
        all_cell_num = max_local_cell_num + max_stack_cell_num;

        frame_size_old = (uint32)offsetof(AOTFrame, lp) + all_cell_num * 4;
        frame_size = (uint32)offsetof(MyAOTFrame, lp) + all_cell_num * 4;

        my_frames[frame_num - 1 - i] = my_frame =
            (MyAOTFrame *)wasm_runtime_malloc(frame_size);

        my_frame->func_index = aot_func_idx;
        my_frame->ip_offset = frame->ip_offset;
        my_frame->sp = my_frame->lp + (frame->sp - frame->lp);
#if WASM_ENABLE_GC != 0
        my_frame->frame_ref =
            (uint8 *)my_frame->lp + (frame->frame_ref - (uint8 *)frame->lp);
#endif

        bh_memcpy_s(my_frame->lp, all_cell_num * 4, frame->lp,
                    all_cell_num * 4);

        frame = frame->prev_frame;
    }

    AOTStackFrameTest::my_frames = my_frames;
    AOTStackFrameTest::my_frame_num = frame_num;
}
}

TEST_F(AOTStackFrameTest, test1)
{
    MyAOTFrame *frame, **frames;
    uint32 frame_num;

    aot_set_stack_frame_callback(aot_stack_frame_cb);

    bh_memcpy_s(test_aot_buf, sizeof(test_aot_buf), test_aot, sizeof(test_aot));

    module = wasm_runtime_load(test_aot_buf, sizeof(test_aot), error_buf,
                               sizeof(error_buf));
    ASSERT_TRUE(module != NULL);

    module_inst = wasm_runtime_instantiate(module, 16384, 0, error_buf,
                                           sizeof(error_buf));
    ASSERT_TRUE(module_inst != NULL);

    exec_env = wasm_runtime_create_exec_env(module_inst, 8 * 1024);
    ASSERT_TRUE(exec_env != NULL);

    func_inst = wasm_runtime_lookup_function(module_inst, "test2");
    ASSERT_TRUE(func_inst != NULL);

    argv[0] = 1234;
    argv[1] = 5678;
    wasm_runtime_call_wasm(exec_env, func_inst, 2, argv);
    ASSERT_TRUE(wasm_runtime_get_exception(module_inst));

    frames = AOTStackFrameTest::my_frames;
    frame_num = AOTStackFrameTest::my_frame_num;

    ASSERT_TRUE(frames != NULL);
    ASSERT_TRUE(frame_num == 1);

    ASSERT_TRUE(frames[0]->lp[0] == 1234);
    ASSERT_TRUE(frames[0]->lp[1] == 5678);
    ASSERT_TRUE(frames[0]->lp[2] == 0x11223344);
    ASSERT_TRUE(*(uint64 *)(frames[0]->lp + 3) == 0x12345678ABCDEF99LL);
    ASSERT_TRUE(*(float *)(frames[0]->lp + 5) == 5566.7788f);
    ASSERT_TRUE(*(double *)(frames[0]->lp + 6) == 99887766.55443322);
}

TEST_F(AOTStackFrameTest, test2)
{
    MyAOTFrame *frame, **frames;
    uint32 frame_num;

    aot_set_stack_frame_callback(aot_stack_frame_cb);

    bh_memcpy_s(test_aot_buf, sizeof(test_aot_buf), test_aot, sizeof(test_aot));

    module = wasm_runtime_load(test_aot_buf, sizeof(test_aot), error_buf,
                               sizeof(error_buf));
    ASSERT_TRUE(module != NULL);

    module_inst = wasm_runtime_instantiate(module, 16384, 0, error_buf,
                                           sizeof(error_buf));
    ASSERT_TRUE(module_inst != NULL);

    exec_env = wasm_runtime_create_exec_env(module_inst, 8 * 1024);
    ASSERT_TRUE(exec_env != NULL);

    func_inst = wasm_runtime_lookup_function(module_inst, "test3");
    ASSERT_TRUE(func_inst != NULL);

    argv[0] = 1234;
    argv[1] = 5678;
    wasm_runtime_call_wasm(exec_env, func_inst, 2, argv);
    ASSERT_TRUE(wasm_runtime_get_exception(module_inst));

    frames = AOTStackFrameTest::my_frames;
    frame_num = AOTStackFrameTest::my_frame_num;

    ASSERT_TRUE(frames != NULL);
    ASSERT_TRUE(frame_num == 2);

    // 5(i32) + 1(i64) local variables, occupied 7 * 4 bytes
    ASSERT_TRUE(frames[0]->sp - frames[0]->lp == 7);

    // offset of ip from module load address
    ASSERT_TRUE(frames[0]->ip_offset == 163);

    ASSERT_TRUE(frames[0]->lp[0] == 1234);
    ASSERT_TRUE(frames[0]->lp[1] == 5678);
    ASSERT_TRUE(frames[0]->lp[2] == 0x11223344);
    ASSERT_TRUE(*(uint64 *)(frames[0]->lp + 3) == 0x12345678ABCDEF99LL);
}
