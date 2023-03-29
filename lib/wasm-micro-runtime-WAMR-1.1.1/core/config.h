/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

/* clang-format off */
#if !defined(BUILD_TARGET_X86_64) \
    && !defined(BUILD_TARGET_AMD_64) \
    && !defined(BUILD_TARGET_AARCH64) \
    && !defined(BUILD_TARGET_X86_32) \
    && !defined(BUILD_TARGET_ARM) \
    && !defined(BUILD_TARGET_ARM_VFP) \
    && !defined(BUILD_TARGET_THUMB) \
    && !defined(BUILD_TARGET_THUMB_VFP) \
    && !defined(BUILD_TARGET_MIPS) \
    && !defined(BUILD_TARGET_XTENSA) \
    && !defined(BUILD_TARGET_RISCV64_LP64D) \
    && !defined(BUILD_TARGET_RISCV64_LP64) \
    && !defined(BUILD_TARGET_RISCV32_ILP32D) \
    && !defined(BUILD_TARGET_RISCV32_ILP32) \
    && !defined(BUILD_TARGET_ARC)
/* clang-format on */
#if defined(__x86_64__) || defined(__x86_64)
#define BUILD_TARGET_X86_64
#elif defined(__amd64__) || defined(__amd64)
#define BUILD_TARGET_AMD_64
#elif defined(__aarch64__)
#define BUILD_TARGET_AARCH64
#elif defined(__i386__) || defined(__i386) || defined(i386)
#define BUILD_TARGET_X86_32
#elif defined(__thumb__)
#define BUILD_TARGET_THUMB
#define BUILD_TARGET "THUMBV4T"
#elif defined(__arm__)
#define BUILD_TARGET_ARM
#define BUILD_TARGET "ARMV4T"
#elif defined(__mips__) || defined(__mips) || defined(mips)
#define BUILD_TARGET_MIPS
#elif defined(__XTENSA__)
#define BUILD_TARGET_XTENSA
#elif defined(__riscv) && (__riscv_xlen == 64)
#define BUILD_TARGET_RISCV64_LP64D
#elif defined(__riscv) && (__riscv_xlen == 32)
#define BUILD_TARGET_RISCV32_ILP32D
#elif defined(__arc__)
#define BUILD_TARGET_ARC
#else
#error "Build target isn't set"
#endif
#endif

#ifndef BH_DEBUG
#define BH_DEBUG 0
#endif

#define MEM_ALLOCATOR_EMS 0
#define MEM_ALLOCATOR_TLSF 1

/* Default memory allocator */
#define DEFAULT_MEM_ALLOCATOR MEM_ALLOCATOR_EMS

#ifndef WASM_ENABLE_INTERP
#define WASM_ENABLE_INTERP 0
#endif

#ifndef WASM_ENABLE_AOT
#define WASM_ENABLE_AOT 0
#endif

#define AOT_MAGIC_NUMBER 0x746f6100
#define AOT_CURRENT_VERSION 3

#ifndef WASM_ENABLE_JIT
#define WASM_ENABLE_JIT 0
#endif

#ifndef WASM_ENABLE_LAZY_JIT
#define WASM_ENABLE_LAZY_JIT 0
#endif

#ifndef WASM_LAZY_JIT_COMPILE_THREAD_NUM
#define WASM_LAZY_JIT_COMPILE_THREAD_NUM 4
#endif

#if (WASM_ENABLE_AOT == 0) && (WASM_ENABLE_JIT != 0)
/* LazyJIT or MCJIT can only be enabled when AOT is enabled */
#undef WASM_ENABLE_JIT
#define WASM_ENABLE_JIT 0

#undef WASM_ENABLE_LAZY_JIT
#define WASM_ENABLE_LAZY_JIT 0
#endif

#ifndef WASM_ENABLE_FAST_JIT
#define WASM_ENABLE_FAST_JIT 0
#endif

#ifndef WASM_ENABLE_FAST_JIT_DUMP
#define WASM_ENABLE_FAST_JIT_DUMP 0
#endif

#ifndef FAST_JIT_DEFAULT_CODE_CACHE_SIZE
#define FAST_JIT_DEFAULT_CODE_CACHE_SIZE 10 * 1024 * 1024
#endif

#ifndef WASM_ENABLE_WAMR_COMPILER
#define WASM_ENABLE_WAMR_COMPILER 0
#endif

#if WASM_ENABLE_WAMR_COMPILER != 0
#ifndef WASM_ENABLE_LLVM_LEGACY_PM
/* Whether to use LLVM legacy pass manager when building wamrc,
   by default it is disabled and LLVM new pass manager is used */
#define WASM_ENABLE_LLVM_LEGACY_PM 0
#endif
#endif

#ifndef WASM_ENABLE_LIBC_BUILTIN
#define WASM_ENABLE_LIBC_BUILTIN 0
#endif

#ifndef WASM_ENABLE_LIBC_WASI
#define WASM_ENABLE_LIBC_WASI 0
#endif

#ifndef WASM_ENABLE_UVWASI
#define WASM_ENABLE_UVWASI 0
#endif

/* Default disable libc emcc */
#ifndef WASM_ENABLE_LIBC_EMCC
#define WASM_ENABLE_LIBC_EMCC 0
#endif

#ifndef WASM_ENABLE_LIB_RATS
#define WASM_ENABLE_LIB_RATS 0
#endif

#ifndef WASM_ENABLE_LIB_PTHREAD
#define WASM_ENABLE_LIB_PTHREAD 0
#endif

#ifndef WASM_ENABLE_LIB_PTHREAD_SEMAPHORE
#define WASM_ENABLE_LIB_PTHREAD_SEMAPHORE 0
#endif

#ifndef WASM_ENABLE_BASE_LIB
#define WASM_ENABLE_BASE_LIB 0
#endif

#ifndef WASM_ENABLE_APP_FRAMEWORK
#define WASM_ENABLE_APP_FRAMEWORK 0
#endif

/* Bulk memory operation */
#ifndef WASM_ENABLE_BULK_MEMORY
#define WASM_ENABLE_BULK_MEMORY 0
#endif

/* Shared memory */
#ifndef WASM_ENABLE_SHARED_MEMORY
#define WASM_ENABLE_SHARED_MEMORY 0
#endif

/* Thread manager */
#ifndef WASM_ENABLE_THREAD_MGR
#define WASM_ENABLE_THREAD_MGR 0
#endif

/* Source debugging */
#ifndef WASM_ENABLE_DEBUG_INTERP
#define WASM_ENABLE_DEBUG_INTERP 0
#endif

#if WASM_ENABLE_DEBUG_INTERP != 0
#ifndef DEBUG_EXECUTION_MEMORY_SIZE
/* 0x85000 is the size required by lldb, if this is changed to a smaller value,
 * then the debugger will not be able to evaluate user expressions, other
 * functionality such as breakpoint and stepping are not influenced by this */
#define DEBUG_EXECUTION_MEMORY_SIZE 0x85000
#endif
#endif /* end of WASM_ENABLE_DEBUG_INTERP != 0 */

#ifndef WASM_ENABLE_DEBUG_AOT
#define WASM_ENABLE_DEBUG_AOT 0
#endif

/* Custom sections */
#ifndef WASM_ENABLE_LOAD_CUSTOM_SECTION
#define WASM_ENABLE_LOAD_CUSTOM_SECTION 0
#endif

/* WASM log system */
#ifndef WASM_ENABLE_LOG
#define WASM_ENABLE_LOG 1
#endif

#ifndef WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS
#if defined(BUILD_TARGET_X86_32) || defined(BUILD_TARGET_X86_64) \
    || defined(BUILD_TARGET_AARCH64)
#define WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS 1
#else
#define WASM_CPU_SUPPORTS_UNALIGNED_ADDR_ACCESS 0
#endif
#endif

/* WASM Interpreter labels-as-values feature */
#ifndef WASM_ENABLE_LABELS_AS_VALUES
#ifdef __GNUC__
#define WASM_ENABLE_LABELS_AS_VALUES 1
#else
#define WASM_ENABLE_LABELS_AS_VALUES 0
#endif
#endif

/* Enable fast interpreter or not */
#ifndef WASM_ENABLE_FAST_INTERP
#define WASM_ENABLE_FAST_INTERP 0
#endif

#if WASM_ENABLE_FAST_INTERP != 0
#define WASM_DEBUG_PREPROCESSOR 0
#endif

/* Enable opcode counter or not */
#ifndef WASM_ENABLE_OPCODE_COUNTER
#define WASM_ENABLE_OPCODE_COUNTER 0
#endif

/* Support a module with dependency, other modules */
#ifndef WASM_ENABLE_MULTI_MODULE
#define WASM_ENABLE_MULTI_MODULE 0
#endif

/* Enable wasm mini loader or not */
#ifndef WASM_ENABLE_MINI_LOADER
#define WASM_ENABLE_MINI_LOADER 0
#endif

/* Disable boundary check with hardware trap or not,
 * enable it by default if it is supported */
#ifndef WASM_DISABLE_HW_BOUND_CHECK
#define WASM_DISABLE_HW_BOUND_CHECK 0
#endif

/* Disable SIMD unless it is manualy enabled somewhere */
#ifndef WASM_ENABLE_SIMD
#define WASM_ENABLE_SIMD 0
#endif

/* Memory profiling */
#ifndef WASM_ENABLE_MEMORY_PROFILING
#define WASM_ENABLE_MEMORY_PROFILING 0
#endif

/* Memory tracing */
#ifndef WASM_ENABLE_MEMORY_TRACING
#define WASM_ENABLE_MEMORY_TRACING 0
#endif

/* Performance profiling */
#ifndef WASM_ENABLE_PERF_PROFILING
#define WASM_ENABLE_PERF_PROFILING 0
#endif

/* Dump call stack */
#ifndef WASM_ENABLE_DUMP_CALL_STACK
#define WASM_ENABLE_DUMP_CALL_STACK 0
#endif

/* Heap verification */
#ifndef BH_ENABLE_GC_VERIFY
#define BH_ENABLE_GC_VERIFY 0
#endif

/* Enable global heap pool if heap verification is enabled */
#if BH_ENABLE_GC_VERIFY != 0
#define WASM_ENABLE_GLOBAL_HEAP_POOL 1
#endif

/* Global heap pool */
#ifndef WASM_ENABLE_GLOBAL_HEAP_POOL
#define WASM_ENABLE_GLOBAL_HEAP_POOL 0
#endif

#ifndef WASM_ENABLE_SPEC_TEST
#define WASM_ENABLE_SPEC_TEST 0
#endif

/* Global heap pool size in bytes */
#ifndef WASM_GLOBAL_HEAP_SIZE
#if WASM_ENABLE_SPEC_TEST != 0
/* Spec test requires more heap pool size */
#define WASM_GLOBAL_HEAP_SIZE (300 * 1024 * 1024)
#else
#define WASM_GLOBAL_HEAP_SIZE (10 * 1024 * 1024)
#endif
#endif

/* Max app number of all modules */
#define MAX_APP_INSTALLATIONS 3

/* Default timer number in one app */
#define DEFAULT_TIMERS_PER_APP 20

/* Max timer number in one app */
#define MAX_TIMERS_PER_APP 30

/* Max connection number in one app */
#define MAX_CONNECTION_PER_APP 20

/* Max resource registration number in one app */
#define RESOURCE_REGISTRATION_NUM_MAX 16

/* Max length of resource/event url */
#define RESOUCE_EVENT_URL_LEN_MAX 256

/* Default length of queue */
#define DEFAULT_QUEUE_LENGTH 50

/* Default watchdog interval in ms */
#define DEFAULT_WATCHDOG_INTERVAL (3 * 60 * 1000)

/* The max percentage of global heap that app memory space can grow */
#define APP_MEMORY_MAX_GLOBAL_HEAP_PERCENT 1 / 3

/* Default min/max heap size of each app */
#ifndef APP_HEAP_SIZE_DEFAULT
#define APP_HEAP_SIZE_DEFAULT (8 * 1024)
#endif
#define APP_HEAP_SIZE_MIN (256)
#define APP_HEAP_SIZE_MAX (512 * 1024 * 1024)

/* Default wasm stack size of each app */
#if defined(BUILD_TARGET_X86_64) || defined(BUILD_TARGET_AMD_64)
#define DEFAULT_WASM_STACK_SIZE (16 * 1024)
#else
#define DEFAULT_WASM_STACK_SIZE (12 * 1024)
#endif
/* Min auxilliary stack size of each wasm thread */
#define WASM_THREAD_AUX_STACK_SIZE_MIN (256)

/* Default/min native stack size of each app thread */
#if !(defined(APP_THREAD_STACK_SIZE_DEFAULT) \
      && defined(APP_THREAD_STACK_SIZE_MIN))
#if defined(BH_PLATFORM_ZEPHYR) || defined(BH_PLATFORM_ALIOS_THINGS) \
    || defined(BH_PLATFORM_ESP_IDF) || defined(BH_PLATFORM_OPENRTOS)
#define APP_THREAD_STACK_SIZE_DEFAULT (6 * 1024)
#define APP_THREAD_STACK_SIZE_MIN (4 * 1024)
#elif defined(PTHREAD_STACK_DEFAULT) && defined(PTHREAD_STACK_MIN)
#define APP_THREAD_STACK_SIZE_DEFAULT PTHREAD_STACK_DEFAULT
#define APP_THREAD_STACK_SIZE_MIN PTHREAD_STACK_MIN
#elif WASM_ENABLE_UVWASI != 0
/* UVWASI requires larger native stack */
#define APP_THREAD_STACK_SIZE_DEFAULT (64 * 1024)
#define APP_THREAD_STACK_SIZE_MIN (48 * 1024)
#else
#define APP_THREAD_STACK_SIZE_DEFAULT (32 * 1024)
#define APP_THREAD_STACK_SIZE_MIN (24 * 1024)
#endif
#endif /* end of !(defined(APP_THREAD_STACK_SIZE_DEFAULT) \
                   && defined(APP_THREAD_STACK_SIZE_MIN)) */

/* Max native stack size of each app thread */
#if !defined(APP_THREAD_STACK_SIZE_MAX)
#define APP_THREAD_STACK_SIZE_MAX (8 * 1024 * 1024)
#endif

/* Reserved bytes to the native thread stack boundary, throw native
   stack overflow exception if the guard boudary is reached */
#ifndef WASM_STACK_GUARD_SIZE
#if WASM_ENABLE_UVWASI != 0
/* UVWASI requires larger native stack */
#define WASM_STACK_GUARD_SIZE (4096 * 6)
#else
#define WASM_STACK_GUARD_SIZE (1024)
#endif
#endif

/* Guard page count for stack overflow check with hardware trap */
#ifndef STACK_OVERFLOW_CHECK_GUARD_PAGE_COUNT
#define STACK_OVERFLOW_CHECK_GUARD_PAGE_COUNT 3
#endif

/* Default wasm block address cache size and conflict list size */
#ifndef BLOCK_ADDR_CACHE_SIZE
#define BLOCK_ADDR_CACHE_SIZE 64
#endif
#define BLOCK_ADDR_CONFLICT_SIZE 2

/* Default max thread num per cluster. Can be overwrite by
    wasm_runtime_set_max_thread_num */
#define CLUSTER_MAX_THREAD_NUM 4

#ifndef WASM_ENABLE_TAIL_CALL
#define WASM_ENABLE_TAIL_CALL 0
#endif

#ifndef WASM_ENABLE_CUSTOM_NAME_SECTION
#define WASM_ENABLE_CUSTOM_NAME_SECTION 0
#endif

#ifndef WASM_ENABLE_REF_TYPES
#define WASM_ENABLE_REF_TYPES 0
#endif

#ifndef WASM_ENABLE_SGX_IPFS
#define WASM_ENABLE_SGX_IPFS 0
#endif

#endif /* end of _CONFIG_H_ */
