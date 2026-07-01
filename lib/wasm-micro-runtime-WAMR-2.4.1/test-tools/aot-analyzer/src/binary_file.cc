/*
 * Copyright (C) 2024 Xiaomi Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "binary_file.h"

#include <cctype>
#include <cstring>

#include "analyzer_error.h"

#if HAVE_ALLOCA
#include <alloca.h>
#endif

namespace analyzer {

BinaryFile::BinaryFile(const char *file_name)
  : file_name_(file_name)
  , file_data_(NULL)
  , file_size_(0)
  , current_pos_(0)
  , module_(NULL)
{
    memset(&mem_conspn_, 0, sizeof(WASMModuleMemConsumption));
}

BinaryFile::~BinaryFile()
{
    if (module_) {
        wasm_runtime_unload(module_);
        wasm_runtime_free(file_data_);
        wasm_runtime_destroy();
    }
}

Result
BinaryFile::ReadModule()
{
    char error_buf[128];

#if WASM_ENABLE_GC != 0
    uint32_t gc_heap_size = GC_HEAP_SIZE_DEFAULT;
#endif

    uint32_t buf_size, stack_size = DEFAULT_WASM_STACK_SIZE,
                       heap_size = GC_HEAP_SIZE_DEFAULT;

    RuntimeInitArgs init_args;
    memset(&init_args, 0, sizeof(RuntimeInitArgs));

#if WASM_ENABLE_GLOBAL_HEAP_POOL != 0
    static char global_heap_buf[WASM_GLOBAL_HEAP_SIZE] = { 0 };
    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = global_heap_buf;
    init_args.mem_alloc_option.pool.heap_size = sizeof(global_heap_buf);
#else
    init_args.mem_alloc_type = Alloc_With_Allocator;
    init_args.mem_alloc_option.allocator.malloc_func = (void *)malloc;
    init_args.mem_alloc_option.allocator.realloc_func = (void *)realloc;
    init_args.mem_alloc_option.allocator.free_func = (void *)free;
#endif

    /* initialize runtime environment */
    if (!wasm_runtime_full_init(&init_args)) {
        printf("Init runtime environment failed.\n");
        return Result::Error;
    }

    file_data_ = (uint8 *)bh_read_file_to_buffer(file_name_, &file_size_);
    if (!file_data_) {
        printf("Open Binary file [%s] failed.\n", file_name_);
        wasm_runtime_destroy();
        return Result::Error;
    }

    module_ =
        wasm_runtime_load(file_data_, file_size_, error_buf, sizeof(error_buf));
    if (!module_) {
        printf("Load Binary module failed. error: %s\n", error_buf);
        wasm_runtime_free(file_data_);
        wasm_runtime_destroy();
        return Result::Error;
    }
    return Result::Ok;
}

Result
BinaryFile::Scan()
{
    return Result::Ok;
}

void ANALYZER_PRINTF_FORMAT(2, 3) BinaryFile::PrintError(const char *format,
                                                         ...)
{
    ErrorLevel error_level = ErrorLevel::Error;
    ANALYZER_SNPRINTF_ALLOCA(buffer, length, format);
    Error error(error_level, buffer);
    fprintf(stderr, "%07" PRIzx ": %s: %s\n", current_pos_,
            GetErrorLevelName(error_level), buffer);
}

Result
BinaryFile::UpdateCurrentPos(uint32_t steps)
{
    if (current_pos_ + steps > file_size_) {
        return Result::Error;
    }
    current_pos_ += steps;
    return Result::Ok;
}

} // namespace analyzer
