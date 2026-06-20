/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

package wamr

/*
#include <stdlib.h>
#include <string.h>

#include <wasm_export.h>

void
bh_log_set_verbose_level(uint32_t level);

bool
init_wamr_runtime(bool alloc_with_pool, uint8_t *heap_buf,
                  uint32_t heap_size, uint32_t max_thread_num)
{
    RuntimeInitArgs init_args;

    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    if (alloc_with_pool) {
        init_args.mem_alloc_type = Alloc_With_Pool;
        init_args.mem_alloc_option.pool.heap_buf = heap_buf;
        init_args.mem_alloc_option.pool.heap_size = heap_size;
    }
    else {
        init_args.mem_alloc_type = Alloc_With_System_Allocator;
    }

    return wasm_runtime_full_init(&init_args);
}
*/
import "C"
import (
    "fmt"
    "unsafe"
)

type LogLevel uint32
const (
    LOG_LEVEL_FATAL   LogLevel = 0
    LOG_LEVEL_ERROR   LogLevel = 1
    LOG_LEVEL_WARNING LogLevel = 2
    LOG_LEVEL_DEBUG   LogLevel = 3
    LOG_LEVEL_VERBOSE LogLevel = 4
)

/*
type NativeSymbol struct {
    symbol string
    func_ptr *uint8
    signature string
}
*/

type _Runtime struct {
    initialized bool
}

var _runtime_singleton *_Runtime

/* Return the runtime singleton */
func Runtime() *_Runtime {
    if (_runtime_singleton == nil) {
        self := &_Runtime{}
        _runtime_singleton = self
    }
    return _runtime_singleton;
}

/* Initialize the WASM runtime environment */
func (self *_Runtime) FullInit(alloc_with_pool bool, heap_buf []byte,
                               max_thread_num uint) error {
    var heap_buf_C *C.uchar

    if (self.initialized) {
        return nil
    }

    if (alloc_with_pool) {
        if (heap_buf == nil) {
            return fmt.Errorf("Failed to init WAMR runtime")
        }
        heap_buf_C = (*C.uchar)(unsafe.Pointer(&heap_buf[0]))
    }

    if (!C.init_wamr_runtime((C.bool)(alloc_with_pool), heap_buf_C,
                             (C.uint)(len(heap_buf)),
                             (C.uint)(max_thread_num))) {
        return fmt.Errorf("Failed to init WAMR runtime")
    }

    self.initialized = true
    return nil
}

/* Initialize the WASM runtime environment */
func (self *_Runtime) Init() error {
    return self.FullInit(false, nil, 1)
}

/* Destroy the WASM runtime environment */
func (self *_Runtime) Destroy() {
    if (self.initialized) {
        C.wasm_runtime_destroy()
        self.initialized = false
    }
}

/* Set log verbose level (0 to 5, default is 2),
   larger level with more log */
func (self *_Runtime) SetLogLevel(level LogLevel) {
    C.bh_log_set_verbose_level(C.uint32_t(level))
}

/*
func (self *_Runtime) RegisterNatives(moduleName string,
                                      nativeSymbols []NativeSymbol) {
}
*/ /* TODO */

func (self *_Runtime) InitThreadEnv() bool {
    if (!C.wasm_runtime_init_thread_env()) {
        return false
    }
    return true
}

func (self *_Runtime) DestroyThreadEnv() {
    C.wasm_runtime_destroy_thread_env();
}

func (self *_Runtime) ThreadEnvInited() bool {
    if (!C.wasm_runtime_thread_env_inited()) {
        return false
    }
    return true
}

/* Allocate memory from runtime memory environment */
func (self *_Runtime) Malloc(size uint32) *uint8 {
    ptr := C.wasm_runtime_malloc((C.uint32_t)(size))
    return (*uint8)(ptr)
}

/* Free memory to runtime memory environment */
func (self *_Runtime) Free(ptr *uint8) {
    C.wasm_runtime_free((unsafe.Pointer)(ptr))
}
