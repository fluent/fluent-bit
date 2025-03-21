/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

package wamr

/*
#include <stdlib.h>
#include <wasm_export.h>

static inline void
PUT_I64_TO_ADDR(uint32_t *addr, int64_t value)
{
    union {
        int64_t val;
        uint32_t parts[2];
    } u;
    u.val = value;
    addr[0] = u.parts[0];
    addr[1] = u.parts[1];
}

static inline void
PUT_F64_TO_ADDR(uint32_t *addr, double value)
{
    union {
        double val;
        uint32_t parts[2];
    } u;
    u.val = value;
    addr[0] = u.parts[0];
    addr[1] = u.parts[1];
}

static inline int64_t
GET_I64_FROM_ADDR(uint32_t *addr)
{
    union {
        int64_t val;
        uint32_t parts[2];
    } u;
    u.parts[0] = addr[0];
    u.parts[1] = addr[1];
    return u.val;
}

static inline double
GET_F64_FROM_ADDR(uint32_t *addr)
{
    union {
        double val;
        uint32_t parts[2];
    } u;
    u.parts[0] = addr[0];
    u.parts[1] = addr[1];
    return u.val;
}
*/
import "C"

import (
    "runtime"
    "unsafe"
    "fmt"
)

type Instance struct {
    _instance C.wasm_module_inst_t
    _exec_env C.wasm_exec_env_t
    _module *Module
    _exportsCache map[string]C.wasm_function_inst_t
}

/* Create instance from the module */
func NewInstance(module *Module,
                 stackSize uint, heapSize uint) (*Instance, error) {
    if (module == nil) {
        return nil, fmt.Errorf("NewInstance error: invalid input")
    }

    errorBytes := make([]byte, 128)
    errorPtr := (*C.char)(unsafe.Pointer(&errorBytes[0]))
    errorLen := C.uint(len(errorBytes))

    instance := C.wasm_runtime_instantiate(module.module, C.uint(stackSize),
                                           C.uint(heapSize), errorPtr, errorLen)
    if (instance == nil) {
        return nil, fmt.Errorf("NewInstance Error: %s", string(errorBytes))
    }

    exec_env := C.wasm_runtime_create_exec_env(instance, C.uint(stackSize))
    if (exec_env == nil) {
        C.wasm_runtime_deinstantiate(instance)
        return nil, fmt.Errorf("NewInstance Error: create exec_env failed")
    }

    self := &Instance{
        _instance: instance,
        _exec_env: exec_env,
        _module: module,
        _exportsCache: make(map[string]C.wasm_function_inst_t),
    }

    runtime.SetFinalizer(self, func(self *Instance) {
        self.Destroy()
    })

    return self, nil
}

/* Destroy the instance */
func (self *Instance) Destroy() {
    runtime.SetFinalizer(self, nil)
    if (self._instance != nil) {
        C.wasm_runtime_deinstantiate(self._instance)
    }
    if (self._exec_env != nil) {
        C.wasm_runtime_destroy_exec_env(self._exec_env)
    }
}

/* Call the wasm function with argument in the uint32 array, and store
   the return values back into the array */
func (self *Instance) CallFunc(funcName string,
                               argc uint32, args []uint32) error {
    _func := self._exportsCache[funcName]
    if _func == nil {
        cName := C.CString(funcName)
        defer C.free(unsafe.Pointer(cName))

        _func = C.wasm_runtime_lookup_function(self._instance,
                                               cName, (*C.char)(C.NULL))
        if _func == nil {
            return fmt.Errorf("CallFunc error: lookup function failed")
        }
        self._exportsCache[funcName] = _func
    }

    thread_env_inited := Runtime().ThreadEnvInited()
    if (!thread_env_inited) {
        Runtime().InitThreadEnv()
    }

    var args_C *C.uint32_t
    if (argc > 0) {
        args_C = (*C.uint32_t)(unsafe.Pointer(&args[0]))
    }
    if (!C.wasm_runtime_call_wasm(self._exec_env, _func,
                                  C.uint(argc), args_C)) {
        if (!thread_env_inited) {
            Runtime().DestroyThreadEnv()
        }
        return fmt.Errorf("CallFunc error: %s", string(self.GetException()))
    }

    if (!thread_env_inited) {
        Runtime().DestroyThreadEnv()
    }
    return nil
}

/* Call the wasm function with variant arguments, and store the return
   values back into the results array */
func (self *Instance) CallFuncV(funcName string,
                                num_results uint32, results []interface{},
                                args ... interface{}) error {
    _func := self._exportsCache[funcName]
    if _func == nil {
        cName := C.CString(funcName)
        defer C.free(unsafe.Pointer(cName))

        _func = C.wasm_runtime_lookup_function(self._instance,
                                               cName, (*C.char)(C.NULL))
        if _func == nil {
            return fmt.Errorf("CallFunc error: lookup function failed")
        }
        self._exportsCache[funcName] = _func
    }

    param_count := uint32(C.wasm_func_get_param_count(_func, self._instance))
    result_count := uint32(C.wasm_func_get_result_count(_func, self._instance))

    if (num_results < result_count) {
        str := "CallFunc error: invalid result count %d, " +
               "must be no smaller than %d"
        return fmt.Errorf(str, num_results, result_count)
    }

    param_types := make([]C.uchar, param_count, param_count)
    result_types := make([]C.uchar, result_count, result_count)
    if (param_count > 0) {
        C.wasm_func_get_param_types(_func, self._instance,
                                    (*C.uchar)(unsafe.Pointer(&param_types[0])))
    }
    if (result_count > 0) {
        C.wasm_func_get_result_types(_func, self._instance,
                                     (*C.uchar)(unsafe.Pointer(&result_types[0])))
    }

    argv_size := param_count * 2
    if (result_count > param_count) {
        argv_size = result_count * 2
    }
    argv := make([]uint32, argv_size, argv_size)

    var i, argc uint32
    for _, arg := range args {
        if (i >= param_count) {
            break;
        }
        switch arg.(type) {
            case int32:
                if (param_types[i] != C.WASM_I32 &&
                    param_types[i] != C.WASM_FUNCREF &&
                    param_types[i] != C.WASM_ANYREF) {
                    str := "CallFunc error: invalid param type %d, " +
                           "expect i32 but got other"
                    return fmt.Errorf(str, param_types[i])
                }
                argv[argc] = (uint32)(arg.(int32))
                argc++
                break
            case int64:
                if (param_types[i] != C.WASM_I64) {
                    str := "CallFunc error: invalid param type %d, " +
                           "expect i64 but got other"
                    return fmt.Errorf(str, param_types[i])
                }
                addr := (*C.uint32_t)(unsafe.Pointer(&argv[argc]))
                C.PUT_I64_TO_ADDR(addr, (C.int64_t)(arg.(int64)))
                argc += 2
                break
            case float32:
                if (param_types[i] != C.WASM_F32) {
                    str := "CallFunc error: invalid param type %d, " +
                           "expect f32 but got other"
                    return fmt.Errorf(str, param_types[i])
                }
                *(*C.float)(unsafe.Pointer(&argv[argc])) = (C.float)(arg.(float32))
                argc++
                break
            case float64:
                if (param_types[i] != C.WASM_F64) {
                    str := "CallFunc error: invalid param type %d, " +
                           "expect f64 but got other"
                    return fmt.Errorf(str, param_types[i])
                }
                addr := (*C.uint32_t)(unsafe.Pointer(&argv[argc]))
                C.PUT_F64_TO_ADDR(addr, (C.double)(arg.(float64)))
                argc += 2
                break
            default:
                return fmt.Errorf("CallFunc error: unknown param type %d",
                                  param_types[i])
        }
        i++
    }

    if (i < param_count) {
        str := "CallFunc error: invalid param count, " +
               "must be no smaller than %d"
        return fmt.Errorf(str, param_count)
    }

    err := self.CallFunc(funcName, argc, argv)
    if (err != nil) {
        return err
    }

    argc = 0
    for i = 0; i < result_count; i++ {
        switch result_types[i] {
            case C.WASM_I32:
                fallthrough
            case C.WASM_FUNCREF:
                fallthrough
            case C.WASM_ANYREF:
                i32 := (int32)(argv[argc])
                results[i] = i32
                argc++
                break
            case C.WASM_I64:
                addr := (*C.uint32_t)(unsafe.Pointer(&argv[argc]))
                results[i] = (int64)(C.GET_I64_FROM_ADDR(addr))
                argc += 2
                break
            case C.WASM_F32:
                addr := (*C.float)(unsafe.Pointer(&argv[argc]))
                results[i] = (float32)(*addr)
                argc++
                break
            case C.WASM_F64:
                addr := (*C.uint32_t)(unsafe.Pointer(&argv[argc]))
                results[i] = (float64)(C.GET_F64_FROM_ADDR(addr))
                argc += 2
                break
        }
    }

    return nil
}

/* Get exception info of the instance */
func (self *Instance) GetException() string {
    cStr := C.wasm_runtime_get_exception(self._instance)
    goStr := C.GoString(cStr)
    return goStr
}

/* Allocate memory from the heap of the instance */
func (self Instance) ModuleMalloc(size uint32) (uint32, *uint8) {
    var offset C.uint32_t
    native_addrs := make([]*uint8, 1, 1)
    ptr := unsafe.Pointer(&native_addrs[0])
    offset = C.wasm_runtime_module_malloc(self._instance, (C.uint32_t)(size),
                                          (*unsafe.Pointer)(ptr))
    return (uint32)(offset), native_addrs[0]
}

/* Free memory to the heap of the instance */
func (self Instance) ModuleFree(offset uint32) {
    C.wasm_runtime_module_free(self._instance, (C.uint32_t)(offset))
}

func (self Instance) ValidateAppAddr(app_offset uint32, size uint32) bool {
    ret := C.wasm_runtime_validate_app_addr(self._instance,
                                            (C.uint32_t)(app_offset),
                                            (C.uint32_t)(size))
    return (bool)(ret)
}

func (self Instance) ValidateStrAddr(app_str_offset uint32) bool {
    ret := C.wasm_runtime_validate_app_str_addr(self._instance,
                                                (C.uint32_t)(app_str_offset))
    return (bool)(ret)
}

func (self Instance) ValidateNativeAddr(native_ptr *uint8, size uint32) bool {
    native_ptr_C := (unsafe.Pointer)(native_ptr)
    ret := C.wasm_runtime_validate_native_addr(self._instance,
                                               native_ptr_C,
                                               (C.uint32_t)(size))
    return (bool)(ret)
}

func (self Instance) AddrAppToNative(app_offset uint32) *uint8 {
    native_ptr := C.wasm_runtime_addr_app_to_native(self._instance,
                                                    (C.uint32_t)(app_offset))
    return (*uint8)(native_ptr)
}

func (self Instance) AddrNativeToApp(native_ptr *uint8) uint32 {
    native_ptr_C := (unsafe.Pointer)(native_ptr)
    offset := C.wasm_runtime_addr_native_to_app(self._instance,
                                                native_ptr_C)
    return (uint32)(offset)
}

func (self Instance) GetAppAddrRange(app_offset uint32) (bool,
                                                         uint32,
                                                         uint32) {
    var start_offset, end_offset C.uint32_t
    ret := C.wasm_runtime_get_app_addr_range(self._instance,
                                             (C.uint32_t)(app_offset),
                                             &start_offset, &end_offset)
    return (bool)(ret), (uint32)(start_offset), (uint32)(end_offset)
}

func (self Instance) GetNativeAddrRange(native_ptr *uint8) (bool,
                                                            *uint8,
                                                            *uint8) {
    var start_addr, end_addr *C.uint8_t
    native_ptr_C := (*C.uint8_t)((unsafe.Pointer)(native_ptr))
    ret := C.wasm_runtime_get_native_addr_range(self._instance,
                                                native_ptr_C,
                                                &start_addr, &end_addr)
    return (bool)(ret), (*uint8)(start_addr), (*uint8)(end_addr)
}

func (self Instance) DumpMemoryConsumption() {
    C.wasm_runtime_dump_mem_consumption(self._exec_env)
}

func (self Instance) DumpCallStack() {
    C.wasm_runtime_dump_call_stack(self._exec_env)
}
