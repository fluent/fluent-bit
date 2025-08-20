/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

package wamr

// #include <wasm_export.h>
import "C"
import (
    "unsafe"
    "runtime"
    "fmt"
)

type Module struct {
    module C.wasm_module_t
}

/* Create WASM/AOT module from the memory buffer */
func NewModule(wasmBytes []byte) (*Module, error) {
    if (wasmBytes == nil || len(wasmBytes) == 0) {
        return nil, fmt.Errorf("NewModule error: invalid input")
    }

    wasmPtr := (*C.uint8_t)(unsafe.Pointer(&wasmBytes[0]))
    wasmLen := C.uint(len(wasmBytes))

    errorBytes := make([]byte, 128)
    errorPtr := (*C.char)(unsafe.Pointer(&errorBytes[0]))
    errorLen := C.uint(len(errorBytes))

    m := C.wasm_runtime_load(wasmPtr, wasmLen, errorPtr, errorLen)
    if (m == nil) {
        return nil, fmt.Errorf("NewModule error: %s", string(errorBytes))
    }

    self := &Module{
        module: m,
    }

    runtime.SetFinalizer(self, func(self *Module) {
        self.Destroy()
    })

    return self, nil
}

/* Destroy the module */
func (self *Module) Destroy() {
    runtime.SetFinalizer(self, nil)
    if (self.module != nil) {
        C.wasm_runtime_unload(self.module)
    }
}

/* Set module's wasi arguments */
func (self *Module) SetWasiArgs(dirList [][]byte, mapDirList [][]byte,
                                env [][]byte, argv[][]byte) {
    var dirPtr, mapDirPtr, envPtr, argvPtr **C.char
    var dirCount, mapDirCount, envCount C.uint
    var argc C.int

    if (dirList != nil) {
        dirPtr = (**C.char)(unsafe.Pointer(&dirList[0]))
        dirCount = C.uint(len(dirList))
    }

    if (mapDirList != nil) {
        mapDirPtr = (**C.char)(unsafe.Pointer(&mapDirList[0]))
        mapDirCount = C.uint(len(mapDirList))
    }

    if (env != nil) {
        envPtr = (**C.char)(unsafe.Pointer(&env[0]))
        envCount = C.uint(len(env))
    }

    if (argv != nil) {
        argvPtr = (**C.char)(unsafe.Pointer(&argv[0]))
        argc = C.int(len(argv))
    }

    C.wasm_runtime_set_wasi_args(self.module, dirPtr, dirCount,
                                 mapDirPtr, mapDirCount,
                                 envPtr, envCount, argvPtr, argc)
}

/* Set module's wasi arguments */
func (self *Module) SetWasiArgsEx(dirList [][]byte, mapDirList [][]byte,
                                env [][]byte, argv[][]byte,
                                stdinfd int, stdoutfd int, stderrfd int) {
    var dirPtr, mapDirPtr, envPtr, argvPtr **C.char
    var dirCount, mapDirCount, envCount C.uint
    var argc C.int

    if (dirList != nil) {
        dirPtr = (**C.char)(unsafe.Pointer(&dirList[0]))
        dirCount = C.uint(len(dirList))
    }

    if (mapDirList != nil) {
        mapDirPtr = (**C.char)(unsafe.Pointer(&mapDirList[0]))
        mapDirCount = C.uint(len(mapDirList))
    }

    if (env != nil) {
        envPtr = (**C.char)(unsafe.Pointer(&env[0]))
        envCount = C.uint(len(env))
    }

    if (argv != nil) {
        argvPtr = (**C.char)(unsafe.Pointer(&argv[0]))
        argc = C.int(len(argv))
    }

    C.wasm_runtime_set_wasi_args_ex(self.module, dirPtr, dirCount,
                                    mapDirPtr, mapDirCount,
                                    envPtr, envCount, argvPtr, argc,
                                    C.int64_t(stdinfd), C.int64_t(stdoutfd),
                                    C.int64_t(stderrfd))
}

/* Set module's wasi network address pool */
func (self *Module) SetWasiAddrPool(addrPool [][]byte) {
    var addrPoolPtr **C.char
    var addrPoolSize C.uint

    if (addrPool != nil) {
        addrPoolPtr = (**C.char)(unsafe.Pointer(&addrPool[0]))
        addrPoolSize = C.uint(len(addrPool))
    }
    C.wasm_runtime_set_wasi_addr_pool(self.module, addrPoolPtr, addrPoolSize)
}

/* Set module's wasi domain lookup pool */
func(self *Module) SetWasiNsLookupPool(nsLookupPool [][]byte) {
    var nsLookupPoolPtr **C.char
    var nsLookupPoolSize C.uint

    if (nsLookupPool != nil) {
        nsLookupPoolPtr = (**C.char)(unsafe.Pointer(&nsLookupPool[0]))
        nsLookupPoolSize = C.uint(len(nsLookupPool))
    }
    C.wasm_runtime_set_wasi_ns_lookup_pool(self.module, nsLookupPoolPtr, nsLookupPoolSize)
}
