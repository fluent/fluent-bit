# -*- coding: utf-8 -*-
#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
import ctypes
import wamr.wasmcapi.ffi as ffi

WAMS_BINARY_CONTENT = (
    b"\x00asm\x01\x00\x00\x00\x01\x84\x80\x80\x80\x00\x01`\x00\x00\x02\x8a\x80"
    b"\x80\x80\x00\x01\x00\x05hello\x00\x00\x03\x82\x80\x80\x80\x00\x01\x00"
    b"\x07\x87\x80\x80\x80\x00\x01\x03run\x00\x01\n\x8a\x80\x80\x80\x00\x01"
    b"\x84\x80\x80\x80\x00\x00\x10\x00\x0b"
)


@ffi.wasm_func_cb_decl
def hello_callback(args, results):
    print("Calling back...")
    print("> Hello World!")


def main():
    print("Initializing...")
    engine = ffi.wasm_engine_new()
    store = ffi.wasm_store_new(engine)

    print("Loading binary...")

    # for convenience, use binary content instead of open file
    # with open("./hello.wasm", "rb") as f:
    #     wasm = f.read()
    wasm = WAMS_BINARY_CONTENT
    binary = ffi.wasm_byte_vec_t()
    ffi.wasm_byte_vec_new_uninitialized(binary, len(wasm))
    # underlying buffer is not writable
    binary.data = (ctypes.c_ubyte * len(wasm)).from_buffer_copy(wasm)

    print("Compiling module...")
    module = ffi.wasm_module_new(store, binary)
    if not module:
        raise RuntimeError("Compiling module failed")

    binary.data = None
    ffi.wasm_byte_vec_delete(binary)

    print("Creating callback...")
    hello_type = ffi.wasm_functype_new_0_0()
    hello_func = ffi.wasm_func_new(
        store,
        hello_type,
        hello_callback,
    )

    ffi.wasm_functype_delete(hello_type)

    print("Instantiating module...")

    imports = ffi.wasm_extern_vec_t()
    ffi.wasm_extern_vec_new((imports), 1, ffi.wasm_func_as_extern(hello_func))
    instance = ffi.wasm_instance_new(store, module, imports, None)

    ffi.wasm_func_delete(hello_func)

    print("Extracting export...")
    exports = ffi.wasm_extern_vec_t()
    ffi.wasm_instance_exports(instance, exports)

    run_func = ffi.wasm_extern_as_func(exports.data[0])
    if not run_func:
        raise RuntimeError("can not extract exported function")

    ffi.wasm_instance_delete(instance)
    ffi.wasm_module_delete(module)

    print("Calling export...")
    args = ffi.wasm_val_vec_t()
    results = ffi.wasm_val_vec_t()

    ffi.wasm_val_vec_new_empty(args)
    ffi.wasm_val_vec_new_empty(results)
    ffi.wasm_func_call(run_func, args, results)

    print("Shutting down...")
    ffi.wasm_store_delete(store)
    ffi.wasm_engine_delete(engine)

    print("Done.")


if __name__ == "__main__":
    main()
