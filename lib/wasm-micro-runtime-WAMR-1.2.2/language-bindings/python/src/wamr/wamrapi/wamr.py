# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

from ctypes import Array
from ctypes import c_char
from ctypes import c_uint
from ctypes import c_uint8
from ctypes import c_void_p
from ctypes import cast
from ctypes import create_string_buffer
from ctypes import POINTER
from ctypes import pointer
from wamr.wamrapi.iwasm import String
from wamr.wamrapi.iwasm import Alloc_With_Pool
from wamr.wamrapi.iwasm import RuntimeInitArgs
from wamr.wamrapi.iwasm import wasm_exec_env_t
from wamr.wamrapi.iwasm import wasm_function_inst_t
from wamr.wamrapi.iwasm import wasm_module_inst_t
from wamr.wamrapi.iwasm import wasm_module_t
from wamr.wamrapi.iwasm import wasm_runtime_call_wasm
from wamr.wamrapi.iwasm import wasm_runtime_create_exec_env
from wamr.wamrapi.iwasm import wasm_runtime_deinstantiate
from wamr.wamrapi.iwasm import wasm_runtime_destroy
from wamr.wamrapi.iwasm import wasm_runtime_destroy_exec_env
from wamr.wamrapi.iwasm import wasm_runtime_full_init
from wamr.wamrapi.iwasm import wasm_runtime_instantiate
from wamr.wamrapi.iwasm import wasm_runtime_load
from wamr.wamrapi.iwasm import wasm_runtime_lookup_function
from wamr.wamrapi.iwasm import wasm_runtime_unload
from wamr.wamrapi.iwasm import wasm_runtime_module_malloc
from wamr.wamrapi.iwasm import wasm_runtime_module_free
from wamr.wamrapi.iwasm import wasm_runtime_register_natives
from wamr.wamrapi.iwasm import NativeSymbol


class Engine:
    def __init__(self):
        self._native_symbols = dict()
        self.init_args = self._get_init_args()
        wasm_runtime_full_init(pointer(self.init_args))

    def __del__(self):
        print("deleting Engine")
        wasm_runtime_destroy()

    def _get_init_args(self, heap_size: int = 1024 * 512) -> RuntimeInitArgs:
        init_args = RuntimeInitArgs()
        init_args.mem_alloc_type = Alloc_With_Pool
        init_args.mem_alloc_option.pool.heap_buf = cast(
            (c_char * heap_size)(), c_void_p
        )
        init_args.mem_alloc_option.pool.heap_size = heap_size
        return init_args

    def register_natives(self, module_name: str, native_symbols: list[NativeSymbol]) -> None:
        module_name = String.from_param(module_name)
        # WAMR does not copy the symbols. We must store them.
        for native in native_symbols:
            self._native_symbols[str(native.symbol)] = (module_name, native)

        if not wasm_runtime_register_natives(
            module_name,
            cast(
                (NativeSymbol * len(native_symbols))(*native_symbols),
                POINTER(NativeSymbol)
            ),
            len(native_symbols)
        ):
            raise Exception("Error while registering symbols")

class Module:
    __create_key = object()

    @classmethod
    def from_file(cls, engine: Engine, fp: str) -> "Module":
        return Module(cls.__create_key, engine, fp)

    def __init__(self, create_key: object, engine: Engine, fp: str) -> None:
        assert (
            create_key == Module.__create_key
        ), "Module objects must be created using Module.from_file"
        self.engine = engine
        self.module, self.file_data = self._create_module(fp)

    def __del__(self):
        print("deleting Module")
        wasm_runtime_unload(self.module)

    def _create_module(self, fp: str) -> tuple[wasm_module_t, Array[c_uint]]:
        with open(fp, "rb") as f:
            data = f.read()
            data = (c_uint8 * len(data))(*data)

        error_buf = create_string_buffer(128)
        module = wasm_runtime_load(data, len(data), error_buf, len(error_buf))
        if not module:
            raise Exception("Error while creating module")
        return module, data


class Instance:
    def __init__(self, module: Module, stack_size: int = 65536, heap_size: int = 16384):
        self.module = module
        self.module_inst = self._create_module_inst(module, stack_size, heap_size)

    def __del__(self):
        print("deleting Instance")
        wasm_runtime_deinstantiate(self.module_inst)

    def malloc(self, nbytes: int, native_handler) -> c_uint:
        return wasm_runtime_module_malloc(self.module_inst, nbytes, native_handler)

    def free(self, wasm_handler) -> None:
        wasm_runtime_module_free(self.module_inst, wasm_handler)

    def lookup_function(self, name: str) -> wasm_function_inst_t:
        func = wasm_runtime_lookup_function(self.module_inst, name, None)
        if not func:
            raise Exception("Error while looking-up function")
        return func

    def _create_module_inst(self, module: Module, stack_size: int, heap_size: int) -> wasm_module_inst_t:
        error_buf = create_string_buffer(128)
        module_inst = wasm_runtime_instantiate(
            module.module, stack_size, heap_size, error_buf, len(error_buf)
        )
        if not module_inst:
            raise Exception("Error while creating module instance")
        return module_inst


class ExecEnv:
    def __init__(self, module_inst: Instance, stack_size: int = 65536):
        self.module_inst = module_inst
        self.exec_env = self._create_exec_env(module_inst, stack_size)

    def __del__(self):
        print("deleting ExecEnv")
        wasm_runtime_destroy_exec_env(self.exec_env)

    def call(self, func: wasm_function_inst_t, argc: int, argv: "POINTER[c_uint]"):
        if not wasm_runtime_call_wasm(self.exec_env, func, argc, argv):
            raise Exception("Error while calling function")

    def _create_exec_env(self, module_inst: Instance, stack_size: int) -> wasm_exec_env_t:
        exec_env = wasm_runtime_create_exec_env(module_inst.module_inst, stack_size)
        if not exec_env:
            raise Exception("Error while creating execution environment")
        return exec_env
