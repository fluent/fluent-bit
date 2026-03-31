# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

from wamr.wamrapi.wamr import Engine, Module, Instance, ExecEnv
from ctypes import c_uint
import pathlib
from ctypes import c_int32
from ctypes import c_uint
from ctypes import c_void_p
from ctypes import cast
from ctypes import CFUNCTYPE

from wamr.wamrapi.iwasm import NativeSymbol
from wamr.wamrapi.iwasm import String
from wamr.wamrapi.wamr import ExecEnv

def python_func(env: int, value: int) -> int:
    print("python: in python_func with input:", value)
    # Example of generating ExecEnv from `wasm_exec_env_t``
    exec_env = ExecEnv.wrap(env)
    add = exec_env.get_module_inst().lookup_function("add")
    const = 1000
    argv = (c_uint * 2)(value, const)
    print(f"python: calling add({value}, {const})")
    exec_env.call(add, 2, argv)
    res = argv[0]
    print("python: result from add:", res)
    return res + 1


native_symbols = (NativeSymbol * 1)(
    *[
        NativeSymbol(
            symbol=String.from_param("python_func"),
            func_ptr=cast(
                CFUNCTYPE(c_int32, c_void_p, c_int32)(python_func), c_void_p
            ),
            signature=String.from_param("(i)i"),
        )
    ]
)

def main():
    engine = Engine()
    engine.register_natives("env", native_symbols)
    module = Module.from_file(engine, pathlib.Path(__file__).parent / "func.wasm")
    module_inst = Instance(module)
    exec_env = ExecEnv(module_inst)

    func = module_inst.lookup_function("c_func")

    inp = 10
    print(f"python: calling c_func({inp})")
    argv = (c_uint)(inp)
    exec_env.call(func, 1, argv)
    print("python: result from c_func:", argv.value)

if __name__ == "__main__":
    main()
