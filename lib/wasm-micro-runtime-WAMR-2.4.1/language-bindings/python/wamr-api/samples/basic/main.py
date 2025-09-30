# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

from wamr.wamrapi.wamr import Engine, Module, Instance, ExecEnv
from ctypes import c_uint
import pathlib

def main():
    engine = Engine()
    module = Module.from_file(engine, pathlib.Path(__file__).parent / "sum.wasm")
    module_inst = Instance(module)
    exec_env = ExecEnv(module_inst)

    func = module_inst.lookup_function("sum")

    argv = (c_uint * 2)(*[10, 11])
    exec_env.call(func, len(argv), argv)
    print(argv[0])


if __name__ == "__main__":
    main()
