#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
import ctypes
from wamr import *


def hello_callback():
    print("Calling back...")
    print("> Hello World!")


def main():
    print("Initializing...")
    engine = Engine()
    store = Store(engine)

    print("Loading binary...")
    print("Compiling module...")
    module = Module.from_file(engine, "./hello.wasm")

    print("Creating callback...")
    hello = Func(store, FuncType([], []), hello_callback)

    print("Instantiating module...")
    instance = Instance(store, module, [hello])

    print("Extracting export...")
    run = instance.exports(store)["run"]

    print("Calling export...")
    run(store)

    print("Shutting down...")
    print("Done.")


if __name__ == "__main__":
    main()
