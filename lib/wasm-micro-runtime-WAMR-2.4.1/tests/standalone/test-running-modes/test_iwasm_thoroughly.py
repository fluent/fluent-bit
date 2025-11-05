#!python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import os
from collections import OrderedDict


def main():
    IWASM_CMD = "../../../wamr/product-mini/platforms/linux/build/iwasm"

    IWASM_CLI_ARGS: list[str] = [
        "--heap-size=16384 --interp",
        "--heap-size=16384 --fast-jit",
        "--heap-size=16384 --llvm-jit",
        "--heap-size=16384 --multi-tier-jit",
        "--heap-size=16384 --llvm-jit --llvm-jit-size-level=1",
        "--heap-size=16384 --llvm-jit --llvm-jit-size-level=2 --llvm-jit-opt-level=1"
    ]

    COMPILE_FLAGS: list[str] = [
        "-DWAMR_BUILD_FAST_INTERP=0 -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_JIT=0 -DWAMR_BUILD_JIT=0",
        "-DWAMR_BUILD_FAST_JIT=1",
        "-DWAMR_BUILD_FAST_JIT=0 -DWAMR_BUILD_JIT=1",
        "-DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_LAZY_JIT=1",
        "-DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_LAZY_JIT=0",
    ]

    # Python 3.7+: Dictionary iteration order is guaranteed to be in order of insertion.
    # just to be safe, using OrderedDict
    # key: value -> compile mode, {"compile_flag": CMake compile flag, "iwasm_cli_args": array of CLI args tested}
    test_options = OrderedDict({
        "INTERP": {"compile_flag": COMPILE_FLAGS[0], "iwasm_cli_args": IWASM_CLI_ARGS[:1]},
        "FAST_JIT": {"compile_flag": COMPILE_FLAGS[1], "iwasm_cli_args": IWASM_CLI_ARGS[:2]},
        "LLVM_JIT": {"compile_flag": COMPILE_FLAGS[2], "iwasm_cli_args": [IWASM_CLI_ARGS[0], IWASM_CLI_ARGS[2]]},
        "MULTI_TIER_JIT": {"compile_flag": COMPILE_FLAGS[3], "iwasm_cli_args": IWASM_CLI_ARGS},
        "EAGER_JIT_WITH_BOTH_JIT": {"compile_flag": COMPILE_FLAGS[4],
                                    "iwasm_cli_args": IWASM_CLI_ARGS[:3] + IWASM_CLI_ARGS[4:]}
    })

    build_cmd = "./build_iwasm.sh \"{build_flag}\""
    wasm_file = "wasm-apps/mytest.wasm"
    run_cmd = "{IWASM_CMD} {cli_args} " + wasm_file

    for compile_mode in test_options.keys():
        build_flag: str = test_options[compile_mode]["compile_flag"]
        cli_args_li: list = test_options[compile_mode]["iwasm_cli_args"]
        # compile
        print("\r\n\r\nCompile iwasm in {} mode".format(compile_mode))
        ret = os.system(build_cmd.format(build_flag=build_flag))
        if ret:
            print("Compile failed")
        # iter over cli args combination
        for cli_args in cli_args_li:
            print(run_cmd.format(IWASM_CMD=IWASM_CMD, cli_args=cli_args))
            ret = os.system(run_cmd.format(
                IWASM_CMD=IWASM_CMD, cli_args=cli_args))
            if ret:
                break
        else:  # if inner for loop finish normally
            continue

        # if break from inner for loop
        print("Run failed")
        break


if __name__ == '__main__':
    main()
