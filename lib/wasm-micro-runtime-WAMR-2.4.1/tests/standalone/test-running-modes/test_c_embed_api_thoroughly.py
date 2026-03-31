#!python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#


import os
from collections import OrderedDict


def CLI_ARGS_GENERATOR(running_modes_supported: list[str]) -> list[str]:
    res = []
    list_2d = [["--default-running-mode={} --module-running-mode={}".format(i, j)
                for i in running_modes_supported] for j in running_modes_supported]
    for list_1d in list_2d:
        res.extend(list_1d)
    return res


def main():
    RUNNING_MODES: list[str] = [
        "interp",
        "fast-jit",
        "llvm-jit",
        "multi-tier-jit",
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
        "INTERP": {"compile_flag": COMPILE_FLAGS[0], "cli_args": CLI_ARGS_GENERATOR(RUNNING_MODES[:1])},
        "FAST_JIT": {"compile_flag": COMPILE_FLAGS[1], "cli_args": CLI_ARGS_GENERATOR(RUNNING_MODES[:2])},
        "LLVM_JIT": {"compile_flag": COMPILE_FLAGS[2],
                     "cli_args": CLI_ARGS_GENERATOR([RUNNING_MODES[0], RUNNING_MODES[2]])},
        "MULTI_TIER_JIT": {"compile_flag": COMPILE_FLAGS[3], "cli_args": CLI_ARGS_GENERATOR(RUNNING_MODES)},
        "EAGER_JIT_WITH_BOTH_JIT": {"compile_flag": COMPILE_FLAGS[4],
                                    "cli_args": CLI_ARGS_GENERATOR(RUNNING_MODES[:3])}
    })

    build_cmd = "./build_c_embed.sh \"{build_flag}\""
    run_cmd = "cd c-embed/build && ./c_embed_test {cli_args}"

    for compile_mode in test_options.keys():
        build_flag: str = test_options[compile_mode]["compile_flag"]
        cli_args_li: list = test_options[compile_mode]["cli_args"]
        # compile
        print("\r\n\r\nCompile C program embed WAMR in {} mode".format(compile_mode))
        ret = os.system(build_cmd.format(build_flag=build_flag))
        if ret:
            print("Compile failed")
        # iter over cli args combination
        for cli_args in cli_args_li:
            print(run_cmd.format(cli_args=cli_args))
            ret = os.system(run_cmd.format(cli_args=cli_args))
        if ret:
            break
        else:  # if inner for loop finish normally
            continue

        # if break from inner for loop
        print("Run failed")
        break


if __name__ == '__main__':
    main()
