#!/usr/bin/python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import os

WORK_DIR = os.getcwd()
WAMR_DIR = os.path.join(WORK_DIR, "../../../")
IWASM_DIR = os.path.join(
    WORK_DIR, "../../../product-mini/platforms/linux")


def compile_llvm():
    print("============ compile llvm =============")
    os.chdir(os.path.join(WAMR_DIR, "wamr-compiler"))
    exit_status = os.system("./build_llvm.sh")
    assert exit_status >> 8 == 0, "compile llvm failed, add -v for detail error output"
    print("============ compile llvm successful =============")


def compile_wamrc(verbose: bool):
    print("============ compile wamrc =============")
    os.chdir(os.path.join(WAMR_DIR, "wamr-compiler"))
    os.system("rm -rf build")
    os.system("mkdir build")
    exit_status = os.system(
        f"cmake -DWAMR_BUILD_GC=1 -B build {'' if verbose else '> /dev/null 2>&1'}")
    exit_status |= os.system(
        f"cmake --build build -j {os.cpu_count()} {'' if verbose else '> /dev/null 2>&1'}"
    )

    assert exit_status >> 8 == 0, "compile wamrc failed, add -v for detail error output"
    print("============ compile wamrc successful =============")


def compile_iwasm(verbose: bool):
    print("============ compile iwasm =============")
    os.chdir(IWASM_DIR)
    os.system("rm -rf build")
    os.system("mkdir build")
    exit_status = os.system(
        f"cmake -DWAMR_BUILD_AOT=1 -DWAMR_BUILD_GC=1 -DWAMR_BUILD_SPEC_TEST=1 -B build {'' if verbose else '> /dev/null 2>&1'}"
    )
    exit_status |= os.system(
        f"cmake --build build -j {os.cpu_count()} {'' if verbose else '> /dev/null 2>&1'}"
    )
    os.chdir(WORK_DIR)

    assert exit_status >> 8 == 0, "compile iwasm failed, add -v for detail error output"
    print("============ compile iwasm successful =============")


def compile_spec_interpreter():
    print("============ compile spec interpreter =============")

    os.chdir(WORK_DIR)
    exit_status = os.system("./build_spec_interpreter.sh")

    assert exit_status >> 8 == 0, "compile spec interpreter failed."
    print("============ compile spec interpreter successful =============")


def build(verbose: bool) -> None:
    compile_llvm()
    compile_wamrc(verbose)
    compile_iwasm(verbose)
    compile_spec_interpreter()
    return


if __name__ == "__main__":
    build(True)
