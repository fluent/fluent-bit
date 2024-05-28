#!/usr/bin/env python3
#
# Copyright (C) 2023 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import argparse
import time
from pathlib import Path
import subprocess, shlex

SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_ROOT_DIR = SCRIPT_DIR.parent
SAMPLE_CODE_FILE = REPO_ROOT_DIR / 'product-mini/app-samples/hello-world/main.c'
WASM_OUT_FILE = SCRIPT_DIR / 'out.wasm'

parser = argparse.ArgumentParser(
    description="Validate the customized lldb with sample code"
)
parser.add_argument(
    "-l", "--lldb", dest='lldb', default='lldb', help="path to lldb executable"
)
parser.add_argument(
    "-w", "--wamr", dest='wamr', default='iwasm', help="path to iwasm executable"
)
parser.add_argument(
    "-p", "--port", dest='port', default='1234', help="debug server listen port"
)
parser.add_argument(
    "-v", "--verbose", dest='verbose', action='store_true', default=False, help="display lldb stdout"
)

options = parser.parse_args()

lldb_command_epilogue = '-o q'

test_cases = {
    'run_to_exit': '-o c',
    'func_breakpoint': '-o "b main" -o c -o c',
    'line_breakpoint': '-o "b main.c:12" -o c -o c',
    'break_on_unknown_func': '-o "b not_a_func" -o c',
    'watch_point': '-o "b main" -o c -o "watchpoint set variable buf" -o c -o "fr v buf" -o c',
}

# Step1: Build wasm module with debug information
build_cmd = f'/opt/wasi-sdk/bin/clang -g -O0 -o {WASM_OUT_FILE} {SAMPLE_CODE_FILE}'
try:
    print(f'building wasm module ...', end='', flush=True)
    subprocess.check_call(shlex.split(build_cmd))
    print(f'\t OK')
except subprocess.CalledProcessError:
    print("Failed to build wasm module with debug information")
    exit(1)

def print_process_output(p):
    try:
        outs, errs = p.communicate(timeout=2)
        print("stdout:")
        print(outs)
        print("stderr:")
        print(errs)
    except subprocess.TimeoutExpired:
        print("Failed to get process output")

# Step2: Launch WAMR in debug mode and validate lldb commands

iteration = 0
for case, cmd in test_cases.items():
    lldb_command_prologue = f'{options.lldb} -o "process connect -p wasm connect://127.0.0.1:{int(options.port) + iteration}"'
    wamr_cmd = f'{options.wamr} -g=127.0.0.1:{int(options.port) + iteration} {WASM_OUT_FILE}'
    iteration += 1

    has_error = False
    print(f'validating case [{case}] ...', end='', flush=True)
    lldb_cmd = f'{lldb_command_prologue} {cmd} {lldb_command_epilogue}'

    wamr_process = subprocess.Popen(shlex.split(
        wamr_cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    time.sleep(0.1)
    if (wamr_process.poll() != None):
        print("\nWAMR doesn't wait for lldb connection")
        print_process_output(wamr_process)
        exit(1)

    lldb_process = subprocess.Popen(shlex.split(
        lldb_cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    if (options.verbose):
        while (lldb_process.poll() is None):
            print(lldb_process.stdout.read(), end='', flush=True)

    try:
        if (lldb_process.wait(5) != 0):
            print(f"\nFailed to validate case [{case}]")
            print_process_output(lldb_process)
            has_error = True

        if wamr_process.wait(2) != 0:
            print("\nWAMR process doesn't exit normally")
            print_process_output(wamr_process)
            has_error = True

    except subprocess.TimeoutExpired:
        print(f"\nFailed to validate case [{case}]")
        print("wamr output:")
        print_process_output(wamr_process)
        print("lldb output:")
        print_process_output(lldb_process)
        has_error = True
    finally:
        if (lldb_process.poll() == None):
            print(f'\nterminating lldb process [{lldb_process.pid}]')
            lldb_process.kill()
        if (wamr_process.poll() == None):
            print(f'terminating wamr process [{wamr_process.pid}]')
            wamr_process.kill()

        if (has_error):
            exit(1)

    print(f'\t OK')

    # wait 100ms to ensure the socket is closed
    time.sleep(0.1)

print('Validate lldb success')
exit(0)
