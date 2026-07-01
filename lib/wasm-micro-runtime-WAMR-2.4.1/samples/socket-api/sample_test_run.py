#!/usr/bin/env python3
#
# Copyright (C) 2023 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import argparse
import shlex
import subprocess
import sys
import time
import traceback
import glob

WAMRC_CMD = "../../wamr-compiler/build/wamrc"

def compile_wasm_files_to_aot(wasm_apps_dir):
    wasm_files = glob.glob(wasm_apps_dir + "/*.wasm")
    print("Compile wasm app into aot files")
    for wasm_file in wasm_files:
        aot_file = wasm_file[0 : len(wasm_file) - 5] + ".aot";
        cmd = [ WAMRC_CMD, "-o", aot_file, wasm_file ]
        subprocess.check_call(cmd)

def start_server(cmd, cwd):
    app_server = subprocess.Popen(shlex.split(cmd), cwd=cwd)
    return app_server

def run_cmd(cmd, cwd):
    qry_prc = subprocess.run(
        shlex.split(cmd), cwd=cwd, check=False, capture_output=True
    )
    if (qry_prc.returncode != 0):
        print("Run {} failed, return {}".format(cmd), qry_prc.returncode)
        return
    print("return code: {}, output:\n{}".format(qry_prc.returncode,
                                                 qry_prc.stdout.decode()))

def main():
    """
    GO!GO!!GO!!!
    """
    parser = argparse.ArgumentParser(description="run the sample and examine outputs")
    parser.add_argument("working_directory", type=str)
    parser.add_argument("--aot", action='store_true', help="Test with AOT")
    args = parser.parse_args()

    test_aot = False
    suffix = ".wasm"
    if not args.aot:
        print("Test with interpreter mode")
    else:
        print("Test with AOT mode")
        test_aot = True
        suffix = ".aot"
        wasm_apps_dir = args.working_directory
        compile_wasm_files_to_aot(wasm_apps_dir)

    ret = 1
    app_server = None
    try:
        print("\n================================")
        print("Test TCP server and client")
        cmd = "./iwasm --addr-pool=0.0.0.0/15 tcp_server" + suffix
        app_server = start_server(cmd, args.working_directory)
        # wait for a second
        time.sleep(1)
        cmd = "./iwasm --addr-pool=127.0.0.1/15 tcp_client" + suffix
        for i in range(5):
            run_cmd(cmd, args.working_directory)

        print("\n================================")
        print("Test UDP server and client")
        cmd = "./iwasm --addr-pool=0.0.0.0/15 udp_server" + suffix
        app_server = start_server(cmd, args.working_directory)
        # wait for a second
        time.sleep(1)
        cmd = "./iwasm --addr-pool=127.0.0.1/15 udp_client" + suffix
        for i in range(5):
            run_cmd(cmd, args.working_directory)

        print("\n=====================================================")
        print("Sleep 80 seconds to wait TCP server port actually close")
        time.sleep(80)

        print("\n================================")
        print("Test send and receive")
        cmd = "./iwasm --addr-pool=127.0.0.1/0 ./send_recv" + suffix
        run_cmd(cmd, args.working_directory)

        print("\n================================")
        print("Test socket options")
        cmd = "./iwasm socket_opts" + suffix
        run_cmd(cmd, args.working_directory)

        print("\n================================")
        print("Test timeout server and client")
        cmd = "./iwasm --addr-pool=0.0.0.0/15 timeout_server" + suffix
        app_server = start_server(cmd, args.working_directory)
        # wait for a second
        time.sleep(1)
        cmd = "./iwasm --addr-pool=127.0.0.1/15 timeout_client" + suffix
        run_cmd(cmd, args.working_directory)

        print("\n==========================================")
        print("Test multicast_client and multicast_server")
        cmd = "./iwasm --addr-pool=0.0.0.0/0,::/0 multicast_client.wasm 224.0.0.1"
        app_server = start_server(cmd, args.working_directory)
        # wait for a second
        time.sleep(1)
        cmd = "./multicast_server 224.0.0.1"
        run_cmd(cmd, args.working_directory)

        cmd = "./iwasm --addr-pool=0.0.0.0/0,::/0 multicast_client.wasm FF02:113D:6FDD:2C17:A643:FFE2:1BD1:3CD2"
        app_server = start_server(cmd, args.working_directory)
        # wait for a second
        time.sleep(1)
        cmd = "./multicast_server FF02:113D:6FDD:2C17:A643:FFE2:1BD1:3CD2"
        run_cmd(cmd, args.working_directory)

        print("\n================================")
        print("Test address resolving")
        cmd = "./iwasm --allow-resolve=*.com addr_resolve.wasm github.com"
        run_cmd(cmd, args.working_directory)

        # wait for a second
        time.sleep(1)

        print("--> All pass")
        ret = 0
    except AssertionError:
        traceback.print_exc()
    finally:
        app_server.kill()

    return ret


if __name__ == "__main__":
    sys.exit(main())
