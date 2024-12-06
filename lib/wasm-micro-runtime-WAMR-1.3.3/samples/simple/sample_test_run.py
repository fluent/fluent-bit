#!/usr/bin/env python3
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
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

def start_server(cwd):
    """
    Startup the 'simple' process works in TCP server mode
    """
    app_server = subprocess.Popen(shlex.split("./simple -s "), cwd=cwd)
    return app_server


def query_installed_application(cwd):
    """
    Query all installed applications
    """
    qry_prc = subprocess.run(
        shlex.split("./host_tool -q"), cwd=cwd, check=False, capture_output=True
    )
    assert qry_prc.returncode == 69
    return qry_prc.returncode, qry_prc.stdout


def install_wasm_application(wasm_name, wasm_file, cwd):
    """
    Install a wasm application
    """
    inst_prc = subprocess.run(
        shlex.split(f"./host_tool -i {wasm_name} -f {wasm_file}"),
        cwd=cwd,
        check=False,
        capture_output=True,
    )
    assert inst_prc.returncode == 65
    return inst_prc.returncode, inst_prc.stdout


def uninstall_wasm_application(wasm_name, cwd):
    """
    Uninstall a wasm application
    """

    unst_prc = subprocess.run(
        shlex.split(f"./host_tool -u {wasm_name}"),
        cwd=cwd,
        check=False,
        capture_output=True,
    )
    assert unst_prc.returncode == 66
    return unst_prc.returncode, unst_prc.stdout


def send_get_to_wasm_application(wasm_name, url, cwd):
    """
    send a request (GET) from host to an applicaton
    """
    qry_prc = subprocess.run(
        shlex.split(f"./host_tool -r /app/{wasm_name}{url} -A GET"),
        cwd=cwd,
        check=False,
        capture_output=True,
    )
    assert qry_prc.returncode == 69
    return qry_prc.returncode, qry_prc.stdout


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
        wasm_apps_dir = args.working_directory + "/wasm-apps"
        compile_wasm_files_to_aot(wasm_apps_dir)

    ret = 1
    app_server = None
    try:
        app_server = start_server(args.working_directory)

        # wait for a second
        time.sleep(1)

        print("--> Install timer" + suffix + "...")
        install_wasm_application(
            "timer", "./wasm-apps/timer" + suffix, args.working_directory
        )

        # wait for a second
        time.sleep(3)

        print("--> Query all installed applications...")
        query_installed_application(args.working_directory)

        print("--> Install event_publisher" + suffix + "...")
        install_wasm_application(
            "event_publisher",
            "./wasm-apps/event_publisher" + suffix,
            args.working_directory,
        )

        print("--> Install event_subscriber" + suffix + "...")
        install_wasm_application(
            "event_subscriber",
            "./wasm-apps/event_subscriber" + suffix,
            args.working_directory,
        )

        print("--> Query all installed applications...")
        query_installed_application(args.working_directory)

        print("--> Uninstall timer" + suffix + "...")
        uninstall_wasm_application("timer", args.working_directory)

        print("--> Query all installed applications...")
        query_installed_application(args.working_directory)

        print("--> Uninstall event_publisher" + suffix + "...")
        uninstall_wasm_application(
            "event_publisher",
            args.working_directory,
        )

        print("--> Uninstall event_subscriber" + suffix + "...")
        uninstall_wasm_application(
            "event_subscriber",
            args.working_directory,
        )

        print("--> Query all installed applications...")
        query_installed_application(args.working_directory)

        print("--> Install request_handler" + suffix + "...")
        install_wasm_application(
            "request_handler",
            "./wasm-apps/request_handler" + suffix,
            args.working_directory,
        )

        print("--> Query again...")
        query_installed_application(args.working_directory)

        print("--> Install request_sender" + suffix + "...")
        install_wasm_application(
            "request_sender",
            "./wasm-apps/request_sender" + suffix,
            args.working_directory,
        )

        print("--> Send GET to the Wasm application named request_handler...")
        send_get_to_wasm_application("request_handler", "/url1", args.working_directory)

        print("--> Uninstall request_handler" + suffix + "...")
        uninstall_wasm_application(
            "request_handler",
            args.working_directory,
        )

        print("--> Uninstall request_sender" + suffix + "...")
        uninstall_wasm_application(
            "request_sender",
            args.working_directory,
        )

        # Install a wasm app named "__exit_app_manager__" just to make app manager exit
        # while the wasm app is uninstalled, so as to collect the code coverage data.
        # Only available when collecting code coverage is enabled.
        print("--> Install timer" + suffix + "...")
        install_wasm_application(
            "__exit_app_manager__", "./wasm-apps/timer" + suffix, args.working_directory
        )

        print("--> Uninstall timer" + suffix + "...")
        uninstall_wasm_application(
            "__exit_app_manager__",
            args.working_directory,
        )

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
