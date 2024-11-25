#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import os
import shutil
import subprocess
import json
import time

from framework import test_api
from framework.test_utils import *

output = "output.txt"

def start_env():
    os.system("./start.sh")

def stop_env():
    os.system("./stop.sh")
    time.sleep(0.5)
    os.chdir("../") #reset path for other cases in the same suite

def check_is_timeout():
    line_num = 0
    ft = open(output, 'r')
    lines = ft.readlines()

    for line in reversed(lines):
        if (line[0:36] == "--------one operation begin.--------"):
            break
        line_num = line_num + 1

    ft.close()
    if (lines[-(line_num)] == "operation timeout"):
        return True
    else:
        return False

def parse_ret(file):
    ft = open(file, 'a')
    ft.writelines("\n")
    ft.writelines("--------one operation finish.--------")
    ft.writelines("\n")
    ft.close()

    ft = open(file, 'r')
    for line in reversed(ft.readlines()):
        if (line[0:16] == "response status "):
            ret = line[16:]
            ft.close()
            return int(ret)

def run_host_tool(cmd, file):
    ft = open(file, 'a')
    ft.writelines("--------one operation begin.--------")
    ft.writelines("\n")
    ft.close()
    os.system(cmd + " -o" + file)
    if (check_is_timeout() == True):
        return -1
    return parse_ret(file)

def install_app(app_name, file_name):
    return run_host_tool("./host_tool -i " + app_name + " -f ../test-app/" + file_name, output)

def uninstall_app(app_name):
    return run_host_tool("./host_tool -u " + app_name, output)

def query_app():
    return run_host_tool("./host_tool -q ", output)

def send_request(url, action, payload):
    if (payload is None):
        return run_host_tool("./host_tool -r " + url + " -A " + action, output)
    else:
        return run_host_tool("./host_tool -r " + url + " -A " + action + " -p " + payload, output)

def register(url, timeout, alive_time):
    return run_host_tool("./host_tool -s " + url + " -t " + str(timeout) + " -a " + str(alive_time), output)

def deregister(url):
    return run_host_tool("./host_tool -d " + url, output)

def get_response_payload():
    line_num = 0
    ft = open(output, 'r')
    lines = ft.readlines()

    for line in reversed(lines):
        if (line[0:16] == "response status "):
            break
        line_num = line_num + 1

    payload_lines = lines[-(line_num):-1]
    ft.close()

    return payload_lines

def check_query_apps(expected_app_list):
    if (check_is_timeout() == True):
        return False
    json_lines = get_response_payload()
    json_str = " ".join(json_lines)
    json_dict = json.loads(json_str)
    app_list = []

    for key, value in json_dict.items():
        if key[0:6] == "applet":
            app_list.append(value)

    if (sorted(app_list) == sorted(expected_app_list)):
        return True
    else:
        return False

def check_response_payload(expected_payload):
    if (check_is_timeout() == True):
        return False
    json_lines = get_response_payload()
    json_str = " ".join(json_lines)

    if (json_str.strip() != ""):
        json_dict = json.loads(json_str)
    else:
        json_dict = {}

    if (json_dict == expected_payload):
        return True
    else:
        return False

def check_get_event():
    line_num = 0
    ft = open(output, 'r')
    lines = ft.readlines()

    for line in reversed(lines):
        if (line[0:16] == "response status "):
            break
        line_num = line_num + 1

    payload_lines = lines[-(line_num):-1]
    ft.close()

    if (payload_lines[1][0:17] ==  "received an event"):
        return True
    else:
        return False
