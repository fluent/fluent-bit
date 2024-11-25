from __future__ import print_function
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import logging
import threading
from .test_utils import *

global logger
logger = None

def api_init_log(log_path):
    global logger
    print("api_init_log: " + log_path)
    logger = logging.getLogger(__name__)

    logger.setLevel(level = logging.INFO)
    handler = logging.FileHandler(log_path)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)

    logger.addHandler(handler)
    logger.addHandler(console)

    return

def api_log(message):
    global logger
    if logger is None:
        print(message)
    else:
        logger.info (message)
    return

def api_log_error(message):
    global logger
    if logger is None:
        print(message)
    else:
        logger.error (message)
    return

def api_logv(message):
    global logger
    if logger is None:
        print(message)
    else:
        logger.info(message)
    return

#####################################3
global g_case_runner_event
def api_wait_case_event(timeout):
    global g_case_runner_event
    g_case_runner_event.clear()
    g_case_runner_event.wait(timeout)

def api_notify_case_runner():
    global g_case_runner_event
    g_case_runner_event.set()

def api_create_case_event():
    global g_case_runner_event
    g_case_runner_event = threading.Event()

#######################################

def api_init_globals():
    global _global_dict
    _global_dict = {}

def api_set_value(name, value):
    _global_dict[name] = value

def api_get_value(name, defValue=None):
    try:
        return _global_dict[name]
    except KeyError:
        return defValue


#########################################
global root_path
def api_set_root_path(root):
    global root_path
    root_path = root

def api_get_root_path():
    global root_path
    return root_path;



