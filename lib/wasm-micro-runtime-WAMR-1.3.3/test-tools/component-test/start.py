#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

#!/usr/bin/env python

# -*- coding: utf-8 -*-
"""
It is the entrance of the iagent test framework.

"""
from __future__ import print_function

import argparse
import datetime
import os
import pprint
import random
import re
import shlex
import subprocess
import signal
import sys
import time

sys.path.append('../../../app-sdk/python')
from framework.test_utils  import *
from framework.framework  import *


def signal_handler(signal, frame):
        print('Pressed Ctrl+C!')
        sys.exit(0)

def Register_signal_handler():
    signal.signal(signal.SIGINT, signal_handler)
#    signal.pause()


def flatten_args_list(l):
    if l is None:
        return None

    return [x for y in l for x in y]



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "to run specific case(s) "\
            "in specific suite(s) with FC test framework")
    parser.add_argument('-s', dest = 'suite_id', action = 'append',
            nargs = '+',
            help = 'one or multiple suite ids, which are also setup ids.'\
                    'by default if it isn\'t passed from argument, all '\
                    'suites are going to be run.')
    parser.add_argument('-t', dest = 'case_id', action = 'append',
            nargs = '+',
            help = 'one or multiple cases ids.'\
                    'by default if it isn\'t passed from argument, all '\
                    'cases in specific suites are going to be run.')
    parser.add_argument('-n', dest = 'repeat_time', action = 'store',
            default = 1,
            help = 'how many times do you want to run. there is 40s '\
                    'break time between two rounds. each round includs '\
                    'init_setup, run_test_case and deinit_setup.')
    parser.add_argument('--shuffle_all', dest = 'shuffle_all',
            default = False, action = 'store_true',
            help = 'shuffle_all test cases in per test suite '\
                    'by default, all cases under per suite should '\
                    'be executed by input order.')
    parser.add_argument('--cases_list', dest='cases_list_file_path',
            default=None,
            action='store',
            help="read cases list from a flie ")
    parser.add_argument('--skip_proc', dest='skip_proc',
            default = False, action = 'store_true',
            help='do not start the test process.'\
                'sometimes the gw_broker process will be started in eclipse for debug purpose')
    parser.add_argument('-b', dest = 'binaries', action = 'store',
            help = 'The path of target folder ')
    parser.add_argument('-d', dest = 'debug', action = 'store_true',
            help = 'wait user to  attach the target process after launch processes ')
    parser.add_argument('--rebuild', dest = 'rebuild', action = 'store_true',
            help = 'rebuild all test binaries')
    args = parser.parse_args()

    print("------------------------------------------------------------")
    print("parsing arguments ... ...")
    print(args)

    '''
    logger = logging.getLogger('coapthon.server.coap')
    logger.setLevel(logging.DEBUG)
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    logger.addHandler(console)
    '''
    print("------------------------------------------------------------")
    print("preparing wamr binary and test tools ... ...")
    os.system("cd ../../samples/simple/ && bash build.sh -p host-interp")

    Register_signal_handler()

    api_init_globals();

    api_create_case_event();

    suites_list = flatten_args_list(args.suite_id)
    cases_list = flatten_args_list(args.case_id)

    dirname, filename = os.path.split(os.path.abspath(sys.argv[0]))
    api_set_root_path(dirname);

    framework = CTestFramework(dirname);
    framework.repeat_time = int(args.repeat_time)
    framework.shuffle_all = args.shuffle_all
    framework.skip_proc=args.skip_proc

    api_set_value('keep_env', args.skip_proc)
    api_set_value('debug', args.debug)
    api_set_value('rebuild', args.rebuild)

    binary_path = args.binaries
    if  binary_path is None:
        binary_path = os.path.abspath(dirname + '/../..')

    print("checking execution binary path: " + binary_path)
    if not os.path.exists(binary_path):
        print("The execution binary path was not available. quit...")
        os._exit(0)
    api_set_value('binary_path', binary_path)

    if suites_list is not None:
        framework.target_suites = suites_list
    else:
        framework.load_suites()

    framework.target_cases = cases_list
    framework.start_run()

    print("\n\n------------------------------------------------------------")
    print("The run folder is [" + framework.running_folder +"]")
    print("that's all. bye")

    print("kill to quit..")
    t_kill_process_by_name("start.py")

    sys.exit(0)
    os._exit()


