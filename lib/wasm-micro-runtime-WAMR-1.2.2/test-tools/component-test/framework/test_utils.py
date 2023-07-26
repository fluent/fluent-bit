from __future__ import print_function
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import datetime
import os
import random
import re
import shlex
import subprocess
import sys
import time
import shutil
from subprocess import check_output, CalledProcessError

def t_getPIDs(process):
    try:
        pidlist = map(int, check_output(["pidof", process]).split())
    except  CalledProcessError:
        pidlist = []
    #print process + ':list of PIDs = ' + ', '.join(str(e) for e in pidlist)
    return pidlist


def t_kill_process_by_name(p_keywords):
    pid_list = []
    ps_info = subprocess.check_output(shlex.split("ps aux")).split("\n")
    for p in ps_info:
        if p_keywords in p:
            tmp = p.split(" ")
            tmp = [x for x in tmp if len(x) > 0]
            pid_list.append(tmp[1])

    for pid in pid_list:
        cmd = "kill -9 {}".format(pid)
        subprocess.call(shlex.split(cmd))

    return pid_list



#proc    -> name of the process
#kill = 1  -> search for pid for kill
#kill = 0  -> search for name (default)

def t_process_exists(proc, kill = 0):
    ret = False
    processes  = t_getPIDs(proc)

    for pid in processes:
            if kill == 0:
                return True
            else:
                print("kill [" + proc + "], pid=" + str(pid))
                os.kill((pid), 9)
                ret = True
    return ret

def t_copy_files(source_dir, pattern, dest_dir):
    files = os.listdir(source_dir)
    for file in files:
        if file in ('/', '.', '..'):
            continue

        if pattern in ('*', '') or files.endswith(pattern):
            shutil.copy(source_dir+"/"+ file, dest_dir)



