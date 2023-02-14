#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import os
import shutil
import types
import time
import glob

from framework.test_api import *
from framework.test_utils import *
from harness.harness_api import *
from framework.suite import *

class CTestSuite(CTestSuiteBase):
    setup_path = ""
    def __init__(self, name, suite_path, run_path):
            CTestSuiteBase.__init__(self, name, suite_path, run_path)

    def on_suite_setup(self):
        global setup_path
        setup_path = os.getcwd()
        cases = os.listdir(self.suite_path + "/cases/")
        cases.sort()

        if api_get_value("rebuild", False):
                  path_tmp = os.getcwd()
                  os.chdir(self.suite_path + "/test-app")
                  os.system(self.suite_path + "/test-app" + "/build.sh")
                  os.chdir(path_tmp)

        os.makedirs(self.run_path + "/test-app")

        for case in cases:
            if case != "__init__.pyc" and case != "__init__.py":
                os.makedirs(self.run_path + "/" + case)
                #copy each case's host_tool, simple, wasm files, start/stop scripts to the run directory,
                shutil.copy(setup_path + "/../../samples/simple/out/simple", self.run_path + "/" + case)
                shutil.copy(setup_path + "/../../samples/simple/out/host_tool", self.run_path + "/" + case)
                for file in glob.glob(self.suite_path + "/test-app/" + "/*.wasm"):
                  shutil.copy(file, self.run_path + "/test-app")
                shutil.copy(self.suite_path + "/tools/product/start.sh", self.run_path + "/" + case)
                shutil.copy(self.suite_path + "/tools/product/stop.sh", self.run_path + "/" + case)

        os.chdir(self.run_path)

        return True, 'OK'

    def on_suite_cleanup(self):
        global setup_path
        os.chdir(setup_path)
        api_log("stopping env..")

        return True, 'OK'
