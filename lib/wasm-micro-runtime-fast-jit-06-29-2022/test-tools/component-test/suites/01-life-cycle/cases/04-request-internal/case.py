#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import sys
import time
import random
import logging
import json

from framework.case_base import *
from framework.test_api import *
from harness.harness_api import *

class CTestCase(CTestCaseBase):
    def __init__(self, suite):
        CTestCaseBase.__init__(self, suite)

    def get_case_name(self):
        case_path = os.path.dirname(os.path.abspath( __file__ ))
        return os.path.split(case_path)[1]

    def on_get_case_description(self):
        return "startup the executables"

    def on_setup_case(self):
        os.chdir(self.get_case_name())
        start_env()
        api_log_error("on_setup_case OK")
        return True, ''

    def on_cleanup_case(self):
        stop_env()
        api_log_error("on_cleanup_case OK")
        return True, ''

    # called by the framework
    def on_run_case(self):
        time.sleep(0.5)

        #install App1
        ret = install_app("App1", "04_request_internal_resp.wasm")
        if (ret != 65):
            return False, ''

        #install App2
        ret = install_app("App2", "04_request_internal_req.wasm")
        if (ret != 65):
            return False, ''

        #query Apps
        ret = query_app()
        if (ret != 69):
            return False, ''
        ret = check_query_apps(["App1","App2"])
        if (ret == False):
            return False, ''

        #send request to App2
        ret = send_request("/res1", "GET", None)
        if (ret != 69):
            return False, ''
        time.sleep(2)
        expect_response_payload = {"key1":"value1","key2":"value2"}
        ret = check_response_payload(expect_response_payload)
        if (ret == False):
            return False, ''

        #send request to App2
        ret = send_request("/res2", "GET", None)
        if (ret != 69):
            return False, ''
        time.sleep(2)
        expect_response_payload = {"key1":"value1","key2":"value2"}
        ret = check_response_payload(expect_response_payload)
        if (ret == False):
            return False, ''

        return True, ''
