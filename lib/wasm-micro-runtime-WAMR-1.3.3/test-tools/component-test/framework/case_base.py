#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import os
import json
from test.test_support import _run_suite

class CTestCaseBase(object):
    def __init__(self, suite):
          self.m_suite = suite
          return
    def on_get_case_description(self):
        return "Undefined"

    def on_setup_case(self):
        return True, ''

    def on_cleanup_case(self):
        return True, ''

    # called by the framework
    def on_run_case(self):
        return True, ''

    def get_suite(self):
        return self.m_suite

