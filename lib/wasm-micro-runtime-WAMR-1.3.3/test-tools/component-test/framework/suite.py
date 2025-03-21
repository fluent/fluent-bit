#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import os
import json

class CTestSuiteBase(object):
    def __init__(self, name, suite_path, run_path):
        self.suite_path=suite_path
        self.run_path=run_path
        self.m_name = name
        self.settings = {}

    def get_settings_item(self,  item):
            if item in self.settings:
                return self.settings[item]
            else:
                return None

    def load_settings(self):
        path = self.suite_path + "/settings.cfg"
        if os.path.isfile(path):
            try:
                fp = open(path, 'r')
                self.settings = json.load(fp)
                fp.close()
            except Exception, e:
                return False, 'Load settings fail: ' + e.message
            return True, 'OK'
        else:
            return True, 'No file'

    def on_suite_setup(self):
        return True, 'OK'

    def on_suite_cleanup(self):
        return True, 'OK'

