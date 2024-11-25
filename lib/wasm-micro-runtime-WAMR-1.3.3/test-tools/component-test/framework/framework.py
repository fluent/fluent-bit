from __future__ import print_function
#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

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
import shutil

from .test_api import *
import this


'''
The run evironment dir structure:

 run/
      run{date-time}/
         suites/
               {suite name}/
                      -- target/  (the target software being tested)
                      -- tools/   (the tools for testing the target software)
'''


framework=None

def get_framework():
    global framework
    return framework

def my_import(name):
    mod = __import__(name)
    components = name.split('.')
    for comp in components[1:]:
        mod = getattr(mod, comp)
    return mod


# we maintain a root path apart from framework location
# so the suites can be located in anywhere
class CTestFramework(object):

    def __init__(self,  path):
        self.running_case = ''
        self.running_suite = ''
        self.target_suites = {}
        self.target_cases = {}
        self.root_path = path
        self.running_folder=''
        self.report = None
        self.sucess_cases = 0
        self.failed_cases = 0
        self.setup_fails = 0
        self.load_fails = 0;
        global framework
        framework = self

        api_set_root_path(path)

        print("root_path is " + self.root_path)

    def gen_execution_stats(self):
        return '\nTest Execution Summary: '  \
                       '\n\tSuccess:              {}'  \
                       '\n\tCases fails:          {}' \
                       '\n\tSetup fails:          {}' \
                       '\n\tCase load fails:      {}'.format(
           self.sucess_cases,  self.failed_cases, self.setup_fails, self.load_fails)

    def report_result(self, success, message, case_description):
        if self.report is None:
            return

        case_pass = "pass"
        if not success:
            case_pass = "fail"

        self.report.write(case_pass + ": [" + self.running_case + "]\n\treason: " + \
                          message + "\n\tcase: " + case_description + "\n")
        return

    def get_running_path(self):
        return self.root_path + "/run/" + self.running_folder

    def load_suites(self):
        self.target_suites = os.listdir(self.root_path + "/suites")
        return

    def run_case(self, suite_instance, case):
        # load the test case module
        case_description = ''
        suite = suite_instance.m_name
        api_log("\n>>start run [" + case + "] >>")
        module_name = 'suites.' + suite + ".cases." + case + ".case"
        try:
            module = my_import(module_name)
        except Exception as e:
            report_fail("load case fail: " + str(e))
            api_log_error("load case fail: " + str(e))
            self.load_fails = self.load_fails +1
            print(traceback.format_exc())
            return False

        try:
            case = module.CTestCase(suite_instance)
        except Exception as e:
            report_fail("initialize case fail: " + str(e))
            api_log_error("initialize case fail: " + str(e))
            self.load_fails = self.load_fails +1
            return False

        # call the case on setup callback
        try:
            case_description = case.on_get_case_description()
            result, message = case.on_setup_case()
        except Exception as e:
            result = False
            message = str(e);
        if not result:
            api_log_error(message)
            report_fail (message, case_description)
            self.failed_cases = self.failed_cases+1
            return False

        # call the case execution callaback
        try:
            result, message = case.on_run_case()
        except Exception as e:
            result = False
            message = str(e);
        if not result:
            report_fail (message, case_description)
            api_log_error(message)
            self.failed_cases = self.failed_cases+1
        else:
            report_success(case_description)
            self.sucess_cases = self.sucess_cases +1

        # call the case cleanup callback
        try:
            clean_result, message = case.on_cleanup_case()
        except Exception as e:
            clean_result = False
            message = str(e)

        if not clean_result:
            api_log(message)

        return  result

    def run_suite(self, suite, cases):
        # suite setup
        message = ''
        api_log("\n>>> Suite [" + suite + "] starting >>>")
        running_folder = self.get_running_path()+ "/suites/" + suite;

        module_name = 'suites.' + suite + ".suite_setup"
        try:
            module = my_import(module_name)
        except Exception as e:
            report_fail("load suite [" + suite +"] fail: " + str(e))
            self.load_fails = self.load_fails +1
            return False

        try:
            suite_instance = module.CTestSuite(suite, \
                self.root_path + '/suites/' + suite, running_folder)
        except Exception as e:
            report_fail("initialize suite fail: " + str(e))
            self.load_fails = self.load_fails +1
            return False

        result, message = suite_instance.load_settings()
        if not result:
            report_fail("load settings fail: " + str(e))
            self.load_fails = self.load_fails +1
            return False

        try:
            result, message = suite_instance.on_suite_setup()
        except Exception as e:
            result = False
            message = str(e);
        if not result:
            api_log_error(message)
            report_fail (message)
            self.setup_fails = self.setup_fails + 1
            return False

        self.running_suite = suite

        cases.sort()

        # run cases
        for case in cases:
            if not os.path.isdir(self.root_path + '/suites/' + suite + '/cases/' + case):
                continue

            self.running_case = case
            self.run_case(suite_instance, case)
            self.running_case = ''

        # suites cleanup
        self.running_suite = ''
        try:
            result, message = suite_instance.on_suite_cleanup()
        except Exception as e:
            result = False
            message = str(e);
        if not result:
            api_log_error(message)
            report_fail (message)
            self.setup_fails = self.setup_fails + 1
        return

    def start_run(self):
        if self.target_suites is None:
            print("\n\nstart run: no target suites, exit..")
            return

        cur_time = time.localtime()
        time_prefix = "{:02}-{:02}-{:02}-{:02}".format(
            cur_time.tm_mon, cur_time.tm_mday, cur_time.tm_hour,  cur_time.tm_min)

        debug = api_get_value('debug', False)
        if debug:
            self.running_folder = 'debug'
        else:
            self.running_folder = 'run-' + time_prefix

        folder = self.root_path + "/run/" +self.running_folder;

        if os.path.exists(folder):
            shutil.rmtree(folder, ignore_errors=True)

        if not os.path.exists(folder):
            os.makedirs(folder )
            os.makedirs(folder  + "/suites")

        api_init_log(folder + "/test.log")

        self.report = open(folder + "/report.txt", 'a')

        self.target_suites.sort()

        for suite in self.target_suites:
            if not os.path.isdir(self.root_path + '/suites/' + suite):
                continue
            self.report.write("suite " + suite + " cases:\n")
            if self.target_cases is None:
                cases = os.listdir(self.root_path + "/suites/" + suite + "/cases")
                self.run_suite(suite, cases)
            else:
                self.run_suite(suite, self.target_cases)
            self.report.write("\n")

        self.report.write("\n\n")
        summary = self.gen_execution_stats()
        self.report.write(summary);
        self.report.flush()
        self.report.close()
        print(summary)


def report_fail(message, case_description=''):
    global framework
    if framework is not None:
        framework.report_result(False, message, case_description)

    api_log_error(message)

    return

def report_success(case_description=''):
    global framework
    if framework is not None:
        framework.report_result(True , "OK", case_description)
    return
