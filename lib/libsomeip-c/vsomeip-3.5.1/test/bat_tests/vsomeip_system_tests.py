# Copyright (C) 2023. BMW Car IT GmbH. All rights reserved.
import json
import os

from mtee.testing.support.target_share import TargetShare
from mtee.testing.tools import assert_process_returncode, metadata
from mtee.testing.test_environment import require_environment, require_environment_setup
from mtee.testing.test_environment import TEST_ENVIRONMENT as te
from mtee.testing.support.set_test_description import set_description


required_target_packages = ["vsomeip-systemtests-targetfiles"]

# test needs a target for execution
target = TargetShare().target

# include text file with tests to be excluded
with open('/tests/vsomeip/systemtests/excluded_tests.txt', 'r') as file:
    excluded_tests = []
    for test in file:
        test = test.strip()
        excluded_tests.append(test)


@metadata(testsuite=["BAT", "domain", "regression"],
          component="vsomeip",
          domain="SYSINFRA",
          duration="short",
          priority=1,
          image=["APPL"],
          teststage="system",
          testlevel="ENG_07",
          traceability={
              "MGU": {
                    "FEATURE": ["HLF - SUC | Some/IP Communication", ],
                    "MGUJIRA": ["MGUSIN-11117", "MGUSIN-1442", ],
                },
            },
        )

class TestTargetVSomeIP(object):

    @classmethod
    def setup_class(cls):
        cls.deploy_dir = target.targetfiles_path(__file__)

    @require_environment(te.target.simulator)
    def run_tests(self):
        with open('/tests/vsomeip/systemtests/test-metadata.json', 'r') as file:
            for test_case in json.load(file):

                if test_case['name'] not in excluded_tests:
                    def execute_tests_wrapper(test):
                        result = target.execute_command(
                            args='./' + ' '.join(test['command']), cwd=self.deploy_dir, environment={**test['environment'], 'USE_DOCKER' : '1'}, timeout=120)
                        assert_process_returncode(
                            0, result, "Executing {} failed. {}".format(test['name'], result))

                    set_description(execute_tests_wrapper, test_case['name'])
                    yield execute_tests_wrapper, test_case
