# Copyright (C) 2023. BMW Car IT GmbH. All rights reserved.
import os
import nose

from mtee.testing.support.target_share import TargetShare
from mtee.testing.tools import metadata, assert_process_returncode
from mtee.testing.test_environment import require_environment, TEST_ENVIRONMENT as te

from nose.tools import assert_regexp_matches, assert_true, assert_equal, assert_not_equal

# test needs a target for execution
target = TargetShare().target

TEST_ENVIRONMENT = (te.target.hardware.mgu22, )

@require_environment(*TEST_ENVIRONMENT)
@metadata(testsuite=["BAT", "domain"],
          component="vsomeip",
          domain="SYSMAN",
          duration="short",
          priority=1,
          testlevel="ENG_07",
          teststage="regression")
class TestTargetVSomeIP(object):

    @metadata(test_case_id="SYSMAN_vsomeip_socket_path")
    def test_sockets_path(self):
        result = target.execute_command("ls /var/run/someip/vsomeip*")
        assert_process_returncode(0, result, "No vsomeip sockets found")
