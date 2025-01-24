# Copyright (C) 2023. BMW Car IT GmbH. All rights reserved.

# Test it with:
#   run-mgu-tests -v --sdktarget xs-baytrail-hmgua1 --sysroot / /usr/share/vsomeip-sdktests/sdktests/sdk_vsomeip_tests.py

import os
import shutil
import tempfile

import subprocess
if not hasattr(subprocess, "TimeoutExpired"):
    import subprocess32 as subprocess

from mtee.testing.tools import assert_true, assert_equal, metadata

@metadata(testsuite="BAT", component="vsomeip", teststage="regression")
class TestsSdkVSomeIP(object):

    def setup(self):
        TestsSdkVSomeIP._srcdir = os.path.dirname(os.path.realpath(__file__));
        TestsSdkVSomeIP._tempdir = tempfile.mkdtemp()

    def teardown(self):
        if os.path.isdir(TestsSdkVSomeIP._tempdir):
            shutil.rmtree(TestsSdkVSomeIP._tempdir)

    @staticmethod
    def run_command(cmd, cwd=None, input=None):
        if cwd==None: cwd=os.getcwd()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, shell=False,cwd=cwd)
        if input: proc.stdin.write(input.encode('utf-8'))
        (stdo,stde)=proc.communicate()
        stdo = stdo.decode('utf-8') if stdo else None
        stde = stde.decode('utf-8') if stde else None
        assert_equal(0, proc.returncode, "Running command failed")

    def test_001_hello_world(self):
        TestsSdkVSomeIP.run_command(["cmake", os.path.join(TestsSdkVSomeIP._srcdir, "hello_world")], cwd=TestsSdkVSomeIP._tempdir)
        TestsSdkVSomeIP.run_command(["make"], cwd=TestsSdkVSomeIP._tempdir)

        assert_true(os.path.isfile(os.path.join(TestsSdkVSomeIP._tempdir, "hello_world_service")), "hello_world_service not created")
        assert_true(os.path.isfile(os.path.join(TestsSdkVSomeIP._tempdir, "hello_world_client")), "hello_world_client not created")
