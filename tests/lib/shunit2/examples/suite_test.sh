#!/bin/sh
# file: examples/suite_test.sh
#
# This test demonstrates the use of suites. Note: the suite functionality is
# deprecated as of v2.1.0, and will be removed in a future major release.

# suite is a special function called by shUnit2 to setup a suite of tests. It
# enables a developer to call a set of functions that contain tests without
# needing to rename the functions to start with "test".
#
# Tests that are to be called from within `suite()` are added to the list of
# executable tests by means of the `suite_addTest()` function.
suite() {
  # Add the suite_test_one() function to the list of executable tests.
  suite_addTest suite_test_one

  # Call the suite_test_two() function, but note that the test results will not
  # be added to the global stats, and therefore not reported at the end of the
  # unit test execution.
  suite_test_two
}

suite_test_one() {
  assertEquals 1 1
}

suite_test_two() {
  assertNotEquals 1 2
}

# Load and run shUnit2.
. ../shunit2
