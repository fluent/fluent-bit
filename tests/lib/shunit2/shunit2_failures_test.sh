#! /bin/sh
# vim:et:ft=sh:sts=2:sw=2
#
# Copyright 2008-2019 Kate Ward. All Rights Reserved.
# Released under the Apache 2.0 license.
# http://www.apache.org/licenses/LICENSE-2.0
#
# shUnit2 -- Unit testing framework for Unix shell scripts.
# https://github.com/kward/shunit2
#
# Author: kate.ward@forestent.com (Kate Ward)
#
# shUnit2 unit test for failure functions
#
# Disable source following.
#   shellcheck disable=SC1090,SC1091

# These variables will be overridden by the test helpers.
stdoutF="${TMPDIR:-/tmp}/STDOUT"
stderrF="${TMPDIR:-/tmp}/STDERR"

# Load test helpers.
. ./shunit2_test_helpers

testFail() {
  ( fail >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'fail' $? "${stdoutF}" "${stderrF}"

  ( fail "${MSG}" >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'fail with msg' $? "${stdoutF}" "${stderrF}"

  ( fail arg1 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'too many arguments' $? "${stdoutF}" "${stderrF}"
}

testFailNotEquals() {
  ( failNotEquals 'x' 'x' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'same' $? "${stdoutF}" "${stderrF}"

  ( failNotEquals "${MSG}" 'x' 'x' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'same with msg' $? "${stdoutF}" "${stderrF}"

  ( failNotEquals 'x' 'y' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'not same' $? "${stdoutF}" "${stderrF}"

  ( failNotEquals '' '' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'null values' $? "${stdoutF}" "${stderrF}"

  ( failNotEquals >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too few arguments' $? "${stdoutF}" "${stderrF}"

  ( failNotEquals arg1 arg2 arg3 arg4 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too many arguments' $? "${stdoutF}" "${stderrF}"
}

testFailSame() {
  ( failSame 'x' 'x' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'same' $? "${stdoutF}" "${stderrF}"

  ( failSame "${MSG}" 'x' 'x' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'same with msg' $? "${stdoutF}" "${stderrF}"

  ( failSame 'x' 'y' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'not same' $? "${stdoutF}" "${stderrF}"

  ( failSame '' '' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'null values' $? "${stdoutF}" "${stderrF}"

  ( failSame >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too few arguments' $? "${stdoutF}" "${stderrF}"

  ( failSame arg1 arg2 arg3 arg4 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too many arguments' $? "${stdoutF}" "${stderrF}"
}

oneTimeSetUp() {
  th_oneTimeSetUp

  MSG='This is a test message'
}

# Load and run shUnit2.
# shellcheck disable=SC2034
[ -n "${ZSH_VERSION:-}" ] && SHUNIT_PARENT=$0
. "${TH_SHUNIT}"
