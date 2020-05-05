#! /bin/sh
# vim:et:ft=sh:sts=2:sw=2
#
# shunit2 unit test for macros.
#
# Copyright 2008-2017 Kate Ward. All Rights Reserved.
# Released under the Apache 2.0 license.
#
# Author: kate.ward@forestent.com (Kate Ward)
# https://github.com/kward/shunit2
#
### ShellCheck http://www.shellcheck.net/
# Disable source following.
#   shellcheck disable=SC1090,SC1091
# Presence of LINENO variable is checked.
#   shellcheck disable=SC2039

# These variables will be overridden by the test helpers.
stdoutF="${TMPDIR:-/tmp}/STDOUT"
stderrF="${TMPDIR:-/tmp}/STDERR"

# Load test helpers.
. ./shunit2_test_helpers

testAssertEquals() {
  # Start skipping if LINENO not available.
  [ -z "${LINENO:-}" ] && startSkipping

  ( ${_ASSERT_EQUALS_} 'x' 'y' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_EQUALS_ failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  ( ${_ASSERT_EQUALS_} '"some msg"' 'x' 'y' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_EQUALS_ w/ msg failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  return 0
}

testAssertNotEquals() {
  # Start skipping if LINENO not available.
  [ -z "${LINENO:-}" ] && startSkipping

  ( ${_ASSERT_NOT_EQUALS_} 'x' 'x' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_NOT_EQUALS_ failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  ( ${_ASSERT_NOT_EQUALS_} '"some msg"' 'x' 'x' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_NOT_EQUALS_ w/ msg failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  return 0
}

testSame() {
  # Start skipping if LINENO not available.
  [ -z "${LINENO:-}" ] && startSkipping

  ( ${_ASSERT_SAME_} 'x' 'y' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_SAME_ failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  ( ${_ASSERT_SAME_} '"some msg"' 'x' 'y' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_SAME_ w/ msg failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  return 0
}

testNotSame() {
  # Start skipping if LINENO not available.
  [ -z "${LINENO:-}" ] && startSkipping

  ( ${_ASSERT_NOT_SAME_} 'x' 'x' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_NOT_SAME_ failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  ( ${_ASSERT_NOT_SAME_} '"some msg"' 'x' 'x' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_NOT_SAME_ w/ msg failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  return 0
}

testNull() {
  # Start skipping if LINENO not available.
  [ -z "${LINENO:-}" ] && startSkipping

  ( ${_ASSERT_NULL_} 'x' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_NULL_ failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  ( ${_ASSERT_NULL_} '"some msg"' 'x' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_NULL_ w/ msg failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  return 0
}

testNotNull()
{
  # start skipping if LINENO not available
  [ -z "${LINENO:-}" ] && startSkipping

  ( ${_ASSERT_NOT_NULL_} '' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_NOT_NULL_ failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  ( ${_ASSERT_NOT_NULL_} '"some msg"' '""' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_NOT_NULL_ w/ msg failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stdoutF}" "${stderrF}" >&2

  return 0
}

testAssertTrue() {
  # Start skipping if LINENO not available.
  [ -z "${LINENO:-}" ] && startSkipping

  ( ${_ASSERT_TRUE_} "${SHUNIT_FALSE}" >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_TRUE_ failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  ( ${_ASSERT_TRUE_} '"some msg"' "${SHUNIT_FALSE}" >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_TRUE_ w/ msg failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  return 0
}

testAssertFalse() {
  # Start skipping if LINENO not available.
  [ -z "${LINENO:-}" ] && startSkipping

  ( ${_ASSERT_FALSE_} "${SHUNIT_TRUE}" >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_FALSE_ failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  ( ${_ASSERT_FALSE_} '"some msg"' "${SHUNIT_TRUE}" >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_ASSERT_FALSE_ w/ msg failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  return 0
}

testFail() {
  # Start skipping if LINENO not available.
  [ -z "${LINENO:-}" ] && startSkipping

  ( ${_FAIL_} >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_FAIL_ failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  ( ${_FAIL_} '"some msg"' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_FAIL_ w/ msg failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  return 0
}

testFailNotEquals()
{
  # start skipping if LINENO not available
  [ -z "${LINENO:-}" ] && startSkipping

  ( ${_FAIL_NOT_EQUALS_} 'x' 'y' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_FAIL_NOT_EQUALS_ failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  ( ${_FAIL_NOT_EQUALS_} '"some msg"' 'x' 'y' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_FAIL_NOT_EQUALS_ w/ msg failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  return 0
}

testFailSame() {
  # Start skipping if LINENO not available.
  [ -z "${LINENO:-}" ] && startSkipping

  ( ${_FAIL_SAME_} 'x' 'x' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_FAIL_SAME_ failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  ( ${_FAIL_SAME_} '"some msg"' 'x' 'x' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_FAIL_SAME_ w/ msg failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  return 0
}

testFailNotSame() {
  # Start skipping if LINENO not available.
  [ -z "${LINENO:-}" ] && startSkipping

  ( ${_FAIL_NOT_SAME_} 'x' 'y' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_FAIL_NOT_SAME_ failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  ( ${_FAIL_NOT_SAME_} '"some msg"' 'x' 'y' >"${stdoutF}" 2>"${stderrF}" )
  grep '^ASSERT:\[[0-9]*\] *' "${stdoutF}" >/dev/null
  rtrn=$?
  assertTrue '_FAIL_NOT_SAME_ w/ msg failure' ${rtrn}
  [ "${rtrn}" -ne "${SHUNIT_TRUE}" ] && cat "${stderrF}" >&2

  return 0
}

oneTimeSetUp() {
  th_oneTimeSetUp
}

# Disable output coloring as it breaks the tests.
SHUNIT_COLOR='none'; export SHUNIT_COLOR

# Load and run shUnit2.
# shellcheck disable=SC2034
[ -n "${ZSH_VERSION:-}" ] && SHUNIT_PARENT="$0"
. "${TH_SHUNIT}"
