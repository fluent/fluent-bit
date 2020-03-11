#! /bin/sh
# vim:et:ft=sh:sts=2:sw=2
#
# shunit2 unit test for assert functions.
#
# Copyright 2008-2017 Kate Ward. All Rights Reserved.
# Released under the Apache 2.0 license.
#
# Author: kate.ward@forestent.com (Kate Ward)
# https://github.com/kward/shunit2
#
# Disable source following.
#   shellcheck disable=SC1090,SC1091

# These variables will be overridden by the test helpers.
stdoutF="${TMPDIR:-/tmp}/STDOUT"
stderrF="${TMPDIR:-/tmp}/STDERR"

# Load test helpers.
. ./shunit2_test_helpers

commonEqualsSame() {
  fn=$1

  ( ${fn} 'x' 'x' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'equal' $? "${stdoutF}" "${stderrF}"

  ( ${fn} "${MSG}" 'x' 'x' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'equal; with msg' $? "${stdoutF}" "${stderrF}"

  ( ${fn} 'abc def' 'abc def' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'equal with spaces' $? "${stdoutF}" "${stderrF}"

  ( ${fn} 'x' 'y' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'not equal' $? "${stdoutF}" "${stderrF}"

  ( ${fn} '' '' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'null values' $? "${stdoutF}" "${stderrF}"

  ( ${fn} arg1 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too few arguments' $? "${stdoutF}" "${stderrF}"

  ( ${fn} arg1 arg2 arg3 arg4 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too many arguments' $? "${stdoutF}" "${stderrF}"
}

commonNotEqualsSame() {
  fn=$1

  ( ${fn} 'x' 'y' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'not same' $? "${stdoutF}" "${stderrF}"

  ( ${fn} "${MSG}" 'x' 'y' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'not same, with msg' $? "${stdoutF}" "${stderrF}"

  ( ${fn} 'x' 'x' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'same' $? "${stdoutF}" "${stderrF}"

  ( ${fn} '' '' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'null values' $? "${stdoutF}" "${stderrF}"

  ( ${fn} arg1 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too few arguments' $? "${stdoutF}" "${stderrF}"

  ( ${fn} arg1 arg2 arg3 arg4 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too many arguments' $? "${stdoutF}" "${stderrF}"
}

testAssertEquals() {
  commonEqualsSame 'assertEquals'
}

testAssertNotEquals() {
  commonNotEqualsSame 'assertNotEquals'
}

testAssertSame() {
  commonEqualsSame 'assertSame'
}

testAssertNotSame() {
  commonNotEqualsSame 'assertNotSame'
}

testAssertContains() {
  ( assertContains 'abcdef' 'abc' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'found' $? "${stdoutF}" "${stderrF}"

  ( assertContains 'abcdef' 'bcd' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'found' $? "${stdoutF}" "${stderrF}"

  ( assertContains 'abcdef' 'def' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'found' $? "${stdoutF}" "${stderrF}"

  ( assertContains 'abc -Xabc def' '-Xabc' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'content starts with "-"' $? "${stdoutF}" "${stderrF}"

  ( assertContains "${MSG}" 'abcdef' 'abc' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'found, with msg' $? "${stdoutF}" "${stderrF}"

  ( assertContains 'abcdef' 'xyz' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'not found' $? "${stdoutF}" "${stderrF}"

  ( assertContains 'abcdef' 'zab' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'not found' $? "${stdoutF}" "${stderrF}"

  ( assertContains 'abcdef' 'efg' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'not found' $? "${stdoutF}" "${stderrF}"

  ( assertContains 'abcdef' 'acf' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'not found' $? "${stdoutF}" "${stderrF}"

  ( assertContains 'abcdef' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too few arguments' $? "${stdoutF}" "${stderrF}"

  ( assertContains arg1 arg2 arg3 arg4 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too many arguments' $? "${stdoutF}" "${stderrF}"
}

testAssertNotContains() {
  ( assertNotContains 'abcdef' 'xyz' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'not found' $? "${stdoutF}" "${stderrF}"

  ( assertNotContains 'abcdef' 'zab' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'not found' $? "${stdoutF}" "${stderrF}"

  ( assertNotContains 'abcdef' 'efg' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'not found' $? "${stdoutF}" "${stderrF}"

  ( assertNotContains 'abcdef' 'acf' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'not found' $? "${stdoutF}" "${stderrF}"

  ( assertNotContains "${MSG}" 'abcdef' 'xyz' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'not found, with msg' $? "${stdoutF}" "${stderrF}"

  ( assertNotContains 'abcdef' 'abc' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'found' $? "${stdoutF}" "${stderrF}"

  ( assertNotContains 'abcdef' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too few arguments' $? "${stdoutF}" "${stderrF}"

  ( assertNotContains arg1 arg2 arg3 arg4 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too many arguments' $? "${stdoutF}" "${stderrF}"
}

testAssertNull() {
  ( assertNull '' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'null' $? "${stdoutF}" "${stderrF}"

  ( assertNull "${MSG}" '' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'null, with msg' $? "${stdoutF}" "${stderrF}"

  ( assertNull 'x' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'not null' $? "${stdoutF}" "${stderrF}"

  ( assertNull >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too few arguments' $? "${stdoutF}" "${stderrF}"

  ( assertNull arg1 arg2 arg3 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too many arguments' $? "${stdoutF}" "${stderrF}"
}

testAssertNotNull()
{
  ( assertNotNull 'x' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'not null' $? "${stdoutF}" "${stderrF}"

  ( assertNotNull "${MSG}" 'x' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'not null, with msg' $? "${stdoutF}" "${stderrF}"

  ( assertNotNull 'x"b' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'not null, with double-quote' $? \
      "${stdoutF}" "${stderrF}"

  ( assertNotNull "x'b" >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'not null, with single-quote' $? \
      "${stdoutF}" "${stderrF}"

  # shellcheck disable=SC2016
  ( assertNotNull 'x$b' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'not null, with dollar' $? \
      "${stdoutF}" "${stderrF}"

  ( assertNotNull 'x`b' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'not null, with backtick' $? \
      "${stdoutF}" "${stderrF}"

  ( assertNotNull '' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'null' $? "${stdoutF}" "${stderrF}"

  # There is no test for too few arguments as $1 might actually be null.

  ( assertNotNull arg1 arg2 arg3 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too many arguments' $? "${stdoutF}" "${stderrF}"
}

testAssertTrue() {
  ( assertTrue 0 >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'true' $? "${stdoutF}" "${stderrF}"

  ( assertTrue "${MSG}" 0 >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'true, with msg' $? "${stdoutF}" "${stderrF}"

  ( assertTrue '[ 0 -eq 0 ]' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'true condition' $? "${stdoutF}" "${stderrF}"

  ( assertTrue 1 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'false' $? "${stdoutF}" "${stderrF}"

  ( assertTrue '[ 0 -eq 1 ]' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'false condition' $? "${stdoutF}" "${stderrF}"

  ( assertTrue '' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'null' $? "${stdoutF}" "${stderrF}"

  ( assertTrue >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too few arguments' $? "${stdoutF}" "${stderrF}"

  ( assertTrue arg1 arg2 arg3 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too many arguments' $? "${stdoutF}" "${stderrF}"
}

testAssertFalse() {
  ( assertFalse 1 >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'false' $? "${stdoutF}" "${stderrF}"

  ( assertFalse "${MSG}" 1 >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'false, with msg' $? "${stdoutF}" "${stderrF}"

  ( assertFalse '[ 0 -eq 1 ]' >"${stdoutF}" 2>"${stderrF}" )
  th_assertTrueWithNoOutput 'false condition' $? "${stdoutF}" "${stderrF}"

  ( assertFalse 0 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'true' $? "${stdoutF}" "${stderrF}"

  ( assertFalse '[ 0 -eq 0 ]' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'true condition' $? "${stdoutF}" "${stderrF}"

  ( assertFalse '' >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithOutput 'true condition' $? "${stdoutF}" "${stderrF}"

  ( assertFalse >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too few arguments' $? "${stdoutF}" "${stderrF}"

  ( assertFalse arg1 arg2 arg3 >"${stdoutF}" 2>"${stderrF}" )
  th_assertFalseWithError 'too many arguments' $? "${stdoutF}" "${stderrF}"
}

oneTimeSetUp() {
  th_oneTimeSetUp

  MSG='This is a test message'
}

# Load and run shunit2.
# shellcheck disable=SC2034
[ -n "${ZSH_VERSION:-}" ] && SHUNIT_PARENT=$0
. "${TH_SHUNIT}"
