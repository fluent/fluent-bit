#! /bin/sh
# vim:et:ft=sh:sts=2:sw=2
#
# shUnit2 unit tests of miscellaneous things
#
# Copyright 2008-2018 Kate Ward. All Rights Reserved.
# Released under the Apache 2.0 license.
#
# Author: kate.ward@forestent.com (Kate Ward)
# https://github.com/kward/shunit2
#
### ShellCheck http://www.shellcheck.net/
# $() are not fully portable (POSIX != portable).
#   shellcheck disable=SC2006
# Disable source following.
#   shellcheck disable=SC1090,SC1091
# Not wanting to escape single quotes.
#   shellcheck disable=SC1003

# These variables will be overridden by the test helpers.
stdoutF="${TMPDIR:-/tmp}/STDOUT"
stderrF="${TMPDIR:-/tmp}/STDERR"

# Load test helpers.
. ./shunit2_test_helpers

# Note: the test script is prefixed with '#' chars so that shUnit2 does not
# incorrectly interpret the embedded functions as real functions.
testUnboundVariable() {
  unittestF="${SHUNIT_TMPDIR}/unittest"
  sed 's/^#//' >"${unittestF}" <<EOF
## Treat unset variables as an error when performing parameter expansion.
#set -u
#
#boom() { x=\$1; }  # This function goes boom if no parameters are passed!
#test_boom() {
#  assertEquals 1 1
#  boom  # No parameter given
#  assertEquals 0 \$?
#}
#SHUNIT_COLOR='none'
#. ${TH_SHUNIT}
EOF
  ( exec "${SHELL:-sh}" "${unittestF}" >"${stdoutF}" 2>"${stderrF}" )
  assertFalse 'expected a non-zero exit value' $?
  grep '^ASSERT:unknown failure' "${stdoutF}" >/dev/null
  assertTrue 'assert message was not generated' $?
  grep '^Ran [0-9]* test' "${stdoutF}" >/dev/null
  assertTrue 'test count message was not generated' $?
  grep '^FAILED' "${stdoutF}" >/dev/null
  assertTrue 'failure message was not generated' $?
}

# assertEquals repeats message argument.
# https://github.com/kward/shunit2/issues/7
testIssue7() {
  # Disable coloring so 'ASSERT:' lines can be matched correctly.
  _shunit_configureColor 'none'

  ( assertEquals 'Some message.' 1 2 >"${stdoutF}" 2>"${stderrF}" )
  diff "${stdoutF}" - >/dev/null <<EOF
ASSERT:Some message. expected:<1> but was:<2>
EOF
  rtrn=$?
  assertEquals "${SHUNIT_TRUE}" "${rtrn}"
  [ "${rtrn}" -eq "${SHUNIT_TRUE}" ] || cat "${stderrF}" >&2
}

# Support prefixes on test output.
# https://github.com/kward/shunit2/issues/29
testIssue29() {
  unittestF="${SHUNIT_TMPDIR}/unittest"
  sed 's/^#//' >"${unittestF}" <<EOF
## Support test prefixes.
#test_assert() { assertTrue ${SHUNIT_TRUE}; }
#SHUNIT_COLOR='none'
#SHUNIT_TEST_PREFIX='--- '
#. ${TH_SHUNIT}
EOF
  ( exec "${SHELL:-sh}" "${unittestF}" >"${stdoutF}" 2>"${stderrF}" )
  grep '^--- test_assert' "${stdoutF}" >/dev/null
  rtrn=$?
  assertEquals "${SHUNIT_TRUE}" "${rtrn}"
  [ "${rtrn}" -eq "${SHUNIT_TRUE}" ] || cat "${stdoutF}" >&2
}

# shUnit2 should not exit with 0 when it has syntax errors.
# https://github.com/kward/shunit2/issues/69
testIssue69() {
  unittestF="${SHUNIT_TMPDIR}/unittest"

  for t in Equals NotEquals Null NotNull Same NotSame True False; do
    assert="assert${t}"
    sed 's/^#//' >"${unittestF}" <<EOF
## Asserts with invalid argument counts should be counted as failures.
#test_assert() { ${assert}; }
#SHUNIT_COLOR='none'
#. ${TH_SHUNIT}
EOF
    ( exec "${SHELL:-sh}" "${unittestF}" >"${stdoutF}" 2>"${stderrF}" )
    grep '^FAILED' "${stdoutF}" >/dev/null
    assertTrue "failure message for ${assert} was not generated" $?
  done
}

# Ensure that test fails if setup/teardown functions fail.
testIssue77() {
  unittestF="${SHUNIT_TMPDIR}/unittest"
  for func in oneTimeSetUp setUp tearDown oneTimeTearDown; do
    sed 's/^#//' >"${unittestF}" <<EOF
## Environment failure should end test.
#${func}() { return ${SHUNIT_FALSE}; }
#test_true() { assertTrue ${SHUNIT_TRUE}; }
#SHUNIT_COLOR='none'
#. ${TH_SHUNIT}
EOF
    ( exec "${SHELL:-sh}" "${unittestF}" ) >"${stdoutF}" 2>"${stderrF}"
    grep '^FAILED' "${stdoutF}" >/dev/null
    assertTrue "failure of ${func}() did not end test" $?
  done
}

# Ensure a test failure is recorded for code containing syntax errors.
# https://github.com/kward/shunit2/issues/84
testIssue84() {
  unittestF="${SHUNIT_TMPDIR}/unittest"
  sed 's/^#//' >"${unittestF}" <<\EOF
## Function with syntax error.
#syntax_error() { ${!#3442} -334 a$@2[1]; }
#test_syntax_error() {
#  syntax_error
#  assertTrue ${SHUNIT_TRUE}
#}
#SHUNIT_COLOR='none'
#SHUNIT_TEST_PREFIX='--- '
#. ${TH_SHUNIT}
EOF
  ( exec "${SHELL:-sh}" "${unittestF}" >"${stdoutF}" 2>"${stderrF}" )
  grep '^FAILED' "${stdoutF}" >/dev/null
  assertTrue "failure message for ${assert} was not generated" $?
}

testPrepForSourcing() {
  assertEquals '/abc' "`_shunit_prepForSourcing '/abc'`"
  assertEquals './abc' "`_shunit_prepForSourcing './abc'`"
  assertEquals './abc' "`_shunit_prepForSourcing 'abc'`"
}

testEscapeCharInStr() {
  while read -r desc char str want; do
    got=`_shunit_escapeCharInStr "${char}" "${str}"`
    assertEquals "${desc}" "${want}" "${got}"
  done <<'EOF'
backslash      \ ''       ''
backslash_pre  \ \def     \\def
backslash_mid  \ abc\def  abc\\def
backslash_post \ abc\     abc\\
quote          " ''       ''
quote_pre      " "def     \"def
quote_mid      " abc"def  abc\"def
quote_post     " abc"     abc\"
string         $ ''       ''
string_pre     $ $def     \$def
string_mid     $ abc$def  abc\$def
string_post    $ abc$     abc\$
EOF

  # TODO(20170924:kward) fix or remove.
#  actual=`_shunit_escapeCharInStr "'" ''`
#  assertEquals '' "${actual}"
#  assertEquals "abc\\'" `_shunit_escapeCharInStr "'" "abc'"`
#  assertEquals "abc\\'def" `_shunit_escapeCharInStr "'" "abc'def"`
#  assertEquals "\\'def" `_shunit_escapeCharInStr "'" "'def"`

#  # Must put the backtick in a variable so the shell doesn't misinterpret it
#  # while inside a backticked sequence (e.g. `echo '`'` would fail).
#  backtick='`'
#  actual=`_shunit_escapeCharInStr ${backtick} ''`
#  assertEquals '' "${actual}"
#  assertEquals '\`abc' \
#      `_shunit_escapeCharInStr "${backtick}" ${backtick}'abc'`
#  assertEquals 'abc\`' \
#      `_shunit_escapeCharInStr "${backtick}" 'abc'${backtick}`
#  assertEquals 'abc\`def' \
#      `_shunit_escapeCharInStr "${backtick}" 'abc'${backtick}'def'`
}

testEscapeCharInStr_specialChars() {
  # Make sure our forward slash doesn't upset sed.
  assertEquals '/' "`_shunit_escapeCharInStr '\' '/'`"

  # Some shells escape these differently.
  # TODO(20170924:kward) fix or remove.
  #assertEquals '\\a' `_shunit_escapeCharInStr '\' '\a'`
  #assertEquals '\\b' `_shunit_escapeCharInStr '\' '\b'`
}

# Test the various ways of declaring functions.
#
# Prefixing (then stripping) with comment symbol so these functions aren't
# treated as real functions by shUnit2.
testExtractTestFunctions() {
  f="${SHUNIT_TMPDIR}/extract_test_functions"
  sed 's/^#//' <<EOF >"${f}"
## Function on a single line.
#testABC() { echo 'ABC'; }
## Multi-line function with '{' on next line.
#test_def()
# {
#  echo 'def'
#}
## Multi-line function with '{' on first line.
#testG3 () {
#  echo 'G3'
#}
## Function with numerical values in name.
#function test4() { echo '4'; }
## Leading space in front of function.
#	test5() { echo '5'; }
## Function with '_' chars in name.
#some_test_function() { echo 'some func'; }
## Function that sets variables.
#func_with_test_vars() {
#  testVariable=1234
#}
## Function with keyword but no parenthesis
#function test6 { echo '6'; }
## Function with keyword but no parenthesis, multi-line
#function test7 {
#  echo '7';
#}
## Function with no parenthesis, '{' on next line
#function test8
#{
#  echo '8'
#}
## Function with hyphenated name
#test-9() {
#  echo '9';
#}
## Function without parenthesis or keyword
#test_foobar { echo 'hello world'; }
## Function with multiple function keywords
#function function test_test_test() { echo 'lorem'; }
EOF

  actual=`_shunit_extractTestFunctions "${f}"`
  assertEquals 'testABC test_def testG3 test4 test5 test6 test7 test8 test-9' "${actual}"
}

# Test that certain external commands sometimes "stubbed" by users are escaped.
testIssue54() {
  for c in mkdir rm cat chmod sed; do
    grep "^[^#]*${c} " "${TH_SHUNIT}" | grep -qv "command ${c}"
    assertFalse "external call to ${c} not protected somewhere" $?
  done
  grep '^[^#]*[^ ]  *\[' "${TH_SHUNIT}" | grep -qv 'command \['
  assertFalse "call to [ ... ] not protected somewhere" $?
  grep '^[^#]*  *\.' "${TH_SHUNIT}" | grep -qv 'command \.'
  assertFalse "call to . not protected somewhere" $?
}

mock_tput() {
  if [ -z "${TERM}" ]; then
    # shellcheck disable=SC2016
    echo 'tput: No value for $TERM and no -T specified'
    return 2
  fi
  if [ "$1" = 'colors' ]; then
    echo 256
    return 0
  fi
  return 1
}

testColors() {
  while read -r desc cmd colors; do
    SHUNIT_CMD_TPUT=${cmd}
    got=`_shunit_colors`
    want=${colors}
    assertEquals "${got}" "${want}"
  done <<'EOF'
missing missing_tput 16
mock mock_tput 256
EOF
}

testColorsWitoutTERM() {
  SHUNIT_CMD_TPUT='mock_tput'
  got=`TERM='' _shunit_colors`
  want=16
  assertEquals "${got}" "${want}"
}

setUp() {
  for f in "${stdoutF}" "${stderrF}"; do
    cp /dev/null "${f}"
  done

  # Reconfigure coloring as some tests override default behavior.
  _shunit_configureColor "${SHUNIT_COLOR_DEFAULT}"

  # shellcheck disable=SC2034,SC2153
  SHUNIT_CMD_TPUT=${__SHUNIT_CMD_TPUT}
}

oneTimeSetUp() {
  SHUNIT_COLOR_DEFAULT="${SHUNIT_COLOR}"
  th_oneTimeSetUp
}

# Load and run shUnit2.
# shellcheck disable=SC2034
[ -n "${ZSH_VERSION:-}" ] && SHUNIT_PARENT=$0
. "${TH_SHUNIT}"
