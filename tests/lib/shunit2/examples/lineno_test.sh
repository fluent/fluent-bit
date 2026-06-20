#! /bin/sh
# file: examples/lineno_test.sh

testLineNo() {
  # This assert will have line numbers included (e.g. "ASSERT:[123] ...") if
  # they are supported.
  echo "_ASSERT_EQUALS_ macro value: ${_ASSERT_EQUALS_}"
  ${_ASSERT_EQUALS_} '"not equal"' 1 2

  # This assert will not have line numbers included (e.g. "ASSERT: ...").
  assertEquals 'not equal' 1 2
}

# Load and run shUnit2.
. ../shunit2
