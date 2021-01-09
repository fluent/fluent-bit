#!/bin/sh
#
# shUnit2 example for mocking files.

MOCK_PASSWD=''  # This will be overridden in oneTimeSetUp().

test_root_uid_from_passed_filename() {
  result="$(root_uid_from_passed_filename "${MOCK_PASSWD}")"
  assertEquals 'unexpected root uid' '0' "${result}"
}

test_root_uid_from_derived_filename() {
  result="$(root_uid_from_derived_filename)"
  assertEquals 'unexpected root uid' '0' "${result}"
}

oneTimeSetUp() {
  # Provide a mock passwd file for testing. This will be cleaned up
  # automatically by shUnit2.
  MOCK_PASSWD="${SHUNIT_TMPDIR}/passwd"
  cat <<EOF >"${MOCK_PASSWD}"
nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false
root:*:0:0:System Administrator:/var/root:/bin/sh
daemon:*:1:1:System Services:/var/root:/usr/bin/false
EOF

  # Load script under test.
  . './mock_file.sh'
}

# Load and run shUnit2.
[ -n "${ZSH_VERSION:-}" ] && SHUNIT_PARENT=$0
. ../shunit2
