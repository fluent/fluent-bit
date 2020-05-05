#!/bin/sh
#
# shUnit2 example for mocking files.
#
# This example demonstrates two different mechanisms for mocking files on the
# system. The first method is preferred for testing specific aspects of a file,
# and the second method is preferred when multiple tests need access to the
# same mock data.
#
# When mocking files, the key thing of importance is providing the code under
# test with the correct file to read. The best practice for writing code where
# files need to be mocked is either:
# - Pass the filename to be tested into a function and test that function, or
# - Provide a function that returns the name of the filename to be read.
#
# The first case is preferred whenever possible as it allows the unit test to
# be explicit about what is being tested. The second case is useful when the
# first case is not achievable.
#
# For the second case, there are two common methods to mock the filename
# returned by the function:
# - Provide a special value (e.g. a mock variable) that is only available
#   during testing, or
# - Override something (e.g. the constant) in the test script.
#
# The first case is preferred as it doesn't require the unit test to alter code
# in any way. Yes, it means that the code itself knows that it is under test,
# and it behaves slightly differently than under normal conditions, but a
# visual inspection of the code by the developer should be sufficient to
# validate proper functionality of such a simple function.

# Treat unset variables as an error.
set -u

PASSWD='/etc/passwd'

# Read the root UID from the passwd filename provided as the first argument.
root_uid_from_passed_filename() {
  filename=$1
  root_uid "${filename}"
  unset filename
}


# Read the root UID from the passwd filename derived by call to the
# passwd_filename() function.
root_uid_from_derived_filename() {
  root_uid "$(passwd_filename)"
}

passwd_filename() {
  if [ -n "${MOCK_PASSWD:-}" ]; then
    echo "${MOCK_PASSWD}"  # Mock file for testing.
    return
  fi
  echo "${PASSWD}"
}


# Extract the root UID.
root_uid() { awk -F: 'u==$1{print $3}' u=root "$1"; }


main() {
  echo "root_uid_from_passed_filename:"
  root_uid_from_passed_filename "${PASSWD}"

  echo

  echo "root_uid_from_derived_filename:"
  root_uid_from_derived_filename
}


# Execute main() if this is run in standalone mode (i.e. not in a unit test).
ARGV0="$(basename "$0")"
argv0="$(echo "${ARGV0}" |sed 's/_test$//;s/_test\.sh$//')"
if [ "${ARGV0}" = "${argv0}" ]; then
  main "$@"
fi
