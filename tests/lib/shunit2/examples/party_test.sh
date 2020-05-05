#! /bin/sh
# file: examples/party_test.sh
#
# This test is mostly for fun. Technically, it is a bad example of a unit test
# because of the temporal requirement, namely that the year be 1999. A better
# test would have been to pass in both a known-bad and known-good year into a
# function, and test for the expected result.

testPartyLikeItIs1999() {
  year=`date '+%Y'`
  assertEquals "It's not 1999 :-(" \
      '1999' "${year}"
}

# Load and run shUnit2.
. ../shunit2
