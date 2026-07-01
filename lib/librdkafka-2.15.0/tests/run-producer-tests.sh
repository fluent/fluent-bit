#!/bin/bash
#
#
# Run all tests that employ a producer.
#

set -e

TESTS=$(for t in $(grep -l '[pp]roduce' 0*.{c,cpp}); do \
            echo $t | sed -e 's/^\([0-9][0-9][0-9][0-9]\)-.*/\1/g' ; \
        done)

export TESTS
echo "# Running producer tests: $TESTS"

./run-test.sh $*
