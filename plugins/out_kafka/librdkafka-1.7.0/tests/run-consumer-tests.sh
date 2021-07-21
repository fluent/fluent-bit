#!/bin/bash
#
#
# Run all tests that employ a consumer.
#

set -e

TESTS=$(for t in $(grep -l '[Cc]onsume' 0*.{c,cpp}); do \
            echo $t | sed -e 's/^\([0-9][0-9][0-9][0-9]\)-.*/\1/g' ; \
        done)

export TESTS
echo "# Running consumer tests: $TESTS"

./run-test.sh $*
