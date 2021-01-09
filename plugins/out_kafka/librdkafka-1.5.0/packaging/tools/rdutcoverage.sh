#!/bin/bash
#
# Verify that code coverage numbers are not reused in multiple places.
#

set -e

echo "Checking for duplicate coverage numbers:"
cnt=0
for d in $(egrep -Rsoh 'RD_UT_COVERAGE\([[:digit:]]+\)' src \
               | sort | uniq -c | \
               egrep -v '^[[:space:]]*1 ' | awk '{print $2}'); do
    grep -RsnF "$d" src
    cnt=$(expr $cnt + 1)
done

echo ""

if [[ $cnt -gt 0 ]]; then
    echo "$cnt duplicates found: please use unique numbers"
    exit 1
else
    echo "No duplicate(s) found"
    exit 0
fi
