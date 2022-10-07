#!/bin/bash
#
#

set -e

# Parse a log with --enable-refcnt output enabled.

log="$1"

if [[ ! -f $log ]]; then
    echo "Usage: $0 <log-file>"
    exit 1
fi


# Create a file with all refcnt creations
cfile=$(mktemp)
grep 'REFCNT.* 0 +1:' $log | awk '{print $6}' | sort > $cfile

# .. and one file with all refcnt destructions
dfile=$(mktemp)
grep 'REFCNT.* 1 -1:' $log | awk '{print $6}' | sort > $dfile

# For each refcnt that was never destructed (never reached 0), find it
# in the input log.

seen=
for p in $(grep -v -f $dfile $cfile) ; do
    echo "=== REFCNT $p never reached 0 ==="
    grep -nH "$p" $log
    echo ""
    seen=yes
done

rm -f "$cfile" "$dfile"

if [[ -z $seen ]]; then
    echo "No refcount leaks found"
    exit 0
fi

exit 2
