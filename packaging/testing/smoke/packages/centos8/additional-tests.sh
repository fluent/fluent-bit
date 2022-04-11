#!/bin/sh

# Additional target-specific tests
exitCode=0

# Test for FIPS
# https://github.com/fluent/fluent-bit/issues/3617#issuecomment-1071518859
yumdownloader fluent-bit
if rpm --checksig -v ./*-bit-*.rpm | grep "SHA256 digest" | grep -vq "OK" ; then
    echo "Failed check for SHA256 digest"
    rpm --checksig -v ./*-bit*.rpm
    exitCode=1
fi

exit $exitCode
