#!/bin/sh

# Create libpolarssl.* symlinks in the given directory

if [ $# -ne 1 ]; then
    echo "Usage: $0 <target-directory>" >&2
    exit 1
fi

if [ -d "$1" ]; then :; else
    echo "$0: target directory must exist" >&2
    exit 1
fi

if cd "$1"; then :; else
    echo "$0: cd '$1' failed" >&2
    exit 1
fi

if ls | grep 'libmbedtls\.' >/dev/null; then :; else
    echo "$0: libmbedtls not found in target directory" >&2
    exit 1
fi

for f in libmbedtls.*; do
    ln -sf $f libpolarssl${f#libmbedtls}
done
