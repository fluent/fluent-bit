#!/bin/bash
#
# Build script for buildbox.io
# Must be ran from top-level directory.

PFX=tmp_install

[ -d $PFX ] && rm -rf "$PFX"

make clean || true
./configure --clean
./configure "--prefix=$PFX" || exit 1
make || exit 1
make install || exit 1



