#!/bin/sh

ver=`cat include/msgpack/version_master.h | tr -d "\n" | sed -e 's/#define MSGPACK_VERSION_MAJOR[[:space:]]*\([[:alnum:]]*\)/\1./g' -e 's/#define MSGPACK_VERSION_MINOR[[:space:]]*\([[:alnum:]]*\)/\1./g' -e 's/#define MSGPACK_VERSION_REVISION[[:space:]]*\([[:alnum:]]*\)/\1/g'`

prefix=msgpack-$ver
filename=$prefix.tar

ln -s . $prefix

test -f AUTHORS   || touch AUTHORS
test -f COPYING   || touch COPYING
test -f ChangeLog || cp -f CHANGELOG.md ChangeLog
test -f NEWS      || touch NEWS
test -f NOTICE    || touch NOTICE
test -f README    || cp -f README.md README

tar cf $filename $prefix/example
tar --append --file=$filename $prefix/test
tar --append --file=$filename $prefix/include
tar --append --file=$filename $prefix/erb
tar --append --file=$filename $prefix/src

tar --append --file=$filename $prefix/CMakeLists.txt
tar --append --file=$filename $prefix/Files.cmake
tar --append --file=$filename $prefix/NOTICE
tar --append --file=$filename $prefix/Doxyfile
tar --append --file=$filename $prefix/msgpack.pc.in
tar --append --file=$filename $prefix/AUTHORS
tar --append --file=$filename $prefix/README.md
tar --append --file=$filename $prefix/LICENSE_1_0.txt
tar --append --file=$filename $prefix/ChangeLog
tar --append --file=$filename $prefix/NEWS
tar --append --file=$filename $prefix/COPYING
tar --append --file=$filename $prefix/README
tar --append --file=$filename $prefix/msgpack_vc8.sln
tar --append --file=$filename $prefix/msgpack_vc8.vcproj

rm -f $prefix

gzip -f $filename
