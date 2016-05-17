#!/bin/sh

./bootstrap
ret=$?
if [ $ret -ne 0 ]
then
    exit $ret
fi

if [ $1 = "cpp11" ]
then
    cpp11="-std=c++11"
else
    cpp11=""
fi

if [ $2 = "32" ]
then
    bit32="-m32"
else
    bit32=""
fi

if [ $3 = "boost" ]
then
    boost="-DMSGPACK_USE_BOOST"
else
    boost=""
fi

./configure CFLAGS="$bit32 -f${CHAR_SIGN}-char" CXXFLAGS="$bit32 -f${CHAR_SIGN}-char $cpp11 $boost -I$4 -DMSGPACK_DEFAULT_API_VERSION=${API_VERSION}"

ret=$?
if [ $ret -ne 0 ]
then
    exit $ret
fi

make

ret=$?
if [ $ret -ne 0 ]
then
    exit $ret
fi

make check

ret=$?
if [ $ret -ne 0 ]
then
    exit $ret
fi

make install DESTDIR=`pwd`/build/install

ret=$?
if [ $ret -ne 0 ]
then
    exit $ret
fi

exit 0
