#!/bin/bash

mkdir build

ret=$?
if [ $ret -ne 0 ]
then
    exit $ret
fi

cd build

ret=$?
if [ $ret -ne 0 ]
then
    exit $ret
fi

if [ $1 = "cpp11" ]
then
    cpp11="-DMSGPACK_CXX11=ON"
else
    cpp11=""
fi

if [ $2 = "32" ]
then
    bit32="-DMSGPACK_32BIT=ON"
else
    bit32=""
fi

if [ $3 = "boost" ]
then
    boost="-DMSGPACK_BOOST=ON"
else
    boost=""
fi

if [ "$4" != "" ]
then
    boost_dir="-DMSGPACK_BOOST_DIR=$4"
else
    boost_dir=""
fi

if [ "$5" = "OFF" ]
then
    shared="-DMSGPACK_ENABLE_SHARED=OFF"
else
    shared=""
fi

cmake $cpp11 $bit32 $boost $boost_dir $shared -DMSGPACK_CHAR_SIGN=${CHAR_SIGN} -DMSGPACK_DEFAULT_API_VERSION=${API_VERSION} ..

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

make test

ret=$?
if [ $ret -ne 0 ]
then
    exit $ret
fi

make install DESTDIR=`pwd`/install

ret=$?
if [ $ret -ne 0 ]
then
    exit $ret
fi

if [ "$2" != "32" ]
then
    ctest -T memcheck | tee memcheck.log

    ret=${PIPESTATUS[0]}
    if [ $ret -ne 0 ]
    then
        exit $ret
    fi
    cat memcheck.log | grep "Memory Leak" > /dev/null
    ret=$?
    if [ $ret -eq 0 ]
    then
        exit 1
    fi
fi

exit 0
