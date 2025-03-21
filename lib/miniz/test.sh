#!/bin/bash

set -e

. amalgamate.sh

cat << "EOF" > miniz_export.h
#ifndef MINIZ_EXPORT
#define MINIZ_EXPORT
#endif
EOF
g++ tests/miniz_tester.cpp tests/timer.cpp amalgamation/miniz.c -o miniz_tester -I. -ggdb -O2

for i in 1 2 3 4 5 6
do
    gcc examples/example$i.c amalgamation/miniz.c -o example$i -lm -I. -ggdb
done

mkdir -p test_scratch
if ! test -e "test_scratch/linux-4.8.11"
then
    cd test_scratch
    wget https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.8.11.tar.xz -O linux-4.8.11.tar.xz
    tar xf linux-4.8.11.tar.xz
    cd ..
fi

cd test_scratch
../miniz_tester -v a linux-4.8.11
../miniz_tester -v -r a linux-4.8.11
../miniz_tester -v -b -r a linux-4.8.11
../miniz_tester -v -a a linux-4.8.11

mkdir -p large_file
truncate -s 5G large_file/lf
../miniz_tester -v -a a large_file
