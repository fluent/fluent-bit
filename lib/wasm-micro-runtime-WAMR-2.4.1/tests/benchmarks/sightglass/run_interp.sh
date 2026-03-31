#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

CUR_DIR=$PWD
OUT_DIR=$CUR_DIR/out
REPORT=$CUR_DIR/report.txt
TIME=/usr/bin/time

PLATFORM=$(uname -s | tr A-Z a-z)
IWASM_CMD=$CUR_DIR/../../../product-mini/platforms/${PLATFORM}/build/iwasm

BENCH_NAME_MAX_LEN=20

SHOOTOUT_CASES="base64 fib2 gimli heapsort matrix memmove nestedloop \
                nestedloop2 nestedloop3 random seqhash sieve strchr \
                switch2"

rm -f $REPORT
touch $REPORT

function print_bench_name()
{
    name=$1
    echo -en "$name" >> $REPORT
    name_len=${#name}
    if [ $name_len -lt $BENCH_NAME_MAX_LEN ]
    then
        spaces=$(( $BENCH_NAME_MAX_LEN - $name_len ))
        for i in $(eval echo "{1..$spaces}"); do echo -n " " >> $REPORT; done
    fi
}

echo "Start to run cases, the result is written to report.txt"

#run benchmarks
cd $OUT_DIR
echo -en "\t\t\t\t\t  native\tiwasm-interp\n" >> $REPORT

for t in $SHOOTOUT_CASES
do
    print_bench_name $t

    echo "run $t with native .."
    echo -en "\t" >> $REPORT
    $TIME -f "real-%e-time" ./${t}_native 2>&1 | grep "real-.*-time" | awk -F '-' '{ORS=""; print $2}' >> $REPORT

    echo "run $t with iwasm interp .."
    echo -en "\t" >> $REPORT
    $TIME -f "real-%e-time" $IWASM_CMD ${t}.wasm 2>&1 | grep "real-.*-time" | awk -F '-' '{ORS=""; print $2}' >> $REPORT

    echo -en "\n" >> $REPORT
done
