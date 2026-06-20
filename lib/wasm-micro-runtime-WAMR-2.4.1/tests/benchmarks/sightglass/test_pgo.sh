#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

CUR_DIR=$PWD
OUT_DIR=$CUR_DIR/out
REPORT=$CUR_DIR/report.txt
TIME=/usr/bin/time

PLATFORM=$(uname -s | tr A-Z a-z)
if [ "$1" = "--sgx" ] && [ "$PLATFORM" = "linux" ]; then
    IWASM_CMD="$CUR_DIR/../../../product-mini/platforms/${PLATFORM}-sgx/enclave-sample/iwasm"
    WAMRC_CMD="$CUR_DIR/../../../wamr-compiler/build/wamrc -sgx"
else
    IWASM_CMD="$CUR_DIR/../../../product-mini/platforms/${PLATFORM}/build/iwasm"
    WAMRC_CMD="$CUR_DIR/../../../wamr-compiler/build/wamrc"
fi

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

pushd $OUT_DIR > /dev/null 2>&1
for t in $SHOOTOUT_CASES
do
    if [ ! -e "${t}.wasm" ]; then
        echo "${t}.wasm doesn't exist, please run build.sh first"
        exit
    fi

    echo ""
    echo "Compile ${t}.wasm to ${t}.aot .."
    ${WAMRC_CMD} -o ${t}.aot ${t}.wasm

    echo ""
    echo "Compile ${t}.wasm to ${t}_pgo.aot .."
    ${WAMRC_CMD} --enable-llvm-pgo -o ${t}_pgo.aot ${t}.wasm

    echo ""
    echo "Run ${t}_pgo.aot to generate the raw profile data .."
    ${IWASM_CMD} --gen-prof-file=${t}.profraw --dir=. ${t}_pgo.aot

    echo ""
    echo "Merge the raw profile data to ${t}.profdata .."
    rm -f ${t}.profdata && llvm-profdata merge -output=${t}.profdata ${t}.profraw

    echo ""
    echo "Compile ${t}.wasm to ${t}_opt.aot with the profile data .."
    ${WAMRC_CMD} --use-prof-file=${t}.profdata -o ${t}_opt.aot ${t}.wasm
done
popd > /dev/null 2>&1

echo "Start to run cases, the result is written to report.txt"

#run benchmarks
cd $OUT_DIR
echo -en "\t\t\t\t\t  native\tiwasm-aot\tiwasm-aot-pgo\n" >> $REPORT

for t in $SHOOTOUT_CASES
do
    print_bench_name $t

    echo "run $t with native .."
    echo -en "\t" >> $REPORT
    $TIME -f "real-%e-time" ./${t}_native 2>&1 | grep "real-.*-time" | awk -F '-' '{ORS=""; print $2}' >> $REPORT

    echo "run $t with iwasm aot .."
    echo -en "\t" >> $REPORT
    $TIME -f "real-%e-time" $IWASM_CMD ${t}.aot 2>&1 | grep "real-.*-time" | awk -F '-' '{ORS=""; print $2}' >> $REPORT

    echo "run $t with iwasm aot opt .."
    echo -en "\t" >> $REPORT
    $TIME -f "real-%e-time" $IWASM_CMD ${t}_opt.aot 2>&1 | grep "real-.*-time" | awk -F '-' '{ORS=""; print $2}' >> $REPORT

    echo -en "\n" >> $REPORT
done
