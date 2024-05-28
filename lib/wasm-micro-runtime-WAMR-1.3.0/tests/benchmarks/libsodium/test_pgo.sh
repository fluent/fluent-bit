#!/bin/bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

libsodium_CASES="aead_aes256gcm2 aead_aes256gcm aead_chacha20poly13052 aead_chacha20poly1305 \
                 aead_xchacha20poly1305 auth2 auth3 auth5 auth6 auth7 auth box2 box7 box8 \
                 box_easy2 box_easy box_seal box_seed box chacha20 codecs core1 core2 core3 \
                 core4 core5 core6 core_ed25519 core_ristretto255 ed25519_convert generichash2 \
                 generichash3 generichash hash3 hash kdf keygen kx metamorphic misuse \
                 onetimeauth2 onetimeauth7 onetimeauth pwhash_argon2id pwhash_argon2i \
                 pwhash_scrypt_ll pwhash_scrypt randombytes scalarmult2 scalarmult5 \
                 scalarmult6 scalarmult7 scalarmult8 scalarmult_ed25519 scalarmult_ristretto255 \
                 scalarmult secretbox2 secretbox7 secretbox8 secretbox_easy2 secretbox_easy \
                 secretbox secretstream_xchacha20poly1305 shorthash sign siphashx24 sodium_core \
                 sodium_utils2 sodium_utils stream2 stream3 stream4 stream verify1 xchacha20"

PLATFORM=$(uname -s | tr A-Z a-z)

readonly OUT_DIR=$PWD/libsodium/zig-out/bin
readonly REPORT=$PWD/report.txt
if [ "$1" = "--sgx" ] && [ "$PLATFORM" = "linux" ]; then
    readonly IWASM_CMD="$PWD/../../../product-mini/platforms/${PLATFORM}-sgx/enclave-sample/iwasm"
    readonly WAMRC_CMD="$PWD/../../../wamr-compiler/build/wamrc -sgx"
else
    readonly IWASM_CMD="$PWD/../../../product-mini/platforms/${PLATFORM}/build/iwasm"
    readonly WAMRC_CMD="$PWD/../../../wamr-compiler/build/wamrc"
fi
readonly TIME=/usr/bin/time

BENCH_NAME_MAX_LEN=20

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
for t in $libsodium_CASES
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

# run benchmarks
cd $OUT_DIR

echo -en "\t\t\t\t\t\tnative\tiwasm-aot\tiwasm-aot-pgo\n" >> $REPORT

for t in $libsodium_CASES
do
    print_bench_name $t

    echo "run $t with native..."
    echo -en "\t" >> $REPORT
    if [[ $t != "sodium_utils2" ]]; then
        ./${t} | awk '{printf "%-10.2f", $0/1000000.0}' >> $REPORT
    else
        # sodium_utils2 doesn't print the result,
        # use time command to get result instead
        $TIME -f "real-%e-time" ./${t} 2>&1 | grep "real-.*-time" |
            awk -F '-' '{printf "%-10.2f", $2}' >> $REPORT
    fi

    echo "run $t with iwasm aot..."
    echo -en "\t  \t" >> $REPORT
    if [[ $t != "sodium_utils2" ]]; then
        $IWASM_CMD ${t}.aot | awk '{printf "%-10.2f", $0/1000000.0}' >> $REPORT
    else
        # sodium_utils2 doesn't print the result,
        # use time command to get result instead
        $TIME -f "real-%e-time" $IWASM_CMD ${t}.aot 2>&1 | grep "real-.*-time" |
            awk -F '-' '{printf "%-10.2f", $2}' >> $REPORT
    fi

    echo "run $t with iwasm aot opt..."
    echo -en "\t  \t" >> $REPORT
    if [[ $t != "sodium_utils2" ]]; then
        $IWASM_CMD ${t}_opt.aot | awk '{printf "%-10.2f", $0/1000000.0}' >> $REPORT
    else
        # sodium_utils2 doesn't print the result,
        # use time command to get result instead
        $TIME -f "real-%e-time" $IWASM_CMD ${t}_opt.aot 2>&1 | grep "real-.*-time" |
            awk -F '-' '{printf "%-10.2f", $2}' >> $REPORT
    fi

    echo -en "\n" >> $REPORT
done

