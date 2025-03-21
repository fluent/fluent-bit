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
readonly IWASM_CMD=$PWD/../../../product-mini/platforms/${PLATFORM}/build/iwasm
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

# run benchmarks
cd $OUT_DIR

if [[ ${PLATFORM} == "linux" ]]; then
    echo -en "\t\t\t\t\t\tnative\tiwasm-aot\tiwasm-aot-segue\n" >> $REPORT
else
    echo -en "\t\t\t\t\t\tnative\tiwasm-aot\n" >> $REPORT
fi

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

    if [[ ${PLATFORM} == "linux" ]]; then
        echo "run $t with iwasm aot segue..."
        echo -en "\t  \t" >> $REPORT
        if [[ $t != "sodium_utils2" ]]; then
            $IWASM_CMD ${t}_segue.aot | awk '{printf "%.2f", $0/1000000.0}' >> $REPORT
        else
            # sodium_utils2 doesn't print the result,
            # use time command to get result instead
            $TIME -f "real-%e-time" $IWASM_CMD ${t}_segue.aot 2>&1 | grep "real-.*-time" |
                awk -F '-' '{printf "%.2f", $2}' >> $REPORT
        fi
    fi

    echo -en "\n" >> $REPORT
done

