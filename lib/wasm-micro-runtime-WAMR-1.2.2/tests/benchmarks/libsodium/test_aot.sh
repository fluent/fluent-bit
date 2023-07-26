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
                 secretbox secretstream shorthash sign siphashx24 sodium_core sodium_utils2 \
                 sodium_utils3 sodium_utils sodium_version stream2 stream3 stream4 stream verify1 \
                 xchacha20"

readonly OUT_DIR=$PWD/libsodium/zig-out/bin
readonly REPORT=$PWD/report.txt
readonly IWASM_CMD=$PWD/../../../product-mini/platforms/linux/build/iwasm

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

echo -en "\t\t\t\t\t\tnative\tiwasm-aot\n" >> $REPORT

for t in $libsodium_CASES
do
    print_bench_name $t

    echo "run $t with native..."
    echo -en "\t" >> $REPORT
    ./${t} | awk -F '-' 'BEGIN{FIELDWIDTHS="10"}{ORS=""; print $1 / 1000000.0}' >> $REPORT

    echo "run $t with iwasm aot..."
    echo -en "\t  \t" >> $REPORT
    $IWASM_CMD ${t}.aot | awk -F '-' 'BEGIN{FIELDWIDTHS="10"}{ORS=""; print $1 / 1000000.0}' >> $REPORT

    echo -en "\n" >> $REPORT
done

