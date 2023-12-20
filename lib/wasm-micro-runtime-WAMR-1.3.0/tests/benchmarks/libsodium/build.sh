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
                 sodium_utils2 sodium_utils3 sodium_utils sodium_version stream2 stream3 stream4 \
                 stream verify1 xchacha20"

PLATFORM=$(uname -s | tr A-Z a-z)

readonly WAMRC_CMD=$PWD/../../../wamr-compiler/build/wamrc
readonly OUT_DIR=$PWD/libsodium/zig-out/bin

if [ ! -d libsodium ]; then
    git clone https://github.com/jedisct1/libsodium.git
    cd libsodium
    git checkout 1.0.19
    cd ..
fi

cd libsodium

echo "Build libsodium native"
zig build -Doptimize=ReleaseFast -Denable_benchmarks=true

echo "Build libsodium wasm32-wasi"
zig build -Doptimize=ReleaseFast -Denable_benchmarks=true -Dtarget=wasm32-wasi

for case in ${libsodium_CASES}
do
    ${WAMRC_CMD} -o ${OUT_DIR}/${case}.aot ${OUT_DIR}/${case}.wasm
    if [ "$?" != 0 ]; then
        echo -e "Error while compiling ${case}.wasm to ${case}.aot"
        exit
    fi

    if [[ ${PLATFORM} == "linux" ]]; then
        ${WAMRC_CMD} --enable-segue -o ${OUT_DIR}/${case}_segue.aot ${OUT_DIR}/${case}.wasm
        if [ "$?" != 0 ]; then
            echo -e "Error while compiling ${case}.wasm to ${case}_segue.aot"
            exit
        fi
    fi
done
