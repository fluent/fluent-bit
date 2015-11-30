#!/bin/sh

set -eu

CONFIG_H='include/mbedtls/config.h'

if [ -r $CONFIG_H ]; then :; else
    echo "$CONFIG_H not found" >&2
    exit 1
fi

if grep -i cmake Makefile >/dev/null; then
    echo "Not compatible with CMake" >&2
    exit 1
fi

doit()
{
    NAME="$1"
    FILE="$2"

    echo "$NAME:"

    cp $CONFIG_H ${CONFIG_H}.bak
    cp "$FILE" include/mbedtls/config.h

    {
        scripts/config.pl unset MBEDTLS_NET_C || true
        scripts/config.pl unset MBEDTLS_TIMING_C || true
        scripts/config.pl unset MBEDTLS_FS_IO || true
    } >/dev/null 2>&1

    CC=arm-none-eabi-gcc AR=arm-none-eabi-ar LD=arm-none-eabi-ld \
        CFLAGS='-Wa,--noexecstack -Os -march=armv7-m -mthumb' \
        make clean lib >/dev/null

    OUT="size-${NAME}.txt"
    arm-none-eabi-size -t library/libmbed*.a > "$OUT"
    head -n1 "$OUT"
    tail -n1 "$OUT"

    cp ${CONFIG_H}.bak $CONFIG_H
}

# creates the yotta config
yotta/create-module.sh >/dev/null

doit default    include/mbedtls/config.h.bak
doit yotta      yotta/module/mbedtls/config.h
doit thread     configs/config-thread.h
doit ecc        configs/config-suite-b.h
doit psk        configs/config-ccm-psk-tls1_2.h
