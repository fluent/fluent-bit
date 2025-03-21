#!/bin/bash -e

# Copyright (C) 2019-21 Intel Corporation and others.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

ESP32_TARGET="esp32"
ESP32C3_TARGET="esp32c3"
ESP32S3_TARGET="esp32s3"

usage ()
{
        echo "USAGE:"
        echo "$0 $ESP32_TARGET|$ESP32C3_TARGET|$ESP32S3_TARGET"
        echo "Example:"
        echo "        $0 $ESP32_TARGET"
        echo "        $0 $ESP32C3_TARGET"
        echo "        $0 $ESP32S3_TARGET"
        exit 1
}

if [ $# != 1 ] ; then
        usage
fi

TARGET=$1

if [[ -z "${WAMR_PATH}" ]]; then
        export WAMR_PATH=$PWD/../../..
fi

rm -rf build
idf.py set-target $TARGET
idf.py build
idf.py flash

