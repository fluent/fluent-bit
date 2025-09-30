#!/usr/bin/env bash

# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

CUR_DIR=$PWD

pushd ${CUR_DIR}/.. > /dev/null 2>&1
./build.sh
popd > /dev/null 2>& 1

cd ${CUR_DIR}
rm -f test
go build test.go
./test
