@REM Copyright (C) 2019 Intel Corporation.  All rights reserved.
@REM SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

@echo off

@REM # create mount directory on host

if not exist host_mnt (
    md host_mnt
)

docker run -it ^
           -v %cd%\host_mnt:/mnt ^
           --name wasm-toolchain-provider-ctr ^
           wasm-toolchain-provider:1.0 ^
           /bin/bash