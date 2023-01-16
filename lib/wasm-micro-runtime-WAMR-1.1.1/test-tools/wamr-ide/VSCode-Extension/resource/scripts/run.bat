@REM Copyright (C) 2019 Intel Corporation.  All rights reserved.
@REM SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

@echo off

docker run --rm -it --name=wasm-debug-server-ctr ^
           -v "%cd%":/mnt ^
           wasm-debug-server:1.0 ^
           /bin/bash -c "./run.sh %1"
