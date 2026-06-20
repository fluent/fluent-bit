@REM Copyright (C) 2019 Intel Corporation.  All rights reserved.
@REM SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

@echo off

docker run --rm -it --name=wasm-debug-server-ctr ^
           -v "%cd%":/mnt ^
           -p 1234:1234 ^
           wasm-debug-server:%2 ^
           /bin/bash -c "./debug.sh %1 %3"
