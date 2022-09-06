@REM Copyright (C) 2019 Intel Corporation.  All rights reserved.
@REM SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

@echo off
set target_name=%1

docker run -it --name=wasm-debug-server-ctr ^
           -v "%cd%":/mnt ^
           -p 1234:1234 ^
           wasm-debug-server:1.0 ^
           /bin/bash -c "./debug.sh %target_name%"

@REM stop and remove wasm-debug-server-container
docker stop wasm-debug-server-ctr && docker rm wasm-debug-server-ctr
