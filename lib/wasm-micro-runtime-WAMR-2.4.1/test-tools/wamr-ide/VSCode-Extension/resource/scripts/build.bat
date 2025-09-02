@REM Copyright (C) 2019 Intel Corporation.  All rights reserved.
@REM SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

@echo off

@REM start a container, mount current project path to container/mnt
docker run --rm --name=wasm-toolchain-ctr ^
                -it -v "%cd%":/mnt ^
                --env=PROJ_PATH="%cd%" ^
                wasm-toolchain:%2  ^
                /bin/bash -c "./build_wasm.sh %1"
