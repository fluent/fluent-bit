@REM Copyright (C) 2019 Intel Corporation.  All rights reserved.
@REM SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

@echo off

call docker --version>nul 2>nul
IF %ERRORLEVEL% GTR 0 (
    echo "Docker is not installed, please install docker desktop firstly."
    echo
    exit /b 1
)

call docker images>nul 2>nul
IF %ERRORLEVEL% GTR 0 (
    echo "Docker is not ready, please launch docker desktop firstly."
    echo
    exit /b 2
)

echo "Prepare to clean up the docker containers..."

call docker inspect wasm-toolchain-ctr>nul 2>nul
IF %ERRORLEVEL% EQU 0 (
    echo "Stopping and removing wasm-toolchain-ctr container..."
    docker rm -f wasm-toolchain-ctr>nul 2>nul
    echo "Done."
)

call docker inspect wasm-debug-server-ctr>nul 2>nul
IF %ERRORLEVEL% EQU 0 (
    echo "Stopping and removing wasm-debug-server-ctr container..."
    docker rm -f wasm-debug-server-ctr>nul 2>nul
    echo "Done."
)

echo "Clean up docker containers successfully."
