@REM Copyright (C) 2019 Intel Corporation.  All rights reserved.
@REM SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

@echo off
set DIR_ROOT=%cd%\..

echo "=== Verify the vscode status ==="
call code --version
IF %ERRORLEVEL%==0 (
   echo "vscode is ready."
) ELSE (
   echo "VSCode is not installed, please install firstly."
   exit /b 1
)

echo "=== Verify the docker status ==="
call docker --version
IF %ERRORLEVEL%==0 (
   echo "docker is ready."
) ELSE (
   echo "Docker is not installed, please install firstly."
   exit /b 1
)

cd %DIR_ROOT%\WASM-Debug-Server\Docker
call docker build -t wasm-debug-server:1.0 .
IF %ERRORLEVEL%==0 (
   echo "wasm-debug-server image is ready."
) ELSE (
   echo "build wasm-debug-server image failed."
   exit /b 1
)

cd %DIR_ROOT%\WASM-Toolchain\Docker
call docker build -t wasm-toolchain:1.0 .
IF %ERRORLEVEL%==0 (
   echo "wasm-toolchain image is ready."
) ELSE (
   echo "build wasm-toolchain image failed."
   exit /b 1
)