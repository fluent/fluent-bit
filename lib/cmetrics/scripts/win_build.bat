@echo off
setlocal
git submodule update --init --recursive
if errorlevel 1 exit /b %errorlevel%
cmake -S . -B build -G "NMake Makefiles" -DCMT_TESTS=On -DCMAKE_BUILD_TYPE=Debug
if errorlevel 1 exit /b %errorlevel%
cmake --build build
endlocal & exit /b %errorlevel%
