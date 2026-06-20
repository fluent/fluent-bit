setlocal
git submodule update --init --recursive
cd build
cmake -G "NMake Makefiles"  -DCMT_TESTS=On ..\
cmake --build .
endlocal
