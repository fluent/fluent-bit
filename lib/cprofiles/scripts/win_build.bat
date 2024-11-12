setlocal
git submodule update --init --recursive
cd build
cmake -G "NMake Makefiles"  -DCPROF_TESTS=On ..\
cmake --build .
endlocal
