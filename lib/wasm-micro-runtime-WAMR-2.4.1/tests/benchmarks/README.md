# WAMR test benchmarks

This folder contains test benchmarks for wamr.

## Build and Run

Refer to the `README.md` under each folder for how to build and run the benchmark.

## Install `llvm-profdata`

> PS: the `llvm-profdata` vesion needs to be the same major version with llvm libraries used to build wamrc.

The tool `llvm-profdata` is used when running the `test_pgo.sh` script under the benchmark folder. There are two ways to install it:

1. Refer to https://apt.llvm.org/, e.g. in Ubuntu 20.04, add lines below to /etc/apt/source.list

```bash
deb http://apt.llvm.org/focal/ llvm-toolchain-focal main
deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal main
# 15
deb http://apt.llvm.org/focal/ llvm-toolchain-focal-15 main
deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-15 main
# 18
deb http://apt.llvm.org/focal/ llvm-toolchain-focal-18 main
deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-18 main
```

Then run `sudo apt update`, `sudo apt install llvm`. And after installing:

```bash
cd /usr/bin
sudo ln -s llvm-profdata-18 llvm-profdata
```

2. Build manually

```bash
git clone --depth 1 --branch release/18.x https://github.com/llvm/llvm-project.git
cd llvm-project
mkdir build && cd build
cmake ../llvm \
    -DCMAKE_BUILD_TYPE:STRING="Release" \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DLLVM_APPEND_VC_REV:BOOL=ON \
    -DLLVM_BUILD_EXAMPLES:BOOL=OFF \
    -DLLVM_BUILD_LLVM_DYLIB:BOOL=OFF \
    -DLLVM_BUILD_TESTS:BOOL=OFF \
    -DLLVM_CCACHE_BUILD:BOOL=ON \
    -DLLVM_ENABLE_BINDINGS:BOOL=OFF \
    -DLLVM_ENABLE_IDE:BOOL=OFF \
    -DLLVM_ENABLE_LIBEDIT=OFF \
    -DLLVM_ENABLE_TERMINFO:BOOL=OFF \
    -DLLVM_ENABLE_ZLIB:BOOL=ON \
    -DLLVM_INCLUDE_BENCHMARKS:BOOL=OFF \
    -DLLVM_INCLUDE_DOCS:BOOL=OFF \
    -DLLVM_INCLUDE_EXAMPLES:BOOL=OFF \
    -DLLVM_INCLUDE_UTILS:BOOL=OFF \
    -DLLVM_INCLUDE_TESTS:BOOL=OFF \
    -DLLVM_BUILD_TESTS:BOOL=OFF \
    -DLLVM_OPTIMIZED_TABLEGEN:BOOL=ON \
    -DLLVM_ENABLE_LIBXML2:BOOL=OFF \
    -DLLVM_TARGETS_TO_BUILD:STRING="X86" \
    -DLLVM_INCLUDE_TOOLS:BOOL=ON \
    -G'Ninja'
ninja -j 8
# tool `llvm-profdata` is generated under this folder.
```
