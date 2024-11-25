
## Use clang compiler

The recommended method to build a WASM binary is to use clang compiler ```clang-8```. You can refer to [apt.llvm.org](https://apt.llvm.org) for the detailed instructions. Here are referenced steps to install clang-8 in Ubuntu 16.04 and Ubuntu 18.04.

(1) Add source to your system source list from llvm website

For Ubuntu 16.04, add the following lines to /etc/apt/sources.list:

``` Bash
deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial main
deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial main
# 8
deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-8 main
deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-8 main
# 9
deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-9 main
deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-9 main
```

For Ubuntu 18.04, add the following lines to /etc/apt/sources.list:

``` Bash
# i386 not available
deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic main
deb-src http://apt.llvm.org/bionic/ llvm-toolchain-bionic main
# 8
deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-8 main
deb-src http://apt.llvm.org/bionic/ llvm-toolchain-bionic-8 main
# 9
deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-9 main
deb-src http://apt.llvm.org/bionic/ llvm-toolchain-bionic-9 main
```

(2) Download and install clang-8 tool-chain using following commands:

``` Bash
sudo wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key|sudo apt-key add -
# Fingerprint: 6084 F3CF 814B 57C1 CF12 EFD5 15CF 4D18 AF4F 7421
sudo apt-get update
sudo apt-get install llvm-8 lld-8 clang-8
```

(3) Create a soft link under /usr/bin:

``` Bash
cd /usr/bin
sudo ln -s wasm-ld-8 wasm-ld
```

(4) Use the clang-8 command below to build the WASM C source code into the WASM binary.

``` Bash
clang-8 --target=wasm32 -O3 \
        -z stack-size=4096 -Wl,--initial-memory=65536 \
        -Wl,--allow-undefined,--export=main \
        -Wl,--strip-all,--no-entry -nostdlib \
        -o test.wasm test.c
```

You will get ```test.wasm``` which is the WASM app binary.

## Using Docker

Another method availble is using [Docker](https://www.docker.com/). We assume you've already configured Docker (see Platform section above) and have a running interactive shell. Currently the Dockerfile only supports compiling apps with clang, with Emscripten planned for the future.

Use the clang-8 command below to build the WASM C source code into the WASM binary.

``` Bash
clang-8 --target=wasm32 -O3 \
        -z stack-size=4096 -Wl,--initial-memory=65536 \
        -Wl,--allow-undefined,--export=main \
        -Wl,--strip-all,--no-entry -nostdlib \
        -o test.wasm test.c
```

You will get ```test.wasm``` which is the WASM app binary.

