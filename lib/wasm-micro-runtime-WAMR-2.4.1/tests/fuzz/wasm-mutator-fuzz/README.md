# WAMR fuzz test framework

## Install wasm-tools

Download the release suitable for your specific platform from https://github.com/bytecodealliance/wasm-tools/releases/latest, unpack it, and add the executable wasm-tools to the `PATH`. Then, you should be able to verify that the installation was successful by using the following command:

```bash
$ wasm-tools --version
# Or learn subcommands with
$ wasm-tools help
```

## Install clang Toolchain

Refer to: https://apt.llvm.org/ and ensure that you have clang installed.

```bash
$ clang --version

$ clang++ --version
```

## Build

```bash
# Without custom mutator (libfuzzer modify the buffer randomly)
$ cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=./clang_toolchain.cmake -DLLVM_DIR=<llvm_install_dir>/lib/cmake/llvm

# TBC: if `wasm-tools mutate` is supported or not
# Or With custom mutator (wasm-tools mutate)
$ cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=./clang_toolchain.cmake -DLLVM_DIR=<llvm_install_dir>/lib/cmake/llvm -DCUSTOM_MUTATOR=1

# Then
$ cmake --build build
```

## Manually generate wasm file in build

````bash
# wasm-tools smith generate some valid wasm file
# The generated wasm file is in corpus_dir under build
# N - Number of files to be generated
$ ./smith_wasm.sh N

# running
``` bash
$ ./build/wasm-mutator/wasm_mutator_fuzz ./build/CORPUS_DIR

$ ./build/aot-compiler/aot_compiler_fuzz ./build/CORPUS_DIR
````

## Fuzzing Server

```shell
1. Installation Dependent Environment
$ cd server
$ pip install -r requirements.txt

2. Database Migration
$ python3 app/manager.py db init
$ python3 app/manager.py db migrate
$ python3 app/manager.py db upgrade

3. Change localhost to your machine's IP address
$ cd ../portal
$ vim .env   # Change localhost to your machine's IP address  # http://<ip>:16667

4. Run Server and Portal
$ cd ..   # Switch to the original directory
If you want to customize the front-end deployment port:  # defaut 9999
    $ vim .env # Please change the portal_port to the port you want to use

The server is deployed on port 16667 by default, If you want to change the server deployment port:
    $ vim .env # Please change the server_port to the port you want to use
    $ vim portal/.env # Please change the VITE_SERVER_URL to the port you want to use  # http://ip:<port>


If your network needs to set up a proxy
    $ vim .env # Change proxy to your proxy address

$ docker-compose up --build -d
Wait for completion, Access the port set by env
```
