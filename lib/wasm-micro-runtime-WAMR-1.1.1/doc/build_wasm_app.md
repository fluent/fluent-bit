# Build WASM applications

Prepare WASM building environments
==================================

For C and C++, WASI-SDK version 12.0+ is the major tool supported by WAMR to build WASM applications. Also, we can use [Emscripten SDK (EMSDK)](https://github.com/emscripten-core/emsdk), but it is not recommended. And there are some other compilers such as the standard clang compiler, which might also work [here](./other_wasm_compilers.md).

To install WASI SDK, please download the [wasi-sdk release](https://github.com/CraneStation/wasi-sdk/releases) and extract the archive to default path `/opt/wasi-sdk`.

The official *wasi-sdk release* doesn't fully support *latest 128-bit SIMD spec* yet. WAMR provides a script in [build-wasi-sdk](../test-tools/build-wasi-sdk/) to generate
another wasi-sdk with *llvm-13* from source code and installs it at *../test-tools/wasi-sdk*. If you plan to build WASM applications with *latest 128-bit SIMD*, please use it instead of the official release.

And [sample workloads](../samples/workload) are using the self-compiled wasi-sdk.

For [AssemblyScript](https://github.com/AssemblyScript/assemblyscript), please refer to [AssemblyScript quick start](https://www.assemblyscript.org/quick-start.html) and [AssemblyScript compiler](https://www.assemblyscript.org/compiler.html#command-line-options) for how to install `asc` compiler and build WASM applications.

For Rust, please refer to [Install Rust and Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) to install *cargo*, *rustc* and *rustup*. By default they are under ~/.cargo/bin.

And then run such a command to install `wasm32-wasi` target.

``` bash
$ rustup target add wasm32-wasi
```

To build WASM applications, run

``` bash
$ cargo build --target wasm32-wasi
```

The output files are under `target/wasm32-wasi`.

To build a release version

``` bash
$ cargo build --release --target wasm32-wasi
```


Build WASM applications with wasi-sdk
=====================================

You can write a simple ```test.c``` as the first sample.

``` C
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    char *buf;

    printf("Hello world!\n");

    buf = malloc(1024);
    if (!buf) {
        printf("malloc buf failed\n");
        return -1;
    }

    printf("buf ptr: %p\n", buf);

    sprintf(buf, "%s", "1234\n");
    printf("buf: %s", buf);

    free(buf);
    return 0;
}
```

To build the source file to WASM bytecode, we can input the following command:

``` Bash
/opt/wasi-sdk/bin/clang -O3 -o test.wasm test.c
```

## 1. wasi-sdk options

There are some useful options that are used to compile C/C++ to Wasm (for a full introduction, please refer to [clang command line argument reference](https://clang.llvm.org/docs/ClangCommandLineReference.html) and [wasm-ld command line argument manual](https://lld.llvm.org/WebAssembly.html)):

- **-nostdlib** Do not use the standard system startup files or libraries when linking. In this mode, the **libc-builtin** library of WAMR must be built to run the wasm app, otherwise, the **libc-wasi** library must be built. You can specify **-DWAMR_BUILD_LIBC_BUILTIN=1** or **-DWAMR_BUILD_LIBC_WASI=1** for CMake to build WAMR with libc-builtin support or libc-wasi support.

- **-Wl,--no-entry** Do not output any entry point

- **-Wl,--export=\<value\>** Force a symbol to be exported, e.g. **-Wl,--export=foo** to export foo function

- **-Wl,--export-all** Export all symbols (normally combined with --no-gc-sections)

- **-Wl,--initial-memory=\<value\>** Initial size of the linear memory, which must be a multiple of 65536

- **-Wl,--max-memory=\<value\>** Maximum size of the linear memory, which must be a multiple of 65536

- **-z stack-size=\<vlaue\>** The auxiliary stack size, which is an area of linear memory, must be smaller than the initial memory size.

- **-Wl,--strip-all** Strip all symbols

- **-Wl,--shared-memory** Use shared linear memory

- **-Wl,--allow-undefined** Allow undefined symbols in linked binary

- **-Wl,--allow-undefined-file=\<value\>** Allow symbols listed in \<file\> to be undefined in linked binary

- **-pthread** Support POSIX threads in generated code

For example, we can build the wasm app with the command:

``` Bash
/opt/wasi-sdk/bin/clang -O3 -nostdlib \
    -z stack-size=8192 -Wl,--initial-memory=65536 \
    -o test.wasm test.c \
    -Wl,--export=main -Wl,--export=__main_argc_argv \
    -Wl,--export=__heap_base -Wl,--export=__data_end \
    -Wl,--no-entry -Wl,--strip-all -Wl,--allow-undefined
```
to generate a wasm binary with nostdlib mode, the auxiliary stack size is 8192 bytes, initial memory size is 64 KB,  main function, heap base global and data end global are exported, no entry function is generated (no _start function is exported), and all symbols are stripped. Note that it is nostdlib mode, so libc-builtin should be enabled by runtime embedder or iwasm (with `cmake -DWAMR_BUILD_LIBC_BUILT=1`, enabled by iwasm in Linux by default).

If we want to build the wasm app with wasi mode, we may build the wasm app with the command:

```bash
/opt/wasi-sdk/bin/clang -O3 \
    -z stack-size=8192 -Wl,--initial-memory=65536 \
    -o test.wasm test.c \
    -Wl,--export=__heap_base -Wl,--export=__data_end \
    -Wl,--strip-all
```

to generate a wasm binary with wasi mode, the auxiliary stack size is 8192 bytes, initial memory size is 64 KB,  heap base global and data end global are exported, wasi entry function exported (_start function), and all symbols are stripped. Note that it is wasi mode, so libc-wasi should be enabled by runtime embedder or iwasm (with `cmake -DWAMR_BUILD_LIBC_WASI=1`, enabled by iwasm in Linux by default), and normally no need to export main function, by default _start function is executed by iwasm.

## 2. How to reduce the footprint?

Firstly if libc-builtin (-nostdlib) mode meets the requirements, e.g. there are no file io operations in wasm app, we should build the wasm app with -nostdlib option as possible as we can, since the compiler doesn't build the libc source code into wasm bytecodes, which greatly reduces the binary size.

### (1) Methods to reduce the libc-builtin (-nostdlib) mode footprint

- export \_\_heap_base global and \_\_data_end global
  ```bash
  -Wl,--export=__heap_base -Wl,--export=__data_end
  ```
  If the two globals are exported, and there are no memory.grow and memory.size opcodes (normally nostdlib mode doesn't introduce these opcodes since the libc malloc function isn't built into wasm bytecode), WAMR runtime will truncate the linear memory at the place of \__heap_base and append app heap to the end, so we don't need to allocate the memory specified by `-Wl,--initial-memory=n` which must be at least 64 KB. This is helpful for some embedded devices whose memory resource might be limited.

- reduce auxiliary stack size

  The auxiliary stack is an area of linear memory, normally the size is 64 KB by default which might be a little large for embedded devices and partly used, we can use `-z stack-size=n` to set its size.

- use -O3 and -Wl,--strip-all

- reduce app heap size when running iwasm

  We can pass `--heap-size=n` option to set the maximum app heap size for iwasm, by default it is 16 KB. For the runtime embedder, we can set the `uint32_t heap_size` argument when calling API ` wasm_runtime_instantiate`.

- reduce wasm operand stack size when running iwasm

  WebAssembly is a binary instruction format for a stack-based virtual machine, which requires a stack to execute the bytecodes. We can pass `--stack-size=n` option to set the maximum stack size for iwasm, by default it is 16 KB. For the runtime embedder, we can set the `uint32_t stack_size` argument when calling API ` wasm_runtime_instantiate` and `wasm_runtime_create_exec_env`.

- decrease block_addr_cache size for classic interpreter

  The block_addr_cache is a hash cache to store the else/end addresses for WebAssembly blocks (BLOCK/IF/LOOP) to speed up address lookup. This is only available in the classic interpreter. We can set it by defineing macro `-DBLOCK_ADDR_CACHE_SIZE=n`, e.g. add `add_defintion (-DBLOCK_ADDR_CACHE_SIZE=n)` in CMakeLists.txt, by default it is 64, and the total block_addr_cache size is 3072 bytes in 64-bit platform and 1536 bytes in 32-bit platform.

### (2) Methods to reduce the libc-wasi (without -nostdlib) mode footprint

Most of the above methods are also available for libc-wasi mode, besides them, we can export malloc and free functions with `-Wl,--export=malloc -Wl,--export=free` option, so WAMR runtime will disable its app heap and call the malloc/free function exported to allocate/free the memory from/to the heap space managed by libc.

Note: wasm-ld from LLVM 13 and later automatically inserts ctor/dtor calls
for all exported functions for a command. (vs reactor)
It breaks the malloc/free exports mentioned above.

## 3. Build wasm app with pthread support

Please ref to [pthread library](./pthread_library.md) for more details.

## 4. Build wasm app with SIMD support

The official *wasi-sdk release* doesn't fully support *latest 128-bit SIMD spec* yet. WARM provides a script in [build-wasi-sdk](../test-tools/build-wasi-sdk/) to generate
another wasi-sdk with *llvm-13* from source code and installs it at *../test-tools/wasi-sdk*. If you plan to build WASM applications with *latest 128-bit SIMD*, please use it instead of the official release.

And also you can install emsdk and use its SSE header files, please ref to workload samples, e.g. [bwa CMakeLists.txt](../samples/workload/bwa/CMakeLists.txt) and [wasm-av1 CMakeLists.txt](../samples/workload/wasm-av1/CMakeLists.txt) for more details.

For both wasi-sdk and emsdk, please add the option `-msimd128` for clang or emcc to generate WASM application with SIMD bytecodes.

# Build WASM applications with emsdk

## 1. Install emsdk

Assuming you are using Linux, you may install emcc and em++ from Emscripten EMSDK following the steps below:

```
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk install latest
./emsdk activate latest
# And then source the emsdk_env.sh script before build wasm app
source emsdk_env.sh    (or add it to ~/.bashrc if you don't want to run it each time)
```

The Emscripten website provides other installation methods beyond Linux.

## 2. emsdk options

To build the wasm C source code into wasm binary, we can use the following command:

```bash
EMCC_ONLY_FORCED_STDLIBS=1 emcc -O3 -s STANDALONE_WASM=1 \
    -o test.wasm test.c \
    -s TOTAL_STACK=4096 -s TOTAL_MEMORY=65536 \
    -s "EXPORTED_FUNCTIONS=['_main']" \
    -s ERROR_ON_UNDEFINED_SYMBOLS=0
```

There are some useful options:

- **EMCC_ONLY_FORCED_STDLIBS=1** whether to link libc library into the output binary or not, similar to `-nostdlib` option of wasi-sdk clang. If specified, then no libc library is linked and the **libc-builtin** library of WAMR must be built to run the wasm app, otherwise, the **libc-wasi** library must be built. You can specify **-DWAMR_BUILD_LIBC_BUILTIN=1** or **-DWAMR_BUILD_LIBC_WASI=1** for CMake to build WAMR with libc-builtin support or libc-wasi support.

  The emsdk's wasi implementation is incomplete, e.g. open a file might just return fail, so it is strongly not recommended to use this mode, especially when there are file io operations in wasm app, please use wasi-sdk instead.

- **-s STANDALONE_WASM=1** build wasm app in standalone mode (non-web mode), if the output file has suffix ".wasm", then only wasm file is generated (without html file and JavaScript file).

- **-s TOTAL_STACK=\<value\>** the auxiliary stack size, same as `-z stack-size=\<value\>` of wasi-sdk

- **-s TOTAL_MEMORY=\<value\>**  or **-s INITIAL_MEORY=\<value\>** the initial linear memory size

- **-s MAXIMUM_MEMORY=\<value\>** the maximum linear memory size, only take effect if **-s ALLOW_MEMORY_GROWTH=1** is set

- **-s ALLOW_MEMORY_GROWTH=1/0** whether the linear memory is allowed to grow or not

- **-s "EXPORTED_FUNCTIONS=['func name1', 'func name2']"** to export functions

- **-s ERROR_ON_UNDEFINED_SYMBOLS=0** disable the errors when there are undefined symbols

For more options, please ref to <EMSDK_DIR>/upstream/emscripten/src/settings.js, or [Emscripten document](https://emscripten.org/docs/compiling/Building-Projects.html).

# Build a project with cmake

If you have a complex WASM application project which contains dozens of source files, you can consider using cmake for project building.

You can cross compile your project by using the toolchain provided by WAMR.

Assume the original `CMakeLists.txt` for `test.c` likes below:

``` cmake
cmake_minimum_required (VERSION 3.5)
project(hello_world)
add_executable(hello_world test.c)
```

It is easy to use *wasi-sdk* in CMake by setting *CMAKE_TOOLCHAIN_FILE* without any modification on the original *CMakeLists.txt*.

```
$ cmake -DWASI_SDK_PREFIX=${WASI_SDK_INSTALLTION_DIR}
        -DCMAKE_TOOLCHAIN_FILE=${WASI_SDK_INSTALLTION_DIR}/share/cmake/wasi-sdk.cmake
        -DCMAKE_SYSROOT=<a sysroot directory>
        ..
```

`WASI_SDK_INSTALLTION_DIR` is the directory in where you install the *wasi-sdk*. like */opt/wasi-sdk*

If you prefer WASI, set *CMAKE_SYSROOT* to *wasi-sysroot*

```
$ cmake <same as above>
        -DCMAKE_SYSROOT=${WASI_SDK_INSTALLTION_DIR}/share/wasi-sysroot
        ..
```

If you prefer *WAMR builtin libc*, set *CMAKE_SYSROOT* to *libc-builtin-sysroot*

> Note: If you have already built a SDK profile

```
$ cmake <same as above>
        -DCMAKE_SYSROOT=${WAMR_SOURCE_ROOT}/wamr-sdk/app/libc-builtin-sysroot
        ..
```

You will get ```hello_world``` which is the WASM app binary.


# Compile WASM to AOT module

Please ensure the wamrc was already generated and available in your shell PATH. Then we can use wamrc to compile WASM app binary to WAMR AOT binary.

``` Bash
wamrc -o test.aot test.wasm
```

wamrc supports a number of compilation options through the command line arguments:

``` Bash
wamrc --help
Usage: wamrc [options] -o output_file wasm_file
  --target=<arch-name>      Set the target arch, which has the general format: <arch><sub>
                            <arch> = x86_64, i386, aarch64, arm, thumb, xtensa, mips,
                                     riscv64, riscv32.
                              Default is host arch, e.g. x86_64
                            <sub> = for ex. on arm or thumb: v5, v6m, v7a, v7m, etc.
                            Use --target=help to list supported targets
  --target-abi=<abi>        Set the target ABI, e.g. gnu, eabi, gnueabihf, msvc, etc.
                              Default is gnu if target isn't riscv64 or riscv32
                              For target riscv64 and riscv32, default is lp64d and ilp32d
                            Use --target-abi=help to list all the ABI supported
  --cpu=<cpu>               Set the target CPU (default: host CPU, e.g. skylake)
                            Use --cpu=help to list all the CPU supported
  --cpu-features=<features> Enable or disable the CPU features
                            Use +feature to enable a feature, or -feature to disable it
                            For example, --cpu-features=+feature1,-feature2
                            Use --cpu-features=+help to list all the features supported
  --opt-level=n             Set the optimization level (0 to 3, default is 3)
  --size-level=n            Set the code size level (0 to 3, default is 3)
  -sgx                      Generate code for SGX platform (Intel Software Guard Extention)
  --bounds-checks=1/0       Enable or disable the bounds checks for memory access:
                              by default it is disabled in all 64-bit platforms except SGX and
                              in these platforms runtime does bounds checks with hardware trap,
                              and by default it is enabled in all 32-bit platforms
  --format=<format>         Specifies the format of the output file
                            The format supported:
                              aot (default)  AoT file
                              object         Native object file
                              llvmir-unopt   Unoptimized LLVM IR
                              llvmir-opt     Optimized LLVM IR
  --disable-bulk-memory     Disable the MVP bulk memory feature
  --enable-multi-thread     Enable multi-thread feature, the dependent features bulk-memory and
                            thread-mgr will be enabled automatically
  --enable-tail-call        Enable the post-MVP tail call feature
  --disable-simd            Disable the post-MVP 128-bit SIMD feature:
                              currently 128-bit SIMD is only supported for x86-64 target,
                              and by default it is enabled in x86-64 target and disabled
                              in other targets
  --disable-ref-types       Disable the MVP reference types feature
  --disable-aux-stack-check Disable auxiliary stack overflow/underflow check
  --enable-dump-call-stack  Enable stack trace feature
  --enable-perf-profiling   Enable function performance profiling
  -v=n                      Set log verbose level (0 to 5, default is 2), larger with more log
Examples: wamrc -o test.aot test.wasm
          wamrc --target=i386 -o test.aot test.wasm
          wamrc --target=i386 --format=object -o test.o test.wasm
```

## AoT compilation with 3rd-party toolchains

`wamrc` uses LLVM to compile wasm bytecode to AoT file, this works for most of the architectures, but there may be circumstances where you want to use 3rd-party toolchains to take over some steps of the compilation pipeline, e.g.

1. The upstream LLVM doesn't support generating object file for your CPU architecture (such as ARC), then we may need some other assembler to do such things.
2. You may get some other LLVM-based toolchains which may have better optimizations for the specific target, then you may want your toolchain to take over all optimization steps.

`wamrc` provides two environment variables to achieve these:
- `WAMRC_LLC_COMPILER`

  When specified, `wamrc` will emit the optimized LLVM-IR (.bc) to a file, and invoke `$WAMRC_LLC_COMPILER` with ` -c -O3 ` to generate the object file.

  Optionally, you can use environment variable `WAMRC_LLC_FLAGS` to overwrite the default flags.

- `WAMRC_ASM_COMPILER`

  When specified, `wamrc` will emit the text based assembly file (.s), and invoke `$WAMRC_ASM_COMPILER` with ` -c -O3 ` to generate the object file.

  Optionally, you can use environment variable `WAMRC_ASM_FLAGS` to overwrite the default flags.

### Usage example
``` bash
WAMRC_LLC_COMPILER=<path/to/your/compiler/driver> ./wamrc -o test.aot test.wasm
```

> Note: `wamrc` will verify whether the specified file exists and executable. If verification failed, `wamrc` will report a warning and fallback to normal pipeline. Since the verification is based on file, you **must specify the absolute path to the binary** even if it's in `$PATH`

> Note: `WAMRC_LLC_COMPILER` has higher priority than `WAMRC_ASM_COMPILER`, if `WAMRC_LLC_COMPILER` is set and verified, then `WAMRC_ASM_COMPILER` will be ignored.

> Note: the `LLC` and `ASM` in the env name just means this compiler will be used to compile the `LLVM IR file`/`assembly file` to object file, usually passing the compiler driver is the simplest way. (e.g. for LLVM toolchain, you don't need to pass `/usr/bin/llc`, using `/usr/bin/clang` is OK)

Run WASM app in WAMR mini product build
=======================================

Run the test.wasm or test.aot with WAMR mini product build:
``` Bash
./iwasm test.wasm   or
./iwasm test.aot
```
You will get the following output:
```
Hello world!
buf ptr: 0xffffc2c8
buf: 1234
```
If you would like to run the test app on Zephyr, we have embedded a test sample into its OS image. You will need to execute:
```
ninja run
```
