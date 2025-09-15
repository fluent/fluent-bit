# Dynamic AOT Module Debugging

> Note: Dynamic AOT debugging is experimental and only a few debugging capabilities are supported.

This guide explains how to debug WAMR AOT modules with dynamic AOT features. Follow these steps to set up and run your debugging environment.

## 1. Test source code

The following c program file is used as a debugging test file.

```bash
#include <stdio.h>

int main() {
    printf("hello, world!\n");
    int a = 1024;
    printf("a is %d\n",a);
    int b = 42;
    printf("b is %d\n",b);
    return 0;
}
```

## 2. Build iwasm with dynamic aot debugging feature

To enable dynamic AOT debugging, ensure the following
compile options are enabled when you [build iwasm](../../product-mini/README.md):

```bash
cmake -DWAMR_BUILD_AOT=1 -DWAMR_BUILD_DYNAMIC_AOT_DEBUG=1 -DCMAKE_BUILD_TYPE=Debug
```

## 3. Build wamrc

Developer may need to build out two versions of wamrc, one is to compile the wasm binary into the AOT file, the other is to compile the wasm binary into an object file. To build out the former, just build wamrc as normal, see [wamrc-compiler/README.md](../../wamr-compiler/README.md). To build out the latter, the `WAMR_BUILD_DEBUG_AOT` flag must be added to cmake, please refer to the first two steps in [doc/source_debugging_aot.md](../../doc/source_debugging_aot.md), and if you encounter the error “‘eLanguageTypeC17’ not declared in this scope”, you can bypass it by commenting out the case judgments. This will not affect the debugging results.

## 4. Dynamic aot debugging and verification across various platforms

You can adjust the compiler options for different architectures and instruction sets.

### 4.1 Linux

#### Compile test.c to test.wasm

```bash
/opt/wasi-sdk/bin/clang -O0 -g -gdwarf-2  -o test.wasm test.c
```

#### Compile test.wasm to test.aot

```bash
./wamrc --opt-level=0 -o test.aot test.wasm
```

#### Compile test.wasm to test object file

> Note: please use the version wamrc which was built with `cmake -DWAMR_BUILD_DEBUG_AOT` flag.

```bash
./wamrc --opt-level=0 --format=object -o test.obj test.wasm
```

#### Launch the program using gdbserver on the remote linux host

```bash
cd ~/aot_debug   # This directory contains iwasm and test.aot
gdbserver hostip:port ./iwasm test.aot
```

#### Local remote debugging

```bash
export OBJ_PATH=~/aot_debug
cd ~/aot_debug   # This directory contains iwasm, test.c, test obj file and dynamic_aot_debug.py
gdb ./iwasm
(gdb) target remote hostip:port
(gdb) source dynamic_aot_debug.py
(gdb) c
(gdb) b test.c:main
(gdb) n
```

### 4.2 ARMv7

#### Compile test.c to test.wasm

```bash
/opt/wasi-sdk/bin/clang -O0 -nostdlib -z stack-size=8192 -Wl,--initial-memory=65536
-g -gdwarf-2 -o test.wasm test.c -Wl,--export=main -Wl,--export=__main_argc_argv
-Wl,--export=__heap_base -Wl,--export=__data_end -Wl,--no-entry -Wl,--allow-undefined
```

#### Compile test.wasm to test.aot

```bash
./wamrc --opt-level=0 --target=thumbv7 --target-abi=gnueabihf --cpu=cortex-a7
--cpu-features=-neon -o test.aot test.wasm
```

#### Compile test.wasm to test object file

> Note: please use the version wamrc which was built with `cmake -DWAMR_BUILD_DEBUG_AOT` flag.

```bash
./wamrc --opt-level=0 --format=object --target=thumbv7 --target-abi=gnueabihf
--cpu=cortex-a7 --cpu-features=-neon -o test.obj test.wasm
```

#### Start Emulator

In Terminal 1, start the emulator in debug mode and launch the GDB server:

```bash
# start emulator on debug mode, and will start gdb server, set port as 1234
./emulator.sh vela -qemu -S -s
ap> iwasm test.aot
```

#### Start NuttX Using GDB

In Terminal 2, set the path to your object file and start NuttX with GDB:

```bash
# You can save test.obj file in this path
export OBJ_PATH=~/work/data/aot_debug
gdb-multiarch nuttx -ex "tar remote:1234" -ex "source dynamic_aot_debug.py"
```

In the GDB prompt:

```bash
(gdb) c
(gdb) b test.c:main
(gdb) n
```

## 5. Workflow

Refer to the workflow diagram (wasm-micro-runtime/test-tools/dynamic-aot-debug) for an overview of the debugging process. In addition, the implementation of this dynamic aot debugging solution is not complete yet. It only supports breakpoints and single-step execution, and it is not yet known to view detailed information such as variables.
