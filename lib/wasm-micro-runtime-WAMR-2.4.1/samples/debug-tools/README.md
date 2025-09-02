# "debug-tools" sample introduction

Tool to symoblicate stack traces. When using wasm in production, debug info are usually stripped using tools like `wasm-opt`, to decrease the binary size. If a corresponding unstripped wasm file is kept, location information (function, file, line, column) can be retrieved from the stripped stack trace.

## Build and run the sample

### Generate the stack trace

Build `iwasm` with `WAMR_BUILD_DUMP_CALL_STACK=1` and `WAMR_BUILD_FAST_INTERP=0` and the wasm file with debug info (e.g. `clang -g`). As it is done in [CMakeLists.txt](./CMakeLists.txt) and [wasm-apps/CMakeLists.txt](./wasm-apps/CMakeLists.txt) (look for `addr2line`):

```bash
$ mkdir build && cd build
$ cmake ..
$ make
$ ./iwasm wasm-apps/trap.wasm
```

The output should be something like

```text
#00: 0x0159 - $f5
#01: 0x01b2 - $f6
#02: 0x0200 - $f7
#03: 0x026b - $f8
#04: 0x236b - $f15
#05: 0x011f - _start

Exception: unreachable
```

Copy the stack trace printed to stdout into a separate file (`call_stack.txt`):

```bash
$ ./iwasm wasm-apps/trap.wasm | grep "#" > call_stack.txt
```

Same for AOT. The AOT binary has to be generated using the `--enable-dump-call-stack` option of `wamrc`, as in [CMakeLists.txt](./wasm-apps/CMakeLists.txt). Then run:

```bash
$ ./iwasm wasm-apps/trap.aot | grep "#" > call_stack.txt
```

### Symbolicate the stack trace

Run the [addr2line](../../test-tools/addr2line/addr2line.py) script to symbolicate the stack trace:

```bash
$ python3 ../../../test-tools/addr2line/addr2line.py \
    --wasi-sdk /opt/wasi-sdk \
    --wabt /opt/wabt \
    --wasm-file wasm-apps/trap.wasm \
    call_stack.txt
```

The output should be something like:

```text
0: c
        at wasm-micro-runtime/samples/debug-tools/wasm-apps/trap.c:5:1
1: b
        at wasm-micro-runtime/samples/debug-tools/wasm-apps/trap.c:11:12
2: a
        at wasm-micro-runtime/samples/debug-tools/wasm-apps/trap.c:17:12
3: main
        at wasm-micro-runtime/samples/debug-tools/wasm-apps/trap.c:24:5
4: __main_void
        at unknown:?:?
5: _start
```

If WAMR is run in fast interpreter mode (`WAMR_BUILD_FAST_INTERP=1`), addresses in the stack trace cannot be tracked back to location info.
If WAMR <= `1.3.2` is used, the stack trace does not contain addresses.
In those two cases, run the script with `--no-addr`: the line info returned refers to the start of the function

```bash
$ python3 ../../../test-tools/addr2line/addr2line.py \
    --wasi-sdk /opt/wasi-sdk \
    --wabt /opt/wabt \
    --wasm-file wasm-apps/trap.wasm \
    call_stack.txt --no-addr
```

#### sourcemap

This script also supports _sourcemap_ which is produced by [_emscripten_](https://emscripten.org/docs/tools_reference/emcc.html). The _sourcemap_ is used to map the wasm function to the original source file. To use it, add `-gsource-map` option to _emcc_ command line. The output should be a section named "sourceMappingURL" and a separated file named "_.map_.

If the wasm file is with _sourcemap_, the script will use it to get the source file and line info. It needs an extra command line option `--emsdk` to specify the path of _emsdk_. The script will use _emsymbolizer_ to query the source file and line info.

````bash
$ python3 ../../../test-tools/addr2line/addr2line.py \
    --wasi-sdk /opt/wasi-sdk \
    --wabt /opt/wabt \
    --wasm-file emscripten/wasm-apps/trap.wasm \
    --emsdk /opt/emsdk \
    call_stack.from_wasm_w_sourcemap.txt

The output should be something like:

```text
1: c
        at ../../../../../wasm-apps/trap.c:5:1
2: b
        at ../../../../../wasm-apps/trap.c:11:12
3: a
        at ../../../../../wasm-apps/trap.c:17:12
4: main
        at ../../../../../wasm-apps/trap.c:24:5
5: __main_void
        at ../../../../../../../../../emsdk/emscripten/system/lib/standalone/__main_void.c:53:10
6: _start
        at ../../../../../../../../../emsdk/emscripten/system/lib/libc/crt1.c:27:3
````

> The script assume the separated map file _.map_ is in the same directory as the wasm file.

### Another approach

If the wasm file is with "name" section, it is able to output function name in the stack trace. To achieve that, need to enable `WAMR_BUILD_LOAD_CUSTOM_SECTION` and `WAMR_BUILD_CUSTOM_NAME_SECTION`. If using .aot file, need to add `--emit-custom-sections=name` into wamrc command line options.

Then the output should be something like

```text
#00: 0x0159 - c
#01: 0x01b2 - b
#02: 0x0200 - a
#03: 0x026b - main
#04: 0x236b - __main_void
#05: 0x011f - _start

Exception: unreachable
```

Also, it is able to use _addr2line.py_ to add file and line info to the stack trace.
