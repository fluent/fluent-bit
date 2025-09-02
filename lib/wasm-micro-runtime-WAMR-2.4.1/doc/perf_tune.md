# Tune the performance of running wasm/aot file

Normally there are some methods to tune the performance:

## 1. Use `wasm-opt` tool

Download the [binaryen release](https://github.com/WebAssembly/binaryen/releases), and use the `wasm-opt` tool in it to optimize the wasm file, for example:

```bash
wasm-opt -O4 -o test_opt.wasm test.wasm
```

## 2. Enable `simd128` option when compiling wasm source files

WebAssembly [128-bit SIMD](https://github.com/WebAssembly/simd) is supported by WAMR on x86-64 and aarch64 targets, enabling it when compiling wasm source files may greatly improve the performance. For [wasi-sdk](https://github.com/WebAssembly/wasi-sdk) and [emsdk](https://github.com/emscripten-core/emsdk), please add `-msimd128` flag for `clang` and `emcc/em++`:

```bash
/opt/wasi-sdk/bin/clang -msimd128 -O3 -o <wasm_file> <c/c++ source files>

emcc -msimd128 -O3 -o <wasm_file> <c/c++ source files>
```

## 3. Enable segue optimization for wamrc when generating the aot file

[Segue](https://plas2022.github.io/files/pdf/SegueColorGuard.pdf) is an optimization technology which uses x86 segment register to store the WebAssembly linear memory base address, so as to remove most of the cost of SFI (Software-based Fault Isolation) base addition and free up a general purpose register, by this way it may:

- Improve the performance of JIT/AOT
- Reduce the footprint of JIT/AOT, the JIT/AOT code generated is smaller
- Reduce the compilation time of JIT/AOT

Currently it is only supported on linux x86-64, developer can use `--enable-segue=[<flags>]` for wamrc:

```bash
wamrc --enable-segue -o aot_file wasm_file
# or
wamrc --enable-segue=[<flags>] -o aot_file wasm_file
```

`flags` can be: i32.load, i64.load, f32.load, f64.load, v128.load, i32.store, i64.store, f32.store, f64.store and v128.store, use comma to separate them, e.g. `--enable-segue=i32.load,i64.store`, and `--enable-segue` means all flags are added.

> Note: Normally for most cases, using `--enable-segue` is enough, but for some cases, using `--enable-segue=<flags>` may be better, for example for CoreMark benchmark, `--enable-segue=i32.store` may lead to better performance than `--enable-segue`.

## 4. Enable segue optimization for iwasm when running wasm file

Similar to segue optimization for wamrc, run:

```bash
iwasm --enable-segue wasm_file      (iwasm is built with llvm-jit enabled)
# or
iwasm --enable-segue=[<flags>] wasm_file
```

> Note: Currently it is only supported on linux x86-64.

## 5. Use the AOT static PGO method

LLVM PGO (Profile-Guided Optimization) allows the compiler to better optimize code for how it actually runs. WAMR supports AOT static PGO, currently it is tested on Linux x86-64 and x86-32. The basic steps are:

1. Use `wamrc --enable-llvm-pgo -o <aot_file_of_pgo> <wasm_file>` to generate an instrumented aot file.

2. Compile iwasm with `cmake -DWAMR_BUILD_STATIC_PGO=1` and run `iwasm --gen-prof-file=<raw_profile_file> <aot_file_of_pgo>` to generate the raw profile file.

> Note: Directly dumping raw profile data to file system may be unsupported in some environments, developer can dump the profile data into memory buffer instead and try outputting it through network (e.g. uart or socket):

```C
uint32_t
wasm_runtime_get_pgo_prof_data_size(wasm_module_inst_t module_inst);

uint32_t
wasm_runtime_dump_pgo_prof_data_to_buf(wasm_module_inst_t module_inst, char *buf, uint32_t len);
```

3. Install or compile `llvm-profdata` tool，refer to [here](../tests/benchmarks/README.md#install-llvm-profdata) for the details.

4. Run `llvm-profdata merge -output=<profile_file> <raw_profile_file>` to merge the raw profile file into the profile file.

5. Run `wamrc --use-prof-file=<profile_file> -o <aot_file> <wasm_file>` to generate the optimized aot file.

6. Run the optimized aot_file: `iwasm <aot_file>`.

Developer can refer to the `test_pgo.sh` files under each benchmark folder for more details, e.g. [test_pgo.sh](../tests/benchmarks/coremark/test_pgo.sh) of CoreMark benchmark.

## 6. Disable the memory boundary check

Please notice that this method is not a general solution since it may lead to security issues. And only boost the performance for some platforms in AOT mode and don't support hardware trap for memory boundary check.

1. Build WAMR with `-DWAMR_CONFIGURABLE_BOUNDS_CHECKS=1` option.

2. Compile AOT module by wamrc with `--bounds-check=0` option.

3. Run the AOT module by iwasm with `--disable-bounds-checks` option.

> Note: The size of AOT file will be much smaller than the default, and some tricks are possible such as let the wasm application access the memory of host os directly.
> Please notice that if this option is enabled, the wasm spec test will fail since it requires the memory boundary check. For example, the runtime will crash when accessing the memory out of the boundary in some cases instead of throwing an exception as the spec requires.

You should only use this method for well tested wasm applications and make sure the memory access is safe.

## 7. Use linux-perf

Linux perf is a powerful tool to analyze the performance of a program, developer can use it to find the hot functions and optimize them. It is one profiler supported by WAMR. In order to use it, you need to add `--perf-profile` while running _iwasm_. By default, it is disabled.

> [!CAUTION]
> For now, only llvm-jit mode and aot mode supports linux-perf.

Here is a basic example, if there is a Wasm application _foo.wasm_, you'll execute.

```
$ perf record --output=perf.data.raw -- iwasm --enable-linux-perf foo.wasm
```

This will create a _perf.data_ and
- a _jit-xxx.dump_ under _~/.debug/jit/_ folder if running llvm-jit mode
- or _/tmp/perf-<pid>.map_ if running AOT mode


This file is WAMR generated. It contains information which includes jitted(precompiled) code addresses in memory, names of jitted (precompiled) functions which are named as *aot_func#N* and so on.

If running with llvm-jit mode, the next thing is to merge _jit-xxx.dump_ file into the _perf.data_.

```
$ perf inject --jit --input=perf.data.raw --output=perf.data
```

This step will create a lot of _jitted-xxxx-N.so_ which are ELF images for all JIT functions created at runtime.

> [!TIP]
> add `-v` and check if there is output likes _write ELF image ..._. If yes, it means above merge is successful.

Finally, you can use _perf report_ to analyze the performance.

```
$ perf report --input=perf.data
```

> [!CAUTION]
> Using release builds of llvm and iwasm will produce "[unknown]" functions in the call graph. It is not only because
> of the missing debug information, but also because of removing frame pointers. To get the complete result, please
> use debug builds of both llvm and iwasm.
>
> Wasm functions names are stored in _the custom name section_. Toolchains always generate the custom name section in both debug and release builds. However, the custom name section is stripped to pursue smallest size in release build. So, if you want to get a understandable result, please search the manual of toolchain to look for a way to keep the custom name section.
>
> For example, with EMCC, you can add `-g2`.
>
> If not able to get the context of the custom name section, WAMR will use `aot_func#N` to represent the function name. `N` is from 0. `aot_func#0` represents the first _not imported wasm function_.

### 7.1 Flamegraph

[Flamegraph](https://www.brendangregg.com/flamegraphs.html) is a powerful tool to visualize stack traces of profiled software so that the most frequent code-paths can be identified quickly and accurately. In order to use it, you need to [capture graphs](https://github.com/brendangregg/FlameGraph#1-capture-stacks) when running `perf record`

```
$ perf record -k mono --call-graph=fp --output=perf.data.raw -- iwasm --enable-linux-perf foo.wasm
```

If running with llvm-jit mode, merge the _jit-xxx.dump_ file into the _perf.data.raw_.

```
$ perf inject --jit --input=perf.data.raw --output=perf.data
```

Generate the stack trace file.

```
$ perf script > out.perf
```

[Fold stacks](https://github.com/brendangregg/FlameGraph#2-fold-stacks).

```
$ ./FlameGraph/stackcollapse-perf.pl out.perf > out.folded
```

[Render a flamegraph](https://github.com/brendangregg/FlameGraph#3-flamegraphpl)

```
$ ./FlameGraph/flamegraph.pl out.folded > perf.foo.wasm.svg
```

> [!TIP]
> use `grep` to pick up folded stacks you are interested in or filter out something.
>
> For example, if just want to see stacks of wasm functions, you can use
>
> ```bash
> # only jitted functions
> $ grep "wasm_runtime_invoke_native" out.folded | ./FlameGraph/flamegraph.pl > perf.foo.wasm.only.svg
> ```

> [!TIP]
> use [trans_wasm_func_name.py](../test-tools/trans-jitted-func-name/trans_wasm_func_name.py) to translate jitted function
> names to its original wasm function names. It requires _wasm-objdump_ in _wabt_ and _name section_ in the .wasm file
>
> The input file is the output of `./FlameGraph/stackcollapse-perf.pl`.
>
> ```bash
> python trans_wasm_func_name.py --wabt_home <wabt-installation> --folded out.folded <.wasm>
> ```
>
> Then you will see a new file named _out.folded.translated_ which contains the translated folded stacks.
> All wasm functions are translated to its original names with a prefix like "[Wasm]"

## 8. Refine the calling processes between host native and wasm application

In some scenarios, there may be lots of callings between host native and wasm application, e.g. frequent callings to AOT/JIT functions from host native or frequent callings to host native from AOT/JIT functions. It is important to refine these calling processes to speedup them, WAMR provides several methods:

### 8.1 Refine callings to native APIs registered by `wasm_runtime_register_natives` from AOT code

When wamrc compiles the wasm file to AOT code, it may generate LLVM IR to call the native API from an AOT function, and if it doesn't know the native API's signature, the generated LLVM IR has to call the runtime API `aot_invoke_native` to invoke the native API, which is a relatively slow way. If developer registers native APIs during execution by calling `wasm_runtime_register_natives` or by `iwasm --native-lib=<lib>`, then developer can also register native APIs with the same signatures to the AOT compiler by `wamrc --native-lib=<lib>`, so as to let the AOT compiler pre-know the native API's signature, and generate optimized LLVM IR to quickly call to the native API.

The below sample registers an API `int test_add(int, int)` to the AOT compiler:

```C
/* test_add.c */

#include "wasm_export.h"

static int
test_add_wrapper(wasm_exec_env_t exec_env, int x, int y) {
    return 0; /* empty function is enough */
}

#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, func_name##_wrapper, signature, NULL }

static NativeSymbol native_symbols[] = {
    REG_NATIVE_FUNC(test_add, "(ii)i")
};

uint32_t
get_native_lib(char **p_module_name, NativeSymbol **p_native_symbols)
{
    *p_module_name = "env";
    *p_native_symbols = native_symbols;
    return sizeof(native_symbols) / sizeof(NativeSymbol);
}
```
```bash
# build native lib
gcc -O3 -fPIC -shared -I <wamr_root>/core/iwasm/include -o libtest_add.so test_add.c
# register native lib to aot compiler
wamrc --native-lib=./libtest_add.so -o <aot_file> <wasm_file>
```

> Note: no need to do anything for LLVM JIT since the native APIs must have been registered before execution and JIT compiler already knows the native APIs' signatures.

### 8.2 Refine callings to native APIs registered by wasm-c-api `wasm_instance_new` from AOT code

In wasm-c-api mode, when the native APIs are registered by `wasm_instance_new(..., imports, ...)`, developer can use `wamrc --invoke-c-api-import` option to generate the AOT file, which treats the unknown import function as wasm-c-api import function and generates optimized LLVM IR to speedup the calling process.

> Note: no need to do anything for LLVM JIT since the similar flag has been set to JIT compiler in wasm-c-api `wasm_engine_new` when LLVM JIT is enabled.

### 8.3 Refine callings to AOT/JIT functions from host native

Currently by default WAMR runtime has registered many quick AOT/JIT entries to speedup the calling processes to call AOT/JIT functions from host native, as long as developer doesn't disable it by using `cmake -DWAMR_BUILD_QUICK_AOT_ENTRY=0` or setting the compiler macro `WASM_ENABLE_QUICK_AOT_ENTRY` to 0 in the makefile. These quick AOT/JIT entries include:

1. wasm function contains 0 to 4 arguments and 0 to 1 results, with the type of each argument is i32 or i64 and the type of result is i32, i64 or void. These functions are like:

```C
// no argument
i32 foo(), i64 foo(), void foo()
// one argument, each argument is i32 or i64
i32 foo(i32/i64), i64 foo(i32/i64), void(i32/i64)
// two arguments, each argument is i32 or i64
i32 foo(i32/i64, i32/i64), i64 foo(i32/i64, i32/i64), void(i32/i64, i32/i64)
// three arguments, each argument is i32 or i64
i32 foo(i32/i64, i32/i64, i32/i64), i64 foo(i32/i64, i32/i64, i32/i64), void(i32/i64, i32/i64, i32/i64)
// four arguments, each argument is i32 or i64
i32 foo(i32/i64, i32/i64, i32/i64, i32/i64)
i64 foo(i32/i64, i32/i64, i32/i64, i32/i64)
void(i32/i64, i32/i64, i32/i64, i32/i64)
```

2. wasm function contains 5 arguments and 0 to 1 results, with the type of each argument is i32 and the type of result is i32, i64 or void. These functions are like:

```C
i32 foo(i32, i32, i32, i32, i32)
i64 foo(i32, i32, i32, i32, i32)
void foo(i32, i32, i32, i32, i32)
```

To speedup the calling processes, developer had better ensure that the signatures of the wasm functions to expose are like above, or add some conversions to achieve it. For example, if a wasm function to call is `f32 foo(f32)`, developer can define a new function `i32 foo1(i32)` like below and export it:
```C
int32 foo1(int32 arg_i32)
{
    float arg_f32 = *(float *)&arg_i32;
    float res_f32 = foo(f32);
    int32 res_i32 = *(int32 *)&res_i32;
    return res_i32;
}
```
And in the host embedder:
```
    uint32 argv[2];
    float arg_f32 = ...; /* argument to foo */
    float res_f32;
    bool ret;

    argv[0] = *(uint32 *)&arg_f32;
    func = wasm_runtime_lookup_function(module_inst, "foo1");
    ret = wasm_runtime_call_wasm(exec_env, func, 1, argv);
    if (!ret) {
        /* handle exception */
        printf("%s\n", wasm_runtime_get_exception(module_inst));
    }
    else {
        /* the return value is stored in argv[0] */
        res_f32 = *(float *)&argv[0];
    }
```
