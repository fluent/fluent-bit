# "native-lib" sample introduction

This sample demonstrates how to write required interfaces in native library, build it into a shared library and register the shared library to iwasm.

The native library should provide `get_native_lib` API for iwasm to return the native library info, including the module name, the native symbol list and the native symbol count, so that iwasm can use them to register the native library, for example:

```C
static int
foo_wrapper(wasm_exec_env_t exec_env, int x, int y)
{
    return x + y;
}

#define REG_NATIVE_FUNC(func_name, signature) \
    { #func_name, func_name##_wrapper, signature, NULL }

static NativeSymbol native_symbols[] = {
    REG_NATIVE_FUNC(foo, "(ii)i")
};

uint32_t
get_native_lib(char **p_module_name, NativeSymbol **p_native_symbols)
{
    *p_module_name = "env";
    *p_native_symbols = native_symbols;
    return sizeof(native_symbols) / sizeof(NativeSymbol);
}
```

## Preparation

Please install WASI SDK, download the [wasi-sdk release](https://github.com/WebAssembly/wasi-sdk/releases) and extract the archive to default path `/opt/wasi-sdk`.

## Build the sample

```bash
mkdir build
cd build
cmake ..
make
```

`iwasm`, one wasm module `test.wasm` and two shared libraries `libtest_add.so`, `libtest_sqrt.so`
will be generated.

## Run workload

### Linux

```bash
cd build
./iwasm --native-lib=./libtest_add.so --native-lib=./libtest_sqrt.so --native-lib=./libtest_hello.so --native-lib=./libtest_hello2.so wasm-app/test.wasm
```

### macOS

```bash
cd build
./iwasm --native-lib=libtest_add.dylib --native-lib=libtest_sqrt.dylib --native-lib=libtest_hello.dylib --native-lib=libtest_hello2.dylib wasm-app/test.wasm
```

The output is:

```bash
init_native_lib in test_hello2.c called
Hello World!
10 + 20 = 30
sqrt(10, 20) = 500
test_hello("main", 0x0, 0) = 41
malloc(42) = 0x24e8
test_hello("main", 0x24e8, 42) = 41
Message from test_hello: Hello, main. This is test_hello_wrapper!
test_hello2("main", 0x0, 0) = 85
malloc(86) = 0x24e8
test_hello2("main", 0x24e8, 86) = 85
Message from test_hello2: Hello, main. This is test_hello2_wrapper! Your wasm_module_inst_t is 0x7fe0e6804280.
deinit_native_lib in test_hello2.c called
```
