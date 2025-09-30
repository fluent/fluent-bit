# wasm-wasi-extensions

wasm-wasi-extensions is a set of small static libraries
which aims to help you build a wasm module using
WAMR's extensions to WASIp1.
It's expected to be used in combination with WASI-SDK.

Currently it contains bindings for the following APIs:

* wasi-nn

* lib-socket

## Usage

### Preparation

Place it somewhere in your `CMAKE_PREFIX_PATH`.

You may want to automate the process with `FetchContent`.
```
set(URL https://github.com/bytecodealliance/wasm-micro-runtime/releases/download/WAMR-2.4.0/wamr-wasi-extensions-2.4.0.zip)

include(FetchContent)
FetchContent_Declare(
    wamr-wasi-extensions
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    URL ${URL}
)
FetchContent_MakeAvailable(wamr-wasi-extensions)
list(APPEND CMAKE_PREFIX_PATH ${wamr-wasi-extensions_SOURCE_DIR})
```

Now you can use cmake find_package and link it to your application.
You can find samples in the [samples](samples) directory.

### wasi-nn

```
find_package(wamr-wasi-nn REQUIRED)
target_link_libraries(you-app wamr-wasi-nn)
```

### lib-socket

```
find_package(wamr-wasi-socket REQUIRED)
target_link_libraries(your-app wamr-wasi-socket)
```
