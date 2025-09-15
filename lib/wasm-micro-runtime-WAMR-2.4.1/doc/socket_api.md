# How to use Berkeley/Posix Socket APIs in WebAssembly

**_Berkeley sockets_** usually means an API for Internet sockets and Unix domain
sockets. A socket is an abstract representation of the local endpoint of a
network communication path.

Currently, WAMR supports some Socket API features:
- Support TCP and UDP
- Support IPv4 and IPv6
- Support get/set socket options
- Support access control

This document introduces a way to support the _Berkeley/POSIX Socket API_ in
WebAssembly code.

## Patch the native code

The first step is to include a header file of the WAMR socket extension in the
native source code.

```c
#ifdef __wasi__
#include <wasi_socket_ext.h>
#endif
```

`__wasi__` is a macro defined by WASI. The host compiler will not enable it.

## CMake files

It is recommended that the project should use CMake as its build system. Use
[_wasi-sdk_](https://github.com/WebAssembly/wasi-sdk)
as a toolchain to compile C/C++ to WebAssembly

```bash
$ cmake -DWASI_SDK_PREFIX=${WASI_SDK_DIR}
      -DCMAKE_TOOLCHAIN_FILE=${WASI_TOOLCHAIN_FILE}
      -DCMAKE_SYSROOT=${WASI_SYS_ROOT}
      ..
```

In the *CMakeLists.txt*, include an extension of socket support and link with it.

```cmake
include(${CMAKE_CURRENT_SOURCE_DIR}/../../../core/iwasm/libraries/lib-socket/lib_socket_wasi.cmake)
add_executable(socket_example tcp_server.c)
target_link_libraries(socket_example socket_wasi_ext)
```

Now, the native code with socket APIs is ready for compilation.

## Run with iwasm

If having the _.wasm_, the last step is to run it with _iwasm_.

The _iwasm_ should be compiled with `WAMR_BUILD_LIBC_WASI=1`. By default, it is
enabled.

_iwasm_ accepts address ranges via an option, `--addr-pool`, to implement
the capability control. All IP address the WebAssembly application may need to `bind()` or `connect()`
should be announced first. Every IP address should be in CIDR notation. If not, _iwasm_ will return
an error.

```bash
$ iwasm --addr-pool=1.2.3.4/15,2.3.4.6/16 socket_example.wasm
```

_iwasm_ also accepts list of domain names and domain name patterns for the address resolution via an option, `--allow-resolve`, to implement the capability control. Every domain that will be resolved using `sock_addr_resolve` needs to be added to the allowlist first.

```bash
$ iwasm --allow-resolve=*.example.com --allow-resolve=domain.com
```

The example above shows how to allow for resolving all `example.com`'s subdomains (e.g. `x.example.com`, `a.b.c.example.com`) and `domain.com` domain.

Refer to [socket api sample](../samples/socket-api) for more details.

## Intel SGX support

WAMR also supports the socket API within Intel SGX enclaves.

The _iwasm_ should be compiled with `WAMR_BUILD_LIBC_WASI=1` and `WAMR_BUILD_LIB_PTHREAD=1`, which are enabled by default.

Similarly to running _iwasm_ outside of an enclave, the allowed address ranges are given via the option `--addr-pool`.

```bash
$ iwasm --addr-pool=1.2.3.4/15,2.3.4.6/16 socket_example.wasm
```

Refer to [socket api sample](../samples/socket-api) for the compilation of the Wasm applications and [_iwasm_ for Intel SGX](../product-mini/platforms/linux-sgx) for the Wasm runtime.

## The background and compatibility notes

### WASIp1

The WASIp1 provides a subset of the socket API.
Namely,

* send()
* recv()
* shutdown()
* accept()

Functionalities like connect() and listen() are intentionally omitted
there to maintain the capability-based security model, inherited from
cloudabi. The common practice for applications is to make the host code
pass already connected/listening sockets to wasm module.

### WAMR extensions

WAMR extends the WASIp1 with the rest of socket API functionalities
for convenience.

* socket()
* connect()
* bind()
* listen()
* some of getsockopt/setsockopt options
* name resolution (a subset of getaddrinfo)

### Compatibilities

Many of runtimes (eg. Wasmer and WasmEdge) provide similar extensions.
Unfortunately, they are all incompatible. Thus, portable applications
should not rely on these extensions.
