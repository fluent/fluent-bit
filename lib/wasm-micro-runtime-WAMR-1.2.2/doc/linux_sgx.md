
Build and Port WAMR vmcore (iwasm) for Linux SGX
================================================

Build WAMR vmcore (iwasm) for Linux SGX
---------------------------------------

First of all please install the [Intel SGX SDK](https://software.intel.com/en-us/sgx/sdk), v2.8 or later is required, and it is recommended to install the SDK to /opt/intel/sgxsdk.

After installing the dependencies, build the source code:
``` Bash
source <SGX_SDK dir>/environment
cd product-mini/platforms/linux-sgx/
mkdir build && cd build
cmake ..
make
```

By default the `fast interpreter` and `AOT` is enabled. If to enable `Fast JIT`, run:
```Bash
mkdir build && cd build
cmake .. -DWAMR_BUILD_FAST_JIT=1
make
```

This builds two libraries required by SGX application:
 - libvmlib.a for Enclave part
 - libvmlib_untrusted.a for App part

**Note:** WAMR provides some features which can be easily configured by passing options to cmake, please see [WAMR vmcore cmake building configurations](./build_wamr.md#wamr-vmcore-cmake-building-configurations) for the details. Currently in Linux SGX, fast interpreter, AOT, libc-builtin, libc-WASI and lib-pthread are enabled by default.

Then build the enclave sample:
``` Bash
source <SGX_SDK dir>/environment
cd enclave-sample
make
```

**Note:** By default, the generated SGX application assumes it is signed with production key and running on simulation mode. The user can explicitly specify the relative variables in commandline to overwrite the default settings. For example, to build a debug enclave, please build the enclave with `make SGX_DEBUG=1`. To build the enclave running on a hardware-based SGX platform, execute `make SGX_MODE=HW`.

The binary file iwasm will be generated. To run the sample:

``` Bash
source <SGX_SDK dir>/environment
iwasm [-options] wasm_file [args...]
or:
iwasm [-options] aot_file [args...]
```

### Minimal build
The libc-WASI and lib-pthread features require a lot of ocalls, if you don't need so much ocalls in your application, you can use the `minimal` version

``` Bash
# replace the build files with minimal version
cd product-mini/platforms/linux-sgx/
cp CMakeLists_minimal.txt CMakeLists.txt
cp enclave-sample/Makefile_minimal enclave-sample/Makefile
cp enclave-sample/Enclave/Enclave_minimal.edl enclave-sample/Enclave/Enclave.edl
# follow the building process above
```

Port WAMR vmcore for Linux SGX
------------------------------

The enclave-sample creates a sample to embed wamr vmlib of Enclave part and App part to an SGX application. To port WAMR vmcore lib to SGX application, there are some steps to do:

**Step 1: Add "sgx_wamr.edl" and "sgx_pthread.edl" into EDL file, e.g. Enclave.edl:**
> This step is not required in minimal version

```bash
from "sgx_pthread.edl" import *;
from "sgx_wamr.edl" import *;
```

The sgx_wamr.edl is under ${WAMR_ROOT}/core/shared/platform/linux-sgx, so please **add it to the search path list** when generating Enclave_u.c and Enclave_t.c from Enclave.edl:

```bash
@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl \
        --search-path ../Enclave \
        --search-path $(SGX_SDK)/include \
        --search-path $(WAMR_ROOT)/core/shared/platform/linux-sgx
```

```bash
@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl \
        --search-path ../Enclave \
        --search-path $(SGX_SDK)/include \
        --search-path $(WAMR_ROOT)/core/shared/platform/linux-sgx
```

**Step 2: Link libvmlib.a to Enclave part and link libvmlib_untrusted.a to App part:**
> libvmlib_untrusted.a is not required in minimal version

```makefile
Enclave_Link_Flags := ... libvmlib.a ...
```

```makefile
App_Link_Flags := ... libvmlib_untrusted.a ...
```

**And link SGX pthread lib to Enclave part:**
> SGX pthread lib is not required in minimal version

```makefile
Enclave_Link_Flags := ... -lsgx_pthread ...
```

**Step 3: Add WAMR folders and SGX SDK folders to Enclave include path:**

```makefile
Enclave_Include_Paths := ... -I$(WAMR_ROOT)/core/iwasm/include \
                         -I$(WAMR_ROOT)/core/shared/utils \
                         -I$(WAMR_ROOT)/core/shared/platform/linux-sgx \
                         -I$(SGX_SDK)/include \
                         -I$(SGX_SDK)/include/tlibc \
                         -I$(SGX_SDK)/include/stlport
```

**Step 4: Configure reserved memory and thread info in file Enclave config file (e.g. Enclave.config.xml) to support WAMR AOT and multi-thread, e.g:**

```xml
<ReservedMemMaxSize>0x400000</ReservedMemMaxSize>
<ReservedMemExecutable>1</ReservedMemExecutable>
<TCSNum>10</TCSNum>
```

**Step 5: To support log output and os_printf() function in Enclave, please implement an ocall_print function, e.g. in Enclave.edl, add:**

```cpp
untrusted {
    void ocall_print([in, string]const char* str);
};
```

In App part, add:

```cpp
void
ocall_print(const char* str)
{
    printf("%s", str);
}
```

And in Enclave part, set the print function:

```cpp
#include "wasm_export.h"
#include "bh_platform.h"

extern "C" {
    typedef void (*os_print_function_t)(const char* message);
    extern void os_set_print_function(os_print_function_t pf);

    void
    enclave_print(const char *message)
    {
        ocall_print(message);
    }
}

// In the beginning of Enclave initialization, add:
os_set_print_function(enclave_print);
```

Embed WAMR vmcore in Linux SGX
------------------------------

Normally we can embed WAMR vmcore in Linux SGX by calling the vmcore exported API's, see [Embed WAMR guide](./embed_wamr.md) for the details. And the the ecall_iwasm_main() function in file Enclave.cpp of enclave-sample also provides sample to invoke wasm app main function with wasm file buffer:

```cpp
void
ecall_iwasm_main(uint8_t *wasm_file_buf, uint32_t wasm_file_size);
```

The enclave-sample also wraps an ecall function to receive commands from App to Enclave, and handle the commands in Enclave by calling the related WAMR vmcore API. The commands and related API's are:

```cpp
typedef enum EcallCmd {
    CMD_INIT_RUNTIME = 0,     /* wasm_runtime_init/full_init() */
    CMD_LOAD_MODULE,          /* wasm_runtime_load() */
    CMD_INSTANTIATE_MODULE,   /* wasm_runtime_instantiate() */
    CMD_LOOKUP_FUNCTION,      /* wasm_runtime_lookup_function() */
    CMD_CREATE_EXEC_ENV,      /* wasm_runtime_create_exec_env() */
    CMD_CALL_WASM,            /* wasm_runtime_call_wasm */
    CMD_EXEC_APP_FUNC,        /* wasm_application_execute_func() */
    CMD_EXEC_APP_MAIN,        /* wasm_application_execute_main() */
    CMD_GET_EXCEPTION,        /* wasm_runtime_get_exception() */
    CMD_DEINSTANTIATE_MODULE, /* wasm_runtime_deinstantiate() */
    CMD_UNLOAD_MODULE,        /* wasm_runtime_unload() */
    CMD_DESTROY_RUNTIME,      /* wasm_runtime_destroy() */
    CMD_SET_WASI_ARGS,        /* wasm_runtime_set_wasi_args() */
    CMD_SET_LOG_LEVEL,        /* bh_log_set_verbose_level() */
};
```

SGX Intel Protected File System
-------------------------------
Intel SGX introduced a feature called [Intel Protection File System Library (IPFS)](https://www.intel.com/content/www/us/en/developer/articles/technical/overview-of-intel-protected-file-system-library-using-software-guard-extensions.html) to create, operate and delete files inside the enclave.
WAMR supports the mapping of IPFS on WASI functions related to file interactions, providing seamless persistence with confidentiality and integrity to the hosted WebAssembly applications in the enclave.

The usage of SGX IPFS is an optional feature.
To opt-in, the support of IPFS requires the following changes:
 - set the flag `WAMR_BUILD_SGX_IPFS=1` when running `cmake`,
 - the enclave must be linked with the trusted IPFS library (`-lsgx_tprotected_fs`),
 - the application outside of the enclave must be linked with the untrusted IPFS library (`-lsgx_uprotected_fs`),
 - the EDL file must include the following import statement:

```edl
from "sgx_tprotected_fs.edl" import *;
```

When using the [enclave-sample](../product-mini/platforms/linux-sgx/enclave-sample/) project, setting the flag `WAMR_BUILD_SGX_IPFS=1` when running `cmake` enables these changes automatically.


### Verification of SGX IPFS
One can observe the usage of IPFS by running the [file sample](../samples/file/) WebAssembly application.
Enabling the SGX IPFS on this sample project leads to the generation of an encrypted text file.


### Mapping of WASI/POSIX to IPFS
This table summarizes how WASI is mapped to POSIX and IPFS.
Since IPFS is a subset of the WASI/POSIX, emulation is performed to fill the missing implementation.

| WASI                   | POSIX             | IPFS                                                                                                                    |
|------------------------|-------------------|-------------------------------------------------------------------------------------------------------------------------|
| `fd_read`              | `readv`           | `sgx_fread`                                                                                                             |
| `fd_write`             | `writev`          | `sgx_fwrite`                                                                                                            |
| `fd_close`             | `close`           | `sgx_fclose`                                                                                                            |
| `path_open`            | `openat`          | `sgx_fopen`                                                                                                             |
| `fd_datasync`          | `fsync`           | `sgx_fflush`                                                                                                            |
| `fd_tell`              | `lseek`           | `sgx_ftell`                                                                                                             |
| `fd_filestat_set_size` | `ftruncate`       | Shrinking files is not supported, nor emulated. Extending files is emulated using `sgx_fseek`/`sgx_ftell`/`sgx_fwrite`. |
| `fd_seek`              | `lseek`           | The POSIX and IPFS behaviors differ. Emulated using `sgx_fseek`/`sgx_ftell`/`sgx_fwrite`.                               |
| `fd_pwrite`            | `pwrite`          | Not supported. Emulated using `sgx_fseek`/`sgx_ftell`/`sgx_fwrite`.                                                     |
| `fd_pread`             | `pread`           | Not supported. Emulated using `sgx_fseek`/`sgx_ftell`/`sgx_fread`.                                                      |
| `fd_allocate`          | `posix_fallocate` | Not supported. Emulated using `sgx_fseek`/`sgx_ftell`/`sgx_fwrite`/`sgx_fflush`.                                        |


### Performance overheads
Many benchmarks have assessed the overheads caused by IPFS through WASI functions using Twine, an early and academic adaptation of WAMR in Intel SGX with WASI support.
The results can be found in [this paper](https://arxiv.org/abs/2103.15860).

### Limitations
The threat model and the limitations of SGX IPFS can be found in [the official documentation](https://www.intel.com/content/dam/develop/external/us/en/documents/overviewofintelprotectedfilesystemlibrary.pdf).


Others
------

- Please add "-sgx" option when generating AoT file for SGX platform, e.g.:

  ```bash
  wamrc -sgx -o test.aot test.wasm
  ```

- The default max heap size of Enclave is 16 MB, it might be not enough when executing some workloads, please modify it in Enclave/Enclave.config.xml with a larger size when exception was thrown:

  ```bash
  Exception: fail to enlarge memory.
  or
  Exception: allocate memory failed.
  ```

  Enclave/Enclave.config.xml, default max heap size is 16 MB:

  ```xml
  <HeapMaxSize>0x1000000</HeapMaxSize>
  ```

