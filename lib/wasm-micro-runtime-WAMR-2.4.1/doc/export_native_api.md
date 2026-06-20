
Export native API to WASM application
=======================================================



Exporting native API steps
--------------------------

#### Step 1: Declare the function interface in WASM app

Create a header file in a WASM app and declare the functions that are exported from native. In this example, we declare foo and foo2 as below in the header file `example.h`

```c
/*** file name: example.h  ***/

int  foo(int a, int b);
void foo2(char * msg, char * buffer, int buf_len);
```



#### Step 2: Define the native API

Then we should define the native functions in runtime source tree for handling the calls from the WASM app. The native function can be any name, for example **foo_native** and **foo2** here:

``` C
int foo_native(wasm_exec_env_t exec_env , int a, int b)
{
    return a+b;
}

void foo2(wasm_exec_env_t exec_env, char * msg, uint8 * buffer, int buf_len)
{
    strncpy(buffer, msg, buf_len);
}
```

The first parameter exec_env must be defined using type **wasm_exec_env_t** which is the calling convention  by WAMR.

The rest parameters should be in the same types as the parameters of WASM function foo(), but there are a few special cases that are explained in section "Buffer address conversion and boundary check".  Regarding the parameter names, they don't have to be the same, but we would suggest using the same names for easy maintenance.



#### Step 3: Register the native APIs

Register the native APIs in the runtime, then everything is fine. It is ready to build the runtime software.

``` C
// Define an array of NativeSymbol for the APIs to be exported.
// Note: the array must be static defined since runtime
//       will keep it after registration
static NativeSymbol native_symbols[] =
{
    {
        "foo", 		// the name of WASM function name
     	foo_native, // the native function pointer
        "(ii)i"		// the function prototype signature
    },
    {
        "foo2", 		// the name of WASM function name
     	foo2, 			// the native function pointer
        "($*~)"			// the function prototype signature
    }
};

// initialize the runtime before registering the native functions
wasm_runtime_init();

int n_native_symbols = sizeof(native_symbols) / sizeof(NativeSymbol);
if (!wasm_runtime_register_natives("env",
                                   native_symbols,
                                   n_native_symbols)) {
    goto fail1;
}

// natives registration must be done before loading WASM modules
module = wasm_runtime_load(buffer, size, error_buf, sizeof(error_buf));

```

**Function signature**:

The function signature field in **NativeSymbol** structure is a string for describing the function prototype.  It is critical to ensure the function signature is correctly mapping the native function interface.

Each letter in the "()" represents a parameter type, and the one following after ")" represents the return value type. The meaning of each letter:

- '**i**': i32
- '**I**': i64
- '**f**': f32
- '**F**': f64
- '**r**': externref (has to be the value of a `uintptr_t` variable), or all kinds of GC reference types when GC feature is enabled
- '**\***': the parameter is a buffer address in WASM application
- '**~**': the parameter is the byte length of WASM buffer as referred by preceding argument "\*". It must follow after '*', otherwise, registration will fail
- '**$**': the parameter is a string in WASM application

The signature can defined as NULL, then all function parameters are assumed as i32 data type.

**Use EXPORT_WASM_API_WITH_SIG**

The `NativeSymbol` element for `foo2 ` above can be also defined with macro EXPORT_WASM_API_WITH_SIG. This macro can be used when the native function name is the same as the WASM symbol name.

```c
static NativeSymbol native_symbols[] =
{
	EXPORT_WASM_API_WITH_SIG(foo2, "($*~)")   // wasm symbol name will be "foo2"
};
```

​

## Call exported API in WASM application

Now we can call the exported native API in wasm application like this:
``` C
#include <stdio.h>
#include "example.h"   // where the APIs are declared

int main(int argc, char **argv)
{
    int a = 0, b = 1;
    char * msg = "hello";
    char buffer[100];

    int c = foo(a, b);   				// call into native foo_native()
    foo2(msg, buffer, sizeof(buffer));   // call into native foo2()

    return 0;
}
```

## Build native lib into shared library and register it with `iwasm` application

Developer can also build the native library into a shared library and register it with iwasm application:
```bash
iwasm --native-lib=<lib file> <wasm file>
```

Refer to [native lib sample](../samples/native-lib) for more details.


## Buffer address conversion and boundary check

A WebAssembly sandbox ensures applications only access to its own memory with a private address space. When passing a pointer address from WASM to native, the address value must be converted to native address before the native function can access it. It is also the native world's responsibility to check the buffer length is not over its sandbox boundary.



The signature letter '$', '\*' and '\~' help the runtime do automatic address conversion and buffer boundary check, so the native function directly uses the string and buffer address. **Notes**:  if '\*' is not followed by '\~', the native function should not assume the length of the buffer is more than 1 byte.



As function parameters are always passed in 32 bits numbers, you can also use 'i' for the pointer type argument, then you must do all the address conversion and boundary checking in your native function. For example, if you change the foo2 signature  to "(iii)", then you will implement the native part as the following sample:

```c
//
// If the function signature used i32 data type ("i")
// for buffer address or string parameters, here
// is how to do address conversion and boundary check manually
//
void foo2(wasm_exec_env_t exec_env,
          uint32 msg_offset,
          uint32 buffer_offset,
          int32 buf_len)
{
    wasm_module_inst_t module_inst = get_module_inst(exec_env);
    char *buffer;
    char * msg ;

    // do boundary check
    if (!wasm_runtime_validate_app_str_add(msg_offset))
        return 0;

    if (!wasm_runtime_validate_app_addr((uint64)buffer_offset, (uint64)buf_len))
        return;

    // do address conversion
    buffer = wasm_runtime_addr_app_to_native((uint64)buffer_offset);
    msg = wasm_runtime_addr_app_to_native((uint64)msg_offset);

    strncpy(buffer, msg, buf_len);
}
```





## Sandbox security attention

The runtime builder should ensure not broking the memory sandbox when exporting the native function to WASM.

A ground rule:

- Do the pointer address conversion in the native API if "$\*" is not used for the pointer in the function signature

A few recommendations:

- Never pass any structure/class object pointer to native (do data serialization instead)
- Never pass a function pointer to the native

Note: while not recommended here, nothing prevents you from passing
structure/function pointers as far as the native API is aware of
and careful about the ABI used in the wasm module. For example,
C function pointers are usually represented as table indexes which
the native API can call with wasm_runtime_call_indirect() or similar.
However, in this document, we don't recommend to implement your native
API that way unless necessary because it needs extra carefulness.


## Pass structured data or class object

We must do data serialization for passing structured data or class objects between the two worlds of WASM and native. There are two serialization methods available in WASM as below, and yet you can introduce more like json, cbor etc.

- [attributes container](https://github.com/bytecodealliance/wamr-app-framework/blob/main/app-framework/app-native-shared/attr_container.c)
- [restful request/response](https://github.com/bytecodealliance/wamr-app-framework/blob/main/app-framework/app-native-shared/restful_utils.c)

Note the serialization library is separately compiled into WASM and runtime. And the source files are located in the folder "[wamr-app-framework/app-framework/app-native-shared](https://github.com/bytecodealliance/wamr-app-framework/blob/main/app-framework/app-native-shared)“ where all source files will be compiled into both worlds.



The following sample code demonstrates WASM app packs a response structure to buffer, then pass the buffer pointer to the native:

```c
/*** file name: https://github.com/bytecodealliance/wamr-app-framework/blob/main/app-framework/base/app/request.c ***/

void api_response_send(response_t *response)
{
    int size;
    char * buffer = pack_response(response, &size);
    if (buffer == NULL)
        return;

    wasm_response_send(buffer, size); // calling exported native API
    free_req_resp_packet(buffer);
}
```



The following code demonstrates the native API unpack the WASM buffer to local native data structure:

```c
/*** file name: https://github.com/bytecodealliance/wamr-app-framework/blob/main/app-framework/base/native/request_response.c  ***/

bool
wasm_response_send(wasm_exec_env_t exec_env, char *buffer, int size)
{
    if (buffer != NULL) {
        response_t response[1];

        if (NULL == unpack_response(buffer, size, response))
            return false;

        am_send_response(response);

        return true;
    }

    return false;
}
```


## Native API implementation notes

### Async thread termination

When threading support is enabled, a thread can be requested to terminate
itself either explicitly by the `wasm_runtime_terminate` API or implicitly
by cluster-wide activities like WASI `proc_exit`.
If a call to your native function can take long or even forever,
you should make it to respond to termination requests in a timely manner.
There are a few implementation approaches for that:

* Design your API so that it always returns in a timely manner.
  This is the most simple approach when possible.

* Make your native function check the cluster state by calling
  `wasm_cluster_is_thread_terminated` from time to time.
  If `wasm_cluster_is_thread_terminated` returns true, make your
  native function return.
  Note: as of writing this, `wasm_cluster_is_thread_terminated` is not
  exported as a runtime API.

* If your native function is a simple wrapper of blocking system call,
  you can probably use the `wasm_runtime_begin_blocking_op` and
  `wasm_runtime_end_blocking_op` runtime API.
  See the comment in `wamr_export.h` for details.

* If your native function is very complex, it might be simpler to put the
  guts of it into a separate worker process so that it can be cleaned up
  by simply killing it.
