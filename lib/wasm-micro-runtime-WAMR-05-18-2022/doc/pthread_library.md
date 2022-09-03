# WAMR pthread library

WAMR provides a built-in library to support pthread APIs. You can call pthread APIs in your application source code.

## Build and run
Suppose you have written a C program calling pthread_create() to create a thread, and the file name is main.c
``` C
#include <stdio.h>
#include <pthread.h>

void *thread_routine(void *arg)
{
    printf("Enter thread\n");
    pthread_exit(NULL);
    return NULL;
}

int main(int argc, char** argv)
{
    pthread_t tid;

    if (0 != pthread_create(&tid, NULL, thread_routine, NULL)) {
        printf("Failed to create thread\n");
    }

    if (0 != pthread_join(tid, NULL)) {
        printf("Failed to join thread %d.\n", tid);
    }

    printf("Exit\n");

    return 0;
}
```
**Build with libc-builtin**

To build this C program into WebAssembly app with libc-builtin, you can use this command:
``` bash
/opt/wasi-sdk/bin/clang  --target=wasm32        \
    --sysroot=${WAMR_ROOT}/wamr-sdk/app/libc-builtin-sysroot   \
    -O3 -pthread -nostdlib -z stack-size=32768      \
    -Wl,--shared-memory             \
    -Wl,--initial-memory=131072,--max-memory=131072 \
    -Wl,--allow-undefined-file=${WAMR_ROOT}/wamr-sdk/app/libc-builtin-sysroot/share/defined-symbols.txt \
    -Wl,--no-entry -Wl,--export=main                \
    -Wl,--export=__heap_base,--export=__data_end    \
    -Wl,--export=__wasm_call_ctors  \
    main.c -o test.wasm
# -pthread: it will enable some dependent WebAssembly features for thread
# -nostdlib: disable the WASI standard library as we are using WAMR builtin-libc
# -z stack-size=: specify the total aux stack size
# -Wl,--export=__heap_base,--export=__data_end: export these globals so the runtime can resolve the total aux stack size and the start offset of the stack top
# -Wl,--export=__wasm_call_ctors: export the init function to initialize the passive data segments
```

**Build with libc-WASI**

You can also build this program with WASI, but we need to make some changes to wasi-sysroot:

1. disable malloc/free of wasi, as they are not atomic operations:
    ``` bash
    /opt/wasi-sdk/bin/llvm-ar -d /opt/wasi-sdk/share/wasi-sysroot/lib/wasm32-wasi/libc.a dlmalloc.o
    ```
2. copy the pthread.h to wasi-sysroot so the compiler can find it:
    ``` bash
    cp ${WAMR_ROOT}/wamr-sdk/app/libc-builtin-sysroot/include/pthread.h /opt/wasi-sdk/share/wasi-sysroot/include
    ```
> Note: </br>
>1. Remember to back up the original sysroot files

Then build the program with this command:
``` bash
/opt/wasi-sdk/bin/clang -pthread -O3                \
    -Wl,--shared-memory,--max-memory=196608         \
    -Wl,--allow-undefined,--no-check-features       \
    -Wl,--export=__heap_base,--export=__data_end    \
    main.c -o test.wasm
# -Wl,--no-check-features: the errno.o in wasi-sysroot is not compatible with pthread feature, pass this option to avoid errors
```

**Build with EMCC**

> Note: This document is based on `emcc 2.0.26`, other version may not work with these commands

EMCC's `-pthread` option is not compatible with standalone mode, we need to pass `-mbulk-memory -matomics` to the compiler and `--shared-memory,--no-check-features` to linker manually

EMCC provides some empty implementation for pthread related APIs, we need to remove them from emcc's libc.
``` bash
cd ${emsdk_dir}/upstream/emscripten/cache/sysroot/lib/wasm32-emscripten
emar d libc.a library_pthread_stub.o
emranlib libc.a
```

``` bash
emcc -O3 -mbulk-memory -matomics -s MALLOC="none"   \
     -Wl,--export=__data_end,--export=__heap_base   \
     -Wl,--shared-memory,--no-check-features        \
     -s ERROR_ON_UNDEFINED_SYMBOLS=0                \
     main.c -o test.wasm
```

**Build AOT module**

You can build the wasm module into AOT module with pthread support, please pass option `--enable-multi-thread` to wamrc:
``` bash
wamrc --enable-multi-thread -o test.aot test.wasm
```

Currently WAMR disables pthread library by default. To run the module with pthread support, please build the runtime with `-DWAMR_BUILD_LIB_PTHREAD=1`
``` bash
cd ${WAMR_ROOT}/product-mini/platforms/linux
mkdir build && cd build
cmake .. -DWAMR_BUILD_LIB_PTHREAD=1
make
# Then you can run the wasm module above:
./iwasm test.wasm
# Or the AOT module:
# ./iwasm test.aot
```

[Here](../samples/multi-thread) is also a sample to show how wasm-apps use pthread APIs to create threads, and how to build it with cmake. You can build this sample and have a try:
``` bash
cd ${WAMR_ROOT}/samples/multi-thread
mkdir build && cd build
cmake ..
make
# Run wasm application
./iwasm wasm-apps/test.wasm
```


## Aux stack seperation
The compiler may use some spaces in the linear memory as an auxiliary stack. When pthread is enabled, every thread should have its own aux stack space, so the total aux stack space reserved by the compiler will be divided into N + 1 parts, where N is the maximum number of threads that can be created by the user code.

The default value of N is 4, which means you can create 4 threads at most. This value can be changed by an option if you are using product-mini:
``` bash
./iwasm --max-threads=n test.wasm
```
If you are going to develop your own runtime product, you can use the API `wasm_runtime_set_max_thread_num` or init arg `init_args.max_thread_num` to set the value, or you can change the macro `CLUSTER_MAX_THREAD_NUM` in [config.h](../core/config.h).

> Note: the total size of aux stack reserved by compiler can be set with `-z stack-size` option during compilation. If you need to create more threads, please set a larger value, otherwise it is easy to cause aux stack overflow.

## Supported APIs
``` C
/* Thread APIs */
int pthread_create(pthread_t *thread, const void *attr,
                   void *(*start_routine) (void *), void *arg);

int pthread_join(pthread_t thread, void **retval);

int pthread_detach(pthread_t thread);

int pthread_cancel(pthread_t thread);

pthread_t pthread_self(void);

void pthread_exit(void *retval);

/* Mutex APIs */
int pthread_mutex_init(pthread_mutex_t *mutex, const void *attr);

int pthread_mutex_lock(pthread_mutex_t *mutex);

int pthread_mutex_unlock(pthread_mutex_t *mutex);

int pthread_mutex_destroy(pthread_mutex_t *mutex);

/* Cond APIs */
int pthread_cond_init(pthread_cond_t *cond, const void *attr);

int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);

int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                           unsigned int useconds);

int pthread_cond_signal(pthread_cond_t *cond);

int pthread_cond_broadcast(pthread_cond_t *cond);

int pthread_cond_destroy(pthread_cond_t *cond);

/* Pthread key APIs */
int pthread_key_create(pthread_key_t *key, void (*destructor)(void *));

int pthread_setspecific(pthread_key_t key, const void *value);

void *pthread_getspecific(pthread_key_t key);

int pthread_key_delete(pthread_key_t key);
```

## Known limits
- `pthread_attr_t`, `pthread_mutexattr_t` and `pthread_condattr_t` are not supported yet, so please pass `NULL` as the second argument of `pthread_create`, `pthread_mutex_init` and `pthread_cond_init`.
- The `errno.o` in wasi-sysroot is not compatible with this feature, so using errno in multi-thread may cause unexpected behavior.
- Currently `struct timespec` is not supported, so the prototype of `pthread_cond_timedwait` is different from the native one, it takes an unsigned int argument `useconds` to indicate the waiting time.
