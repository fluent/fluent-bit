# How to use WAMR with Zephyr in user mode

This example demonstrates how to build and run a WebAssembly application in user mode on Zephyr.

> Note: The user mode is not supported on all Zephyr boards. Please refer to the Zephyr documentation for more information.

## Setup

Please refer to the [previous WAMR Zephyr README.md](../simple/README.md) for general Zephyr setup instructions.

And refer to [official documentation of Zephyr user mode](https://docs.zephyrproject.org/latest/kernel/usermode/index.html) for more information about Zephyr user mode.

### Enable user mode

To enable Zephyr user mode, set the `CONFIG_USERSPACE` option to yes in the Zephyr configuration.

```conf
CONFIG_USERSPACE=y
```

And link the WAMR runtime as a separate library in CMakelists.txt.

```cmake
...WAMR CMake set up...

zephyr_library_named (wamr_lib)

zephyr_library_sources (
  ${WAMR_RUNTIME_LIB_SOURCE} 
  wamr_lib.c
)

zephyr_library_app_memory (wamr_partition)
```

The `wamr_partition` is a memory partition that will be granted to the WAMR runtime. It is defined in the Zephyr application code.

```C
K_APPMEM_PARTITION_DEFINE(wamr_partition);
```

When creating a Zephyr thread, set the thread option to `K_USER` and the timeout to `K_FOREVER`. This can ensure that the `wamr_partition` is granted access to the thread before starting it with `k_thread_start`.

### Advantage of using WAMR runtime in Zephyr user mode thread

In a user-mode Zephyr thread, the application can only access a restricted partition of memory it granted to. It creates a sandbox for the WAMR runtime to run in, and the WAMR runtime can only access that memory space, meaning that all global variables in the WAMR runtime and both runtime and wasm app heap memory will be allocated from it. In this way, an extra layer of security is added to the wasm application on top of the wasm sandbox provided by WAMR.

### Example Targets

x86_64 QEMU (x86_64) is a 64-bit x86 target for emulating the x86_64 platform.

```shell
west build -b qemu_x86_tiny . -p always -- -DWAMR_BUILD_TARGET=X86_32
```

Use qemu to run the image.

```shell
qemu-system-i386 -m 32 -cpu qemu32,+nx,+pae -machine pc -device isa-debug-exit,iobase=0xf4,iosize=0x04 -no-reboot -nographic -net none -pidfile qemu.pid -chardev stdio,id=con,mux=on -serial chardev:con -mon chardev=con,mode=readline -icount shift=5,align=off,sleep=off -rtc clock=vm -kernel ./build/zephyr/zephyr.elf
```
