Memory usage estimation for a module
====================================

This document aims to provide information useful to make a rough estimation
of necessary memory to execute a WASM module.

Instead of trying to cover every possible configurations,
the following configuration is assumed in this document:

* Module is built with `wasi-sdk`
* Module is loaded with `wasm_runtime_load`
* AOT is used
* WASI is used
* libc heap is used
* app heap is not used
* The pthread implementation in `wasi-libc`, which is based on `wasi-threads`
  (`WASM_ENABLE_LIB_WASI_THREADS`) might be used
* The another pthread implementation (`WASM_ENABLE_LIB_PTHREAD`) is not used

Module
------

The memory to store the module binary is allocated by the embedder and
passed to `wasm_runtime_load`.
While WAMR owns the buffer, WAMR might make in-place modifications to
its contents.

Loaded module and its instances
-------------------------------

Many of data structures for module and instances are allocated from
the global heap. (aka. `wasm_runtime_malloc`)

AOT code section
----------------

Memory to load AOT machine code section.

Because this memory needs to be executable, depending on platforms,
it's allocated from a separate allocator.
For example, `mmap` and `mprotect` are used on POSIX-like platforms.

Linear memory
-------------

A WASM linear memory is either shared or non-shared.

A WASM linear memory has `min` and `max` sizes.
(They correspond to `wasm-ld`'s `--init-memory` and `--max-memory` options.)
They are in the number of WASM pages, each of which is of 65536 bytes.
The `max` is optional for non-shared memory. When omitted, it effectivily
means unlimited.

If `OS_ENABLE_HW_BOUND_CHECK` is enabled, the memory is allocated via
`os_mmap` and `os_mem_commit`/`os_mprotect`.
Otherwise, it's allocated from the global heap.

If the memory is shared and `OS_ENABLE_HW_BOUND_CHECK` is not enabled,
the `max` size of memory is allocated on instantiation.

Otherwise, the `min` size of memory is allocated on instantiation.
It can later grow up to the `max` size via the `memory.grow` instruction.

Libc heap
---------

The libc heap is the last (highest address) part of linear memory,
which might be dynamically grown with `memory.grow` instruction, when
necessary to serve memory allocations within the module.

App heap
--------

Not used for the above mentioned configuration.

You can safely disable the app heap creation by specifying `0` for
the `heap_size` argument of `wasm_runtime_instantiate`.
(It's automatically disabled if malloc/free are exported from the module.)

WASM stack
----------

Operand stack is not used for AOT.

However, a small amount of WASM stack is used for call frames when
certain features are enabled.
(`WASM_ENABLE_DUMP_CALL_STACK` or `WASM_ENABLE_PERF_PROFILING`)

It's allocated from the global heap.

You can specify its size with the `stack_size` argument of
`wasm_runtime_instantiate` and `wasm_runtime_create_exec_env`.
(1 is the minimum because 0 means the default.)

AUX stack (aka. C shadow stack)
-------------------------------

For the main thread, it's a part of the linear memory,
between `__data_end` and `__heap_base` symbols.
You can control the size of this stack with `wasm-ld`'s
`-z stack-size` option.

For threads created by `pthread_create`, libc allocates the stack for
them dynamically from the libc heap.
The size of this stack is inherited from the main thread's one
unless overwritten with `pthread_attr_setstacksize` etc.

WAMR tries to detect overflow/underflow when updating the stack pointer
global. For threads created by `pthread_create`, the detection mechanism
is disabled as of writing this.

Native stack
------------

The stack of the host environment thread which runs WAMR.

For threads created by `pthread_create`, WAMR automatically creates
host threads to run those WASM threads. The stack size of these host
threads are controlled by a build-time configuration.
(`APP_THREAD_STACK_SIZE_DEFAULT`)

In some configurations, runtime overflow can be detected using hardware traps.
(`OS_ENABLE_HW_BOUND_CHECK`)

In some configurations, explicit overflow detection logic can be emitted
into AOT modules themselves. (cf. `os_thread_get_stack_boundary`,
`check_stack_boundary`, `wamrc --stack-bounds-checks=1/0`)

Memory profiling
================

You can collect and dump detailed information about memory usage
by actually running a module with the `WASM_ENABLE_MEMORY_PROFILING`
build-time option.
