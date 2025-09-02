# How to create `imports` for wasm_instance_new() properly

It's always been asked how to create `wasm_extern_vec_t *imports` for
`wasm_instance_new()`?

```c
WASM_API_EXTERN own wasm_instance_t* wasm_instance_new(
  wasm_store_t*, const wasm_module_t*, const wasm_extern_vec_t *imports,
  own wasm_trap_t** trap
);
```

`wasm_extern_vec_t *imports` is required to match the requirement of _the
import section_ of a .wasm.

```bash
$ /opt/wabt-1.0.31/bin/wasm-objdump -j Import -x <some_example>.wasm

Section Details:

Import[27]:
 - func[0] sig=2 <pthread_mutex_lock> <- env.pthread_mutex_lock
 - func[1] sig=2 <pthread_mutex_unlock> <- env.pthread_mutex_unlock
 - func[2] sig=2 <pthread_cond_signal> <- env.pthread_cond_signal
 - func[3] sig=3 <host_log> <- env.log
 ...
 - func[11] sig=4 <__imported_wasi_snapshot_preview1_sock_bind> <- wasi_snapshot_preview1.sock_bind
 - func[12] sig=4 <__imported_wasi_snapshot_preview1_sock_connect> <- wasi_snapshot_preview1.sock_connect
 - func[13] sig=4 <__imported_wasi_snapshot_preview1_sock_listen> <- wasi_snapshot_preview1.sock_listen
 - func[14] sig=5 <__imported_wasi_snapshot_preview1_sock_open> <- wasi_snapshot_preview1.sock_open
 - func[15] sig=4 <__imported_wasi_snapshot_preview1_sock_addr_remote> <- wasi_snapshot_preview1.sock_addr_remote
 - func[16] sig=4 <__imported_wasi_snapshot_preview1_args_get> <- wasi_snapshot_preview1.args_get
 - func[17] sig=4 <__imported_wasi_snapshot_preview1_args_sizes_get> <- wasi_snapshot_preview1.args_sizes_get
 ...
```

Developers should fill in _imports_ with enough host functions and make sure
there are no linking problems during instantiation.

```bash
TODO: linking warnings
```

## A natural way

One natural answer is "to create a list which matches every item in _the import
section_" of the .wasm. Since developers can see the section details of
a .wasm by tools like _wasm-objdump_, the answer is doable. Most of the time,
if they also prepare Wasm modules, developers have full control over import
requirements, and they only need to take a look at the order of _the import
section_.

Yes, _the order_. A proper `wasm_extern_vec_t *imports` includes two things:

1. how many `wasm_extern_t`
2. and order of those

Because there is no "name information" in a `wasm_extern_t`. The only way is let
`wasm_instance_new()` to tell which item in _the import section_ of a .wasm
should match any item in `wasm_extern_vec_t *imports` is based on **_index_**.

The algorithm is quite straightforward. The first one of _the import section_ matches
`wasm_extern_vec_t *imports->data[0] `. The second one matches `wasm_extern_vec_t *imports->data[1]`.
And so on.

So the order of `wasm_extern_vec_t *imports` becomes quite a burden. It requires
developers always checking _the import section_ visually.

Until here, the natural way is still workable although involving some handy work.
Right?

## A blocker

Sorry, the situation changes a lot when driving wasm32-wasi Wasm modules with
wasm-c-api.

As you know, WASI provides _a set of crossing-platform standard libraries_ for
Wasm modules, and leaves some _interfaces_ for native platform-dependent supports.
Those _interfaces_ are those import items with the module name `wasi_snapshot_preview1`
in a Wasm module.

It seems not economical to let developers provide their version of host
implementations of the `wasi_snapshot_preview1.XXX` functions. All those support
should be packed into a common library and shared in different Wasm modules.
Like a [cargo WASI](https://github.com/bytecodealliance/cargo-wasi).

WAMR chooses to integrate the WASI support library in the runtime to reduce
developers' compilation work. It brings developers a new thing of a proper
`wasm_extern_vec_t *imports` that developers should avoid overwriting those items
of _the import section_ of a Wasm module that will be provided by the runtime. It
also not economical to code for those functions.

Using module names as a filter seems to be a simple way. But some private
additional c/c++ libraries are supported in WAMR. Those supporting will bring
more import items that don't use `wasi_snapshot_preview1` as module names but are still
covered by the WASM runtime. Like `env.pthread_`. Plus, [the native lib registration](https://github.com/bytecodealliance/wasm-micro-runtime/blob/main/doc/export_native_api.md)
provides another possible way to fill in the requirement of _the import section_.

Let's take summarize. A proper `wasm_extern_vec_t *imports` should include:

1. provides all necessary host implementations for items in _the import section_
2. should not override runtime provided implementation or covered by native
   registrations. functional or econmical.
3. keep them in a right order

## A recommendation

The recommendation is:

- use `wasm_module_imports()` to build the order
- use `wasm_importtype_is_linked()` to avoid overwriting

[wasm-c-api-imports](.) is a simple showcase of how to do that.

First, let's take a look at the Wasm module. [send_recv](./wasm/send_recv.c)
uses both standard WASI and WAMR_BUILD_LIB_PTHREAD supporting. Plus a private
native function `host_log`.

So, `wasm_extern_vec_t *imports` should only include the host implementation of
`host_log` and avoid WASI related(`wasm-c-api-imports.XXX`) and pthread related(`env.pthread_XXX`).

[Here is how to do](./host/example1.c):

- get import types with `wasm_module_imports(0)`. it contains name information

```c
  wasm_importtype_vec_t importtypes = { 0 };
  wasm_module_imports(module, &importtypes);
```

- traversal import types. The final `wasm_importvec_t *imports` should have the
  same order with `wasm_importtype_vec_t`

```c
  for (unsigned i = 0; i < importtypes.num_elems; i++)
```

- use `wasm_importtype_is_linked()` to avoid those covered by the runtime and
  registered natives. A little tip is use "wasm_extern_new_empty()" to create
  a placeholder.

```c
    /* use wasm_extern_new_empty() to create a placeholder */
    if (wasm_importtype_is_linked(importtype)) {
        externs[i] = wasm_extern_new_empty(
            store, wasm_externtype_kind(wasm_importtype_type(importtype)));
        continue;
    }
```

- use `wasm_importtype_module()` to get the module name, use `wasm_importtype_name()`
  to get the field name.

```c
      const wasm_name_t *module_name =
          wasm_importtype_module(importtypes.data[i]);
      const wasm_name_t *field_name =
          wasm_importtype_name(importtypes.data[i]);
```

- fill in `wasm_externvec_t *imports` dynamically and programmatically.

```c
      if (strncmp(module_name->data, "env", strlen("env")) == 0
          && strncmp(field_name->data, "log", strlen("log")) == 0) {
          wasm_functype_t *log_type = wasm_functype_new_2_0(
              wasm_valtype_new_i64(), wasm_valtype_new_i32());
          wasm_func_t *log_func = wasm_func_new(store, log_type, host_logs);
          wasm_functype_delete(log_type);

          externs[i] = wasm_func_as_extern(log_func);
      }
  }
```
