# wasm-c-api introduction

wasm-c-api is an engine-agnostic API to embed a WASM engine.
In wasm-micro-runtime, it's provided by the header file `wasm_c_api.h`.
Its functionalities are overlapping with `wasm_export.h`, which is
a native API of wasm-micro-runtime. An embedder is supposed to pick
one of these APIs, rather than mixing both of them.

All samples come from the commit 340fd9528cc3b26d22fe30ee1628c8c3f2b8c53b
of [wasm-c-api](https://github.com/WebAssembly/wasm-c-api).

Developer can learn these _APIs_ from
[wasm.h](https://github.com/WebAssembly/wasm-c-api/blob/master/include/wasm.h).

And here are [examples](https://github.com/WebAssembly/wasm-c-api/tree/master/example) which
are helpful.

## FYI

- The thread model of _wasm_c_api_ is

  - An `wasm_engine_t` instance may only be created once per process
  - Every `wasm_store_t` and its objects may only be accessed in a single thread

- `wasm_engine_new`, `wasm_engine_new_with_config`, `wasm_engine_new_with_args`,
  `wasm_engine_delete`should be called in a thread-safe environment. Such
  behaviors are not recommended, and please make sure an appropriate calling
  sequence if it has to be.

  - call `wasm_engine_new` and `wasm_engine_delete` in different threads
  - call `wasm_engine_new` or `wasm_engine_delete` multiple times in
    different threads

## unspported list

Currently WAMR supports most of the APIs, the unsupported APIs are listed as below:

- References

```c
WASM_API_EXTERN own wasm_shared_##name##_t* wasm_##name##_share(const wasm_##name##_t*);
WASM_API_EXTERN own wasm_##name##_t* wasm_##name##_obtain(wasm_store_t*, const wasm_shared_##name##_t*);
```

- Several Module APIs

```c
WASM_API_EXTERN void wasm_module_serialize(const wasm_module_t*, own wasm_byte_vec_t* out);
WASM_API_EXTERN own wasm_module_t* wasm_module_deserialize(wasm_store_t*, const wasm_byte_vec_t*);
```

Currently growing a table or memory by wasm opcode is supported and it is not supported to grow them
by host-side function callings.

- Table Grow APIs

```c
WASM_API_EXTERN bool wasm_table_grow(wasm_table_t*, wasm_table_size_t delta, wasm_ref_t* init);
```

- Memory Grow APIs

```c
WASM_API_EXTERN bool wasm_memory_grow(wasm_memory_t*, wasm_memory_pages_t delta);
```
