# WAMR reference-types introduction

WebAssembly [reference-types](https://github.com/WebAssembly/reference-types) proposal introduces two new types `funcref` and `externref`. With `externref`, It is easier and more efficient to interoperate with host environment. Host references are able to be represented directly by type `externref`.

WAMR has implemented the reference-types proposal. WAMR allows a native method to pass a host object to a WASM application as an `externref` parameter or receives a host object from a WASM application as an `externref` result. Internally, WAMR won't try to parse or dereference `externref`. It is an opaque type.

The restriction of using `externref` in a native method is the host object has to be the value of a `unintptr_t` variable. In other words, it takes **8 bytes** on 64-bit machine and **4 bytes** on 32-bit machines. Please keep that in mind especially when calling `wasm_runtime_call_wasm`.

Please ref to the [sample](../samples/ref-types) for more details.
