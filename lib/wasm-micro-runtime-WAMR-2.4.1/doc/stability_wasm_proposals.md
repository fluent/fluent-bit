# Wasm Proposals

This document is intended to describe the current status of WebAssembly proposals and WASI proposals in WAMR.

Only track proposals that are followed in the [WebAssembly proposals](https://github.com/WebAssembly/proposals) and [WASI proposals](https://github.com/WebAssembly/WASI/blob/main/Proposals.md).

Normally, the document tracks proposals that are in phase 4. However, if a proposal in an earlier phase receives support, it will be added to the list below.

The _status_ represents the configuration _product-mini/platforms/linux/CMakeLists.txt_. There may be minor differences between the top-level CMakeLists and platform-specific CMakeLists.

Users can turn those features on or off by using compilation options. If a relevant compilation option is not available(`N/A`), it indicates that the feature is permanently enabled.

## On-by-default Wasm Proposals

| Proposal                              | >= Phase 4 | Compilation Option       |
| ------------------------------------- | ---------- | ------------------------ |
| Bulk memory operations                | Yes        | `WAMR_BUILD_BULK_MEMORY` |
| Fixed-width SIMD[^1]                  | Yes        | `WAMR_BUILD_SIMD`        |
| Multi-value                           | Yes        | N/A                      |
| Non-trapping float-to-int conversions | Yes        | N/A                      |
| Reference Types                       | Yes        | `WAMR_BUILD_REF_TYPES`   |
| Sign-extension operators              | Yes        | N/A                      |
| WebAssembly C and C++ API             | No         | N/A                      |

[^1]: llvm-jit and aot only.

## Off-by-default Wasm Proposals

| Proposal                      | >= Phase 4 | Compilation Option         |
| ----------------------------- | ---------- | -------------------------- |
| Garbage collection            | Yes        | `WAMR_BUILD_GC`            |
| Legacy Exception handling[^2] | No         | `WAMR_BUILD_EXCE_HANDLING` |
| Memory64                      | Yes        | `WAMR_BUILD_MEMORY64`      |
| Multiple memories[^3]         | Yes        | `WAMR_BUILD_MULTI_MEMORY`  |
| Reference-Typed Strings       | No         | `WAMR_BUILD_STRINGREF`     |
| Tail call                     | Yes        | `WAMR_BUILD_TAIL_CALL`     |
| Threads[^4]                   | Yes        | `WAMR_BUILD_SHARED_MEMORY` |
| Typed Function References     | Yes        | `WAMR_BUILD_GC`            |

[^2]:
    interpreter only. [a legacy version](https://github.com/WebAssembly/exception-handling/blob/main/proposals/exception-handling/legacy/Exceptions.md).
    This proposal is currently also known as the "legacy proposal" and still
    supported in the web, but can be deprecated in future and the use of
    this proposal is discouraged.

[^3]: interpreter only
[^4]: `WAMR_BUILD_LIB_PTHREAD` can also be used to enable

## Unimplemented Wasm Proposals

| Proposal                                    | >= Phase 4 |
| ------------------------------------------- | ---------- |
| Branch Hinting                              | Yes        |
| Custom Annotation Syntax in the Text Format | Yes        |
| Exception handling[^5]                      | Yes        |
| Extended Constant Expressions               | Yes        |
| Import/Export of Mutable Globals            | Yes        |
| JS String Builtins                          | Yes        |
| Relaxed SIMD                                | Yes        |

[^5]: [up-to-date version](https://github.com/WebAssembly/exception-handling/blob/main/proposals/exception-handling/Exceptions.md)

## On-by-default WASI Proposals

| Proposal | >= Phase 4 | Compilation Option |
| -------- | ---------- | ------------------ |

## Off-by-default WASI Proposals

| Proposal                   | >= Phase 4 | Compilation Option            |
| -------------------------- | ---------- | ----------------------------- |
| Machine Learning (wasi-nn) | No         | `WAMR_BUILD_WASI_NN`          |
| Threads                    | No         | `WAMR_BUILD_LIB_WASI_THREADS` |

## Unimplemented WASI Proposals

| Proposal | >= Phase 4 |
| -------- | ---------- |

## WAMR features

WAMR offers a variety of customizable features to create a highly efficient runtime. For more details, please refer to [build_wamr](./build_wamr.md).
