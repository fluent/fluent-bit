WebAssembly Micro Runtime Attributions
======================================

WAMR project reused some components from other open source project:
- **cJson**: used in the host_tool for remotely managing wasm applications
- **contiki-ng**: for the coap protocol implementation
- **freebsd libm**: used in core/shared/platform/alios/bh_math.c
- **LVGL**: for the gui samples and wrapped the wasm graphic layer
- **llvm**: for the AOT/JIT compilation
- **wasm-c-api**: to implement the C-APIs of wasm. using headers and sameples
- **wasmtime**: for the wasi libc implementation
- **zephyr**: for several platform specific examples
- **WebAssembly debugging patch for LLDB**: for extending the ability of LLDB to support wasm debugging
- **libuv**: for the WASI Libc with uvwasi implementation
- **uvwasi**: for the WASI Libc with uvwasi implementation
- **asmjit**: for the Fast JIT x86-64 codegen implementation
- **zydis**: for the Fast JIT x86-64 codegen implementation
- **NuttX ELF headers**: used in core/iwasm/aot/debug/elf_parser.c

The WAMR fast interpreter is a clean room development. We would acknowledge the inspirations by [WASM3](https://github.com/wasm3/wasm3) open source project for the approach of pre-calculated oprand stack location.

|  third party components | version number | latest release | vendor pages | CVE details |
| --- | --- | --- | --- | --- |
| cjson | 1.7.10 | 1.7.14 | https://github.com/DaveGamble/cJSON | https://www.cvedetails.com/vendor/19164/Cjson-Project.html |
| contiki-ng (er-coap) | unspecified | 3.0 | https://github.com/contiki-os/contiki | https://www.cvedetails.com/vendor/16528/Contiki-os.html |
| freebsd libm | unspecified | 13.0 | https://www.freebsd.org/ | https://www.cvedetails.com/vendor/6/Freebsd.html |
| LVGL | 6.0.1 | 7.11.0 | https://lvgl.io/ | |
| llvm | 11.0.1 | 12.0.0 | https://llvm.org | https://www.cvedetails.com/vendor/13260/Llvm.html |
| wasm-c-api | ac9b509f4df86e40e56e9b01f3f49afab0100037 | c9d31284651b975f05ac27cee0bab1377560b87e | https://github.com/WebAssembly/wasm-c-api | |
| wasmtime | unspecified | v0.26.0 | https://github.com/bytecodealliance/wasmtime | |
| zephyr | unspecified | v2.5.0 | https://www.zephyrproject.org/ | https://www.cvedetails.com/vendor/19255/Zephyrproject.html |
| WebAssembly debugging patch for LLDB | unspecified | unspecified | https://reviews.llvm.org/D78801 | |
| libuv | v1.42.0 | v1.44.1 | https://github.com/libuv/libuv | https://www.cvedetails.com/vendor/15402/Libuv-Project.html |
| uvwasi | unspecified | v0.0.12 | https://github.com/nodejs/uvwasi | |
| asmjit | unspecified | unspecified | https://github.com/asmjit/asmjit | |
| zydis | unspecified | e14a07895136182a5b53e181eec3b1c6e0b434de | https://github.com/zyantific/zydis | |
| NuttX ELF headers | 72313301e23f9c2de969fb64b9a0f67bb4c284df | 10.3.0 | https://github.com/apache/incubator-nuttx | |

## Licenses

### cJson

[LICENSE](./test-tools/host-tool/external/cJSON/LICENSE)

### contiki-ng

[LICENSE](./core/shared/coap/er-coap/LICENSE.md)

### freebsd libm

[COPYRIGHT](./core/shared/platform/common/math/COPYRIGHT)

### LVGL

[LICENSE](./samples/littlevgl/LICENCE.txt)

[LICENSE](./core/app-framework/wgl/app/wa-inc/lvgl/LICENCE.txt)

### llvm

[LICENSE](./core/deps/llvm/llvm/LICENCE.txt)

### wasm-c-api

[LICENSE](./samples/wasm-c-api/src/LICENSE)

### wasmtime

[LICENSE](./core/iwasm/libraries/libc-wasi/sandboxed-system-primitives/LICENSE)

[LICENSE](./core/iwasm/libraries/libc-wasi/sandboxed-system-primitives/src/LICENSE)

[LICENSE](./core/iwasm/libraries/libc-wasi/sandboxed-system-primitives/include/LICENSE)

### zephyr

[LICENSE](./samples/gui/wasm-runtime-wgl/src/platform/zephyr/LICENSE)

### wac

[LICENSE](./tests/wamr-test-suites/spec-test-script/LICENSE)

### libuv
[LICENSE](./core/iwasm/libraries/libc-uvwasi/LICENSE_LIBUV)

### uvwasi
[LICENSE](./core/iwasm/libraries/libc-uvwasi/LICENSE_UVWASI)

### asmjit
[LICENSE](./core/iwasm/fast-jit/cg/LICENSE_ASMJIT)

### zydis
[LICENSE](./core/iwasm/fast-jit/cg/LICENSE_ZYDIS)

### NuttX ELF headers

[LICENSE](./core/iwasm/aot/debug/LICENSE_NUTTX)

[NOTICE](./core/iwasm/aot/debug/NOTICE_NUTTX)
