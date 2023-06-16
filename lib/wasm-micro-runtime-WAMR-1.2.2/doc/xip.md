# WAMR XIP (Execution In Place) feature introduction

Some IoT devices may require to run the AOT file from flash or ROM which is read-only, so as to reduce the memory consumption, or resolve the issue that there is no executable memory available to run AOT code. In such case, the AOT code inside the AOT file shouldn't be duplicated into memory and shouldn't be modified (or patched) by the AOT relocations. To address this, WAMR implements the XIP (Execution In Place) feature, which generates the AOT relocations as few as possible:
- In the AOT code, an AOT function calls other functions with indirect mode: it doesn't call other functions directly, but looks up their pointers from the function pointer table passed by its first argument exec_env, and then calls the function pointer found. By this way the relocations to other functions are eliminated.
- Eliminate the calls to the LLVM intrinsic functions, or, replace calling them with calling runtime self implemented functions instead, e.g. the calling to `llvm.experimental.constrained.fadd.f32` is replaced by the calling to `aot_intrinsic_fadd_f32`.

The XIP file is an AOT file without (or with few) relocations to patch the AOT code (or text section). Developer can use the option `--enable-indirect-mode --disable-llvm-intrinsics` for wamrc to generate the AOT file, e.g.:
```bash
wamrc --enable-indirect-mode --disable-llvm-intrinsics -o <aot_file> <wasm_file>
```

## Known issues

There may be some relocations to the ".rodata" like sections which require to patch the AOT code. More work will be done to resolve it in the future.
