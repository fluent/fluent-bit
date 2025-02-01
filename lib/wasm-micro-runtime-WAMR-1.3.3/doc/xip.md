# WAMR XIP (Execution In Place) feature introduction

Some IoT devices may require to run the AOT file from flash or ROM which is read-only, so as to reduce the memory consumption, or resolve the issue that there is no executable memory available to run AOT code. In such case, the AOT code inside the AOT file shouldn't be duplicated into memory and shouldn't be modified (or patched) by the AOT relocations. To address this, WAMR implements the XIP (Execution In Place) feature, which generates the AOT relocations as few as possible:
- In the AOT code, an AOT function calls other functions with indirect mode: it doesn't call other functions directly, but looks up their pointers from the function pointer table passed by its first argument exec_env, and then calls the function pointer found. By this way the relocations to other functions are eliminated.
- Eliminate the calls to the LLVM intrinsic functions, or, replace calling them with calling runtime self implemented functions instead, e.g. the calling to `llvm.experimental.constrained.fadd.f32` is replaced by the calling to `aot_intrinsic_fadd_f32`.

The XIP file is an AOT file without (or with few) relocations to patch the AOT code (or text section). Developer can use the option `--enable-indirect-mode --disable-llvm-intrinsics` for wamrc to generate the AOT file, e.g.:
```bash
wamrc --enable-indirect-mode --disable-llvm-intrinsics -o <aot_file> <wasm_file>
or
wamrc --xip -o <aot_file> <wasm_file>
```

Note: --xip is a short option for --enable-indirect-mode --disable-llvm-intrinsics

## Known issues

There may be some relocations to the ".rodata" like sections which require to patch the AOT code. More work will be done to resolve it in the future.

## Tuning the XIP intrinsic functions

WAMR provides a default mapping table for some targets, but it may not be the best one for your target. And it doesn't cover all the supported targets.

So, wamrc provides the option `--enable-builtin-intrinsics=<intr1,intr2,...>` to make it possible to tune the intrinsic functions for your target.

Firstly, you should understand why we don't use the LLVM intrinsic functions directly. The reason is that the LLVM intrinsic functions can't map to the native instructions directly, e.g. the LLVM intrinsic function `i32.div_s` can't map to the native instruction if the target doesn't support the division instruction, it will be translated to a function call to the runtime function from libgcc/compiler-rt. This will cause the AOT code to have the relocations to the libgcc/compiler-rt, which is not acceptable for the XIP feature.

So, we need to replace the LLVM intrinsic functions with the runtime self implemented functions, which can be called through the function pointer table (--enable-indirect-mode) and don't have the relocations to the libgcc/compiler-rt (--disable-llvm-intrinsics).

Available intrinsic functions for tuning:

| LLVM intrinsic function | Explanation |
| --- | --- |
| llvm.experimental.constrained.fadd.f32 | float32 add |
| llvm.experimental.constrained.fadd.f64 | float64 add |
| llvm.experimental.constrained.fsub.f32 | float32 sub |
| llvm.experimental.constrained.fsub.f64 | float64 sub |
| llvm.experimental.constrained.fmul.f32 | float32 mul |
| llvm.experimental.constrained.fmul.f64 | float64 mul |
| llvm.experimental.constrained.fdiv.f32 | float32 div |
| llvm.experimental.constrained.fdiv.f64 | float64 div |
| llvm.fabs.f32 | float32 abs |
| llvm.fabs.f64 | float64 abs |
| llvm.ceil.f32 | float32 ceil |
| llvm.ceil.f64 | float64 ceil |
| llvm.floor.f32 | float32 floor |
| llvm.floor.f64 | float64 floor |
| llvm.trunc.f32 | float32 trunc |
| llvm.trunc.f64 | float64 trunc |
| llvm.rint.f32 | float32 rint |
| llvm.rint.f64 | float64 rint |
| llvm.sqrt.f32 | float32 sqrt |
| llvm.sqrt.f64 | float64 sqrt |
| llvm.copysign.f32 | float32 copysign |
| llvm.copysign.f64 | float64 copysign |
| llvm.minnum.f32 | float32 minnum |
| llvm.minnum.f64 | float64 minnum |
| llvm.maxnum.f32 | float32 maxnum |
| llvm.maxnum.f64 | float64 maxnum |
| llvm.ctlz.i32 | int32 count leading zeros |
| llvm.ctlz.i64 | int64 count leading zeros |
| llvm.cttz.i32 | int32 count trailing zeros |
| llvm.cttz.i64 | int64 count trailing zeros |
| llvm.ctpop.i32 | int32 count population |
| llvm.ctpop.i64 | int64 count population |
| f64_convert_i32_s | int32 to float64 |
| f64_convert_i32_u | uint32 to float64 |
| f32_convert_i32_s | int32 to float32 |
| f32_convert_i32_u | uint32 to float32 |
| f64_convert_i64_s | int64 to float64 |
| f64_convert_i64_u | uint64 to float64 |
| f32_convert_i64_s | int64 to float32 |
| f32_convert_i64_u | uint64 to float32 |
| i32_trunc_f32_s | float32 to int32 |
| i32_trunc_f32_u | float32 to uint32 |
| i32_trunc_f64_s | float64 to int32 |
| i32_trunc_f64_u | float64 to uint32 |
| i64_trunc_f64_s | float64 to int64 |
| i64_trunc_f64_u | float64 to uint64 |
| i64_trunc_f32_s | float32 to int64 |
| i64_trunc_f32_u | float32 to uint64 |
| f32_demote_f64 | float64 to float32 |
| f64_promote_f32 | float32 to float64 |
| f32_cmp | float32 compare |
| f64_cmp | float64 compare |
| i64.div_s | int64 div |
| i64.div_u | uint64 div |
| i32.div_s | int32 div |
| i32.div_u | uint32 div |
| i64.rem_s | int64 rem |
| i64.rem_u | uint64 rem |
| i32.rem_s | int32 rem |
| i32.rem_u | uint32 rem |
| i64.or | int64 or |
| i64.and | int64 and |
| i32.const | emit i32 const into constant table |
| i64.const | emit i64 const into constant table |
| f32.const | emit f32 const into constant table |
| f64.const | emit f64 const into constant table |

And also provide combined intrinsic functions to simplify the tuning:

* all: all the above intrinsic functions
* i32.common: i32.div_s, i32.div_u, i32.rem_s, i32.rem_u
* i64.common: i64.div_s, i64.div_u, i64.rem_s, i64.rem_u, i64.or, i64.and
* f32.common: f32_cmp, llvm.experimental.constrained.fadd.f32, llvm.experimental.constrained.fsub.f32, llvm.experimental.constrained.fmul.f32, llvm.experimental.constrained.fdiv.f32, llvm.fabs.f32, llvm.ceil.f32, llvm.floor.f32, llvm.trunc.f32, llvm.rint.f32, llvm.sqrt.f32, llvm.copysign.f32, llvm.minnum.f32, llvm.maxnum.f32
* f64.common: f32_demote_f64, f64_promote_f32, f64_cmp, llvm.experimental.constrained.fadd.f64, llvm.experimental.constrained.fsub.f64, llvm.experimental.constrained.fmul.f64, llvm.experimental.constrained.fdiv.f64, llvm.fabs.f64, llvm.ceil.f64, llvm.floor.f64, llvm.trunc.f64, llvm.rint.f64, llvm.sqrt.f64, llvm.copysign.f64, llvm.minnum.f64, llvm.maxnum.f64
* f32xi32: i32_trunc_f32_s, i32_trunc_f32_u, f32_convert_i32_s, f32_convert_i32_u
* f64xi32: i32_trunc_f64_s, i32_trunc_f64_u, f64_convert_i32_s, f64_convert_i32_u
* f32xi64: i64_trunc_f32_s, i64_trunc_f32_u, f32_convert_i64_s, f32_convert_i64_u
* f64xi64: i64_trunc_f64_s, i64_trunc_f64_u, f64_convert_i64_s, f64_convert_i64_u
* constop: i32.const, i64.const, f32.const, f64.const
* fpxint: f32xi32, f64xi32, f32xi64, f64xi64
* fp.common: f32.common, f64.common


### Example

For ARM Cortex-M55, since it has double precision floating point unit, so it can support f32/f64 operations. But as a 32-bit MCU, it can only support 32-bit integer operations. So we can use the following command to generate the XIP binary:

```
wamrc --target=thumbv8m.main --cpu=cortex-m55 --xip --enable-builtin-intrinsics=i64.common -o hello.aot hello.wasm
``` 

For ARM Cortex-M3, since it has no floating point unit, and it can only support 32-bit integer operations. So we can use the following command to generate the XIP binary:

```
wamrc --target=thumbv7m --cpu=cortex-m3 --xip --enable-builtin-intrinsics=i64.common,fp.common,fpxint -o hello.aot hello.wasm
```

Other platforms can be tuned in the same way, which intrinsic should be enabled depends on the target platform's hardware capability.
