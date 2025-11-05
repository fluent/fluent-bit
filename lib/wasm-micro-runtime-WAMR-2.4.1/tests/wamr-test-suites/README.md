# WAMR test suites

This folder contains test scripts and cases for wamr.

## Help
```
./test_wamr.sh --help
```

## Examples
Test spec cases with fast interpreter mode, which will create folder `workspace`, download the `spec` and `wabt` repo, and build `iwasm` automatically to test spec cases:
```
./test_wamr.sh -s spec -t fast-interp
```

Test spec cases with aot mode, and use the wabt binary release package instead of compiling wabt from the source code:
```
./test_wamr.sh -s spec -t aot -b
```

Test spec cases with all modes (classic-interp/fast-interp/aot/jit):
```
./test_wamr.sh -s spec
```

Test spec cases with aot mode and pthread enabled:
```
./test_wamr.sh -s spec -t aot -p
```

Test spec cases with aot mode and SIMD enabled:
```
./test_wamr.sh -s spec -t aot -S
```

Test spec cases with fast-interp on target x86_32:
```
./test_wamr.sh -s spec -t fast-interp -m x86_32
```

