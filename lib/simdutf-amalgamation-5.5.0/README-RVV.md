Developing for RISC-V Vector extension (RVV)
--------------------------------------------------------------------------------

Since RVV is not widely available, we still can check validity of implementation
using either QEMU or Spike emulator.

To use Spike one has to specify the toolchain:

```
$ cmake -B rvvbuild -DCMAKE_TOOLCHAIN_FILE=toolchain-rvv-spike.cmake
$ cmake --build rvvbuild
$ cd rvvbuild
```

To use QEMU, please refer to `.github/workflows/rvv-128-clang-17.yml` for
command line options.
