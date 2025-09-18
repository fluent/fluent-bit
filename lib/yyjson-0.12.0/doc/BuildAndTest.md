Building and testing
==============

There are several ways to integrate this library into your project: source code, package manager, and CMake.


# Source code
This library aims to provide a cross-platform JSON library, so it is written in ANSI C (actually C99, but compatible with strict C89). You can copy `yyjson.h` and `yyjson.c` to your project and start using it without any configuration.

The library has been tested with `gcc`, `clang`, `msvc`, `tcc` compilers and `x86`, `arm`, `ppc`, `riscv`, `s390x` architectures in [Github CI](https://github.com/ibireme/yyjson/actions). Please [report a bug](https://github.com/ibireme/yyjson/issues/new?template=bug_report.md) if you encounter any compilation issues.

The library has all features enabled by default, but you can trim out some of them by adding compile-time options. For example, you can disable the JSON writer to reduce the binary size when you don't need serialization, or disable comments support to improve parsing performance. See `Compile-time Options` for details.


# Package manager

You can use some popular package managers like `vcpkg`, `conan`, and `xmake` to download and install yyjson. The yyjson package in these package managers is kept up to date by community contributors. If the version is out of date, please create an issue or pull request on their repository.

## Use vcpkg

You can build and install yyjson using [vcpkg](https://github.com/Microsoft/vcpkg/) dependency manager:

```shell
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh  # ./bootstrap-vcpkg.bat for Powershell
./vcpkg integrate install
./vcpkg install yyjson
```

If the version is out of date, please [create an issue or pull request](https://github.com/Microsoft/vcpkg) on the vcpkg repository.

# CMake

## Use CMake to build the library

Clone the repository and create build directory:
```shell
git clone https://github.com/ibireme/yyjson.git
cmake -E make_directory build; cd build
```

Build static library:
```shell
cmake .. 
cmake --build .
```

Build shared library:
```shell
cmake .. -DBUILD_SHARED_LIBS=ON
cmake --build .
```

Supported CMake options (default OFF):

- `-DYYJSON_BUILD_TESTS=ON` Build all tests.
- `-DYYJSON_BUILD_FUZZER=ON` Build fuzzer with LibFuzzing.
- `-DYYJSON_BUILD_MISC=ON` Build misc.
- `-DYYJSON_BUILD_DOC=ON` Build documentation with doxygen.
- `-DYYJSON_ENABLE_COVERAGE=ON` Enable code coverage for tests.
- `-DYYJSON_ENABLE_VALGRIND=ON` Enable valgrind memory checker for tests.
- `-DYYJSON_ENABLE_SANITIZE=ON` Enable sanitizer for tests.
- `-DYYJSON_ENABLE_FASTMATH=ON` Enable fast-math for tests.
- `-DYYJSON_FORCE_32_BIT=ON` Force 32-bit for tests (gcc/clang/icc).

- `-DYYJSON_DISABLE_READER=ON` Disable JSON reader if you don't need it.
- `-DYYJSON_DISABLE_WRITER=ON` Disable JSON writer if you don't need it.
- `-DYYJSON_DISABLE_INCR_READER=ON` Disable incremental reader if you don't need it.
- `-DYYJSON_DISABLE_UTILS=ON` Disable JSON Pointer, JSON Patch and JSON Merge Patch.
- `-DYYJSON_DISABLE_FAST_FP_CONV=ON` Disable builtin fast floating-pointer conversion.
- `-DYYJSON_DISABLE_NON_STANDARD=ON` Disable non-standard JSON support at compile-time.
- `-DYYJSON_DISABLE_UTF8_VALIDATION=ON` Disable UTF-8 validation at compile-time.
- `-DYYJSON_DISABLE_UNALIGNED_MEMORY_ACCESS=ON` Disable unaligned memory access support at compile-time.


## Use CMake as a dependency

You can download and unzip yyjson to your project directory and link it in your `CMakeLists.txt` file:
```cmake
# Add some options (optional)
set(YYJSON_DISABLE_NON_STANDARD ON CACHE INTERNAL "")

# Add the `yyjson` subdirectory
add_subdirectory(vendor/yyjson)

# Link yyjson to your target
target_link_libraries(your_target PRIVATE yyjson)
```

If your CMake version is higher than 3.11, you can use the following code to let CMake automatically download it:
```cmake
include(FetchContent)

# Let CMake download yyjson
FetchContent_Declare(
    yyjson
    GIT_REPOSITORY https://github.com/ibireme/yyjson.git
    GIT_TAG master # master, or version number, e.g. 0.6.0
)
FetchContent_GetProperties(yyjson)
if(NOT yyjson_POPULATED)
  FetchContent_Populate(yyjson)
  add_subdirectory(${yyjson_SOURCE_DIR} ${yyjson_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

# Link yyjson to your target
target_link_libraries(your_target PRIVATE yyjson)
```


## Use CMake to generate project
If you want to build or debug yyjson with another compiler or IDE, try these commands:
```shell
cmake -E make_directory build; cd build

# Clang for Linux/Unix:
cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++

# Intel ICC for Linux/Unix:
cmake .. -DCMAKE_C_COMPILER=icc -DCMAKE_CXX_COMPILER=icpc

# Other version of GCC:
cmake .. -DCMAKE_C_COMPILER=/usr/local/gcc-8.2/bin/gcc -DCMAKE_CXX_COMPILER=/usr/local/gcc-8.2/bin/g++

# Microsoft Visual Studio for Windows:
cmake .. -G "Visual Studio 16 2019" -A x64
cmake .. -G "Visual Studio 16 2019" -A Win32
cmake .. -G "Visual Studio 15 2017 Win64"

# Xcode for macOS:
cmake .. -G Xcode

# Xcode for iOS:
cmake .. -G Xcode -DCMAKE_SYSTEM_NAME=iOS

# Xcode with XCTest
cmake .. -G Xcode -DYYJSON_BUILD_TESTS=ON
```

## Use CMake to generate documentation

This project uses [doxygen](https://www.doxygen.nl/) to generate the documentation.
Make sure `doxygen` is installed on your system before proceeding,
it's best to use the version specified in `doc/Doxyfile.in`.


To build the documentation:
```shell
cmake -E make_directory build; cd build
cmake .. -DYYJSON_BUILD_DOC=ON
cmake --build .
```

The generated HTML files will be located in `build/doxygen/html`.

You can also browse the pre-generated documentation online:
https://ibireme.github.io/yyjson/doc/doxygen/html/


## Testing With CMake and CTest

Build and run all tests:
```shell
cmake -E make_directory build; cd build
cmake .. -DYYJSON_BUILD_TESTS=ON
cmake --build .
ctest --output-on-failure
```

Build and run tests with [valgrind](https://valgrind.org/) memory checker, (make sure you have `valgrind` installed before proceeding):
```shell
cmake -E make_directory build; cd build
cmake .. -DYYJSON_BUILD_TESTS=ON -DYYJSON_ENABLE_VALGRIND=ON
cmake --build .
ctest --output-on-failure
```

Build and run tests with sanitizer (compiler should be `gcc` or `clang`):
```shell
cmake -E make_directory build; cd build
cmake .. -DYYJSON_BUILD_TESTS=ON -DYYJSON_ENABLE_SANITIZE=ON
cmake --build .
ctest --output-on-failure
```

Build and run code coverage with `gcc`:
```shell
cmake -E make_directory build; cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DYYJSON_BUILD_TESTS=ON -DYYJSON_ENABLE_COVERAGE=ON
cmake --build . --config Debug
ctest --output-on-failure

lcov -c -d ./CMakeFiles --include "*/yyjson.*" -o cov.info
genhtml cov.info -o ./cov_report
```

Build and run code coverage with `clang`:
```shell
cmake -E make_directory build; cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DYYJSON_BUILD_TESTS=ON -DYYJSON_ENABLE_COVERAGE=ON -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build . --config Debug

export LLVM_PROFILE_FILE=cov/profile-%p.profraw
ctest --output-on-failure

ctest_files=$(grep -o "test_\w\+" CTestTestfile.cmake | uniq | tr '\n' ' ')
ctest_files=$(echo $ctest_files | sed 's/  $//' | sed "s/ / -object /g")
llvm-profdata merge -sparse cov/profile-*.profraw -o coverage.profdata
llvm-cov show $ctest_files -instr-profile=coverage.profdata -format=html > coverage.html
```

Build and run fuzz test with [LibFuzzer](https://llvm.org/docs/LibFuzzer.html) (compiler should be `LLVM Clang`, while `Apple Clang` or `gcc` are not supported):
```shell
cmake -E make_directory build; cd build
cmake .. -DYYJSON_BUILD_FUZZER=ON -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build .
./fuzzer -dict=fuzzer.dict ./corpus
```


# Compile-time Options
This library provides some compile-time options that can be defined as 1 to disable specific features during compilation.
For example, to disable the JSON writer:
```shell
cmake -E make_directory build; cd build
cmake .. -DYYJSON_DISABLE_WRITER=ON
gcc -DYYJSON_DISABLE_WRITER=1 ...
```

## YYJSON_DISABLE_READER
Define as 1 to disable JSON reader at compile-time.<br/>
This disables functions with `read` in their name.<br/>
Reduces binary size by about 60%.<br/>
It is recommended when JSON parsing is not required.<br/>

## YYJSON_DISABLE_WRITER
Define as 1 to disable JSON writer at compile-time.<br/>
This disables functions with `write` in their name.<br/>
Reduces binary size by about 30%.<br/>
It is recommended when JSON serialization is not required.<br/>

## YYJSON_DISABLE_INCR_READER
Define as 1 to disable JSON incremental reader at compile-time.<br/>
This disables functions with `incr` in their name.<br/>
It is recommended when JSON incremental reader is not required.<br/>

## YYJSON_DISABLE_UTILS
Define as 1 to disable JSON Pointer, JSON Patch and JSON Merge Patch supports.<br/>
This disables functions with `ptr` or `patch` in their name.<br/>
It is recommended when these functions are not required.<br/>

## YYJSON_DISABLE_FAST_FP_CONV
Define as 1 to disable the fast floating-point number conversion in yyjson.<br/>
Libc's `strtod/snprintf` will be used instead.<br/>
This reduces binary size by about 30%, but significantly slows down the floating-point read/write speed.<br/>
It is recommended when processing JSON with few floating-point numbers.<br/>

## YYJSON_DISABLE_NON_STANDARD
Define as 1 to disable non-standard JSON features support at compile-time:
- YYJSON_READ_ALLOW_INF_AND_NAN
- YYJSON_READ_ALLOW_COMMENTS
- YYJSON_READ_ALLOW_TRAILING_COMMAS
- YYJSON_READ_ALLOW_INVALID_UNICODE
- YYJSON_READ_ALLOW_BOM
- YYJSON_WRITE_ALLOW_INF_AND_NAN
- YYJSON_WRITE_ALLOW_INVALID_UNICODE

This reduces binary size by about 10%, and slightly improves performance.<br/>
It is recommended when not dealing with non-standard JSON.

## YYJSON_DISABLE_UTF8_VALIDATION
Define as 1 to disable UTF-8 validation at compile-time.

Use this if all input strings are guaranteed to be valid UTF-8
(e.g. language-level String types are already validated).

Disabling UTF-8 validation improves performance for non-ASCII strings by about
3% to 7%.

Note: If this flag is enabled while passing illegal UTF-8 strings, the following errors may occur:
- Escaped characters may be ignored when parsing JSON strings.
- Ending quotes may be ignored when parsing JSON strings, causing the string to merge with the next value.
- When serializing with `yyjson_mut_val`, the string's end may be accessed out of bounds, potentially causing a segmentation fault.

## YYJSON_EXPORTS
Define as 1 to export symbols when building the library as a Windows DLL.

## YYJSON_IMPORTS
Define as 1 to import symbols when using the library as a Windows DLL.
