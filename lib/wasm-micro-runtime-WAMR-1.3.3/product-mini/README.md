# Build iwasm

iwasm is the executable binary built with WAMR VMcore supports WASI and command line interface. Refer to [**how to build wamr vmcore**](../doc/build_wamr.md) for all the supported CMAKE compilation variables.

If you are building for ARM architecture on a X86 development machine, you can use the `CMAKE_TOOLCHAIN_FILE`  to set the toolchain file for cross compling.

```
cmake .. -DCMAKE_TOOLCHAIN_FILE=$TOOL_CHAIN_FILE  \
         -DWAMR_BUILD_PLATFORM=linux    \
         -DWAMR_BUILD_TARGET=ARM
```

Refer to toolchain sample file [`samples/simple/profiles/arm-interp/toolchain.cmake`](../samples/simple/profiles/arm-interp/toolchain.cmake) for how to build mini product for ARM target architecture.

If you compile for ESP-IDF, make sure to set the right toolchain file for the chip you're using (e.g. `$IDF_PATH/tools/cmake/toolchain-esp32c3.cmake`).
Note that all ESP-IDF toolchain files live under `$IDF_PATH/tools/cmake/`.

## Linux

First of all please install the dependent packages.
Run command below in Ubuntu-22.04:
``` Bash
sudo apt install build-essential cmake g++-multilib libgcc-11-dev lib32gcc-11-dev ccache
```
Or in Ubuntu-20.04
``` Bash
sudo apt install build-essential cmake g++-multilib libgcc-9-dev lib32gcc-9-dev ccache
```
Or in Ubuntu-18.04:
``` Bash
sudo apt install build-essential cmake g++-multilib libgcc-8-dev lib32gcc-8-dev ccache
```
Or in Fedora:
``` Bash
sudo dnf install glibc-devel.i686
```

After installing dependencies, build the source code:
``` Bash
cd product-mini/platforms/linux/
mkdir build && cd build
cmake ..
make
# iwasm is generated under current directory
```

By default in Linux, the `fast interpreter`, `AOT` and `Libc WASI` are enabled, and JIT is disabled.
And the build target is set to X86_64 or X86_32 depending on the platform's bitwidth.

There are total 6 running modes supported: fast interpreter, classi interpreter, AOT, LLVM JIT, Fast JIT and Multi-tier JIT.

(1) To run a wasm file with `fast interpreter` mode - build iwasm with default build and then:
```Bash
iwasm <wasm file>
```
Or
```Bash
mkdir build && cd build
cmake .. -DWAMR_BUILD_INTERP=1
make
```

(2) To disable `fast interpreter` and enable `classic interpreter` instead:
``` Bash
mkdir build && cd build
cmake .. -DWAMR_BUILD_FAST_INTERP=0
make
```

(3) To run an AOT file, firstly please refer to [Build wamrc AOT compiler](../wamr-compiler/README.md) to build wamrc, and then:
```Bash
wamrc -o <AOT file> <WASM file>
iwasm <AOT file>
```

(4) To enable the `LLVM JIT` mode, firstly we should build the LLVM library:
``` Bash
cd product-mini/platforms/linux/
./build_llvm.sh     (The llvm source code is cloned under <wamr_root_dir>/core/deps/llvm and auto built)
```

Then pass argument `-DWAMR_BUILD_JIT=1` to cmake to enable LLVM JIT:
``` Bash
mkdir build && cd build
cmake .. -DWAMR_BUILD_JIT=1
make
```

Note:
By default, the LLVM Orc JIT with Lazy compilation is enabled to speedup the lanuching process and reduce
the JIT compilation time by creating backend threads to compile the WASM functions parallely, and for the
main thread, the functions in the module will not be compiled until they are firstly called and haven't been
compiled by the compilation threads.

If developer wants to disable the Lazy compilation, we can:
``` Bash
mkdir build && cd build
cmake .. -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_LAZY_JIT=0
make
```
In which all the WASM functions will be previously compiled before main thread starts to run the wasm module.

(5) To enable the `Fast JIT` mode:
``` Bash
mkdir build && cd build
cmake .. -DWAMR_BUILD_FAST_JIT=1
make
```
The Fast JIT is a lightweight JIT engine with quick startup, small footprint and good portability, and gains ~50% performance of AOT.

(6) To enable the `Multi-tier JIT` mode:
``` Bash
mkdir build && cd build
cmake .. -DWAMR_BUILD_FAST_JTI=1 -DWAMR_BUILD_JIT=1
make
```
The Multi-tier JIT is a two level JIT tier-up engine, which launchs Fast JIT to run the wasm module as soon as possible and creates backend threads to compile the LLVM JIT functions at the same time, and when the LLVM JIT functions are compiled, the runtime will switch the extecution from the Fast JIT jitted code to LLVM JIT jitted code gradually, so as to gain the best performance.

## Linux SGX (Intel Software Guard Extension)


Please see [Build and Port WAMR vmcore for Linux SGX](../doc/linux_sgx.md) for the details.

## MacOS


Make sure to install Xcode from App Store firstly, and install cmake.

If you use Homebrew, install cmake from the command line:
``` Bash
brew install cmake
```

Then build the source codes:
``` Bash
cd product-mini/platforms/darwin/
mkdir build
cd build
cmake ..
make
# iwasm is generated under current directory
```
By default in MacOS, the `fast interpreter`, `AOT` and `Libc WASI` are enabled, and JIT is disabled.
And the build target is set to X86_64 or X86_32 depending on the platform's bitwidth.

To run a wasm file with interpreter mode:
```Bash
iwasm <wasm file>
```
To run an AOT file, firstly please refer to [Build wamrc AOT compiler](../wamr-compiler/README.md) to build wamrc, and then:
```Bash
wamrc -o <AOT file> <WASM file>
iwasm <AOT file>
```
Note:
For how to build the `JIT` mode and `classic interpreter` mode, please refer to [Build iwasm on Linux](../doc/build_wamr.md#linux).

WAMR provides some features which can be easily configured by passing options to cmake, please see [WAMR vmcore cmake building configurations](../doc/build_wamr.md#wamr-vmcore-cmake-building-configurations) for details. Currently in MacOS, interpreter, AOT, and builtin libc are enabled by default.

## Windows


Make sure `MSVC` and `cmake` are installed and available in the command line environment

Then build the source codes:
``` Bash
cd product-mini/platforms/windows/
mkdir build
cd build
cmake ..
cmake --build . --config Release
# ./Release/iwasm.exe is generated
```

By default in Windows, the `fast interpreter`, `AOT` and `Libc WASI` are enabled, and JIT is disabled.

To run a wasm file with interpreter mode:
```Bash
iwasm.exe <wasm file>
```
To run an AOT file, firstly please refer to [Build wamrc AOT compiler](../wamr-compiler/README.md) to build wamrc, and then:
```Bash
wamrc.exe -o <AOT file> <WASM file>
iwasm.exe <AOT file>
```
Note:
For how to build the `JIT` mode and `classic interpreter` mode, please refer to [Build iwasm on Linux](../doc/build_wamr.md#linux).

WAMR provides some features which can be easily configured by passing options to cmake, please see [WAMR vmcore cmake building configurations](../doc/build_wamr.md#wamr-vmcore-cmake-building-configurations) for details. Currently in Windows, interpreter, AOT, and builtin libc are enabled by default.

## MinGW


First make sure the correct CMake package is installed; the following commands
are valid for the MSYS2 build environment:

```Bash
pacman -R cmake
pacman -S mingw-w64-x86_64-cmake
pacman -S mingw-w64-x86_64-gcc
pacman -S make git
```

Then follow the build instructions for Windows above, and add the following
arguments for cmake:

```Bash
cmake .. -G"Unix Makefiles" \
         -DWAMR_DISABLE_HW_BOUND_CHECK=1
````

Note that WASI will be disabled until further work is done towards full MinGW support.

- Since memory access boundary check with hardware trap feature is disabled, when generating the AOT file with `wamrc`, the `--bounds-checks=1` flag should be added to generate the memory access boundary check instructions to ensure the sandbox security:
```bash
wamrc --bounds-checks=1 -o <aot_file> <wasm_file>
```
- Compiler complaining about missing `UnwindInfoAddress` field in `RUNTIME_FUNCTION`
struct (winnt.h).


## VxWorks

VxWorks 7 SR0620 release is validated.

First you need to build a VSB. Make sure *UTILS_UNIX* layer is added in the VSB.
After the VSB is built, export the VxWorks toolchain path by:
```bash
export <vsb_dir_path>/host/vx-compiler/bin:$PATH
```
Now switch to iwasm source tree to build the source code:
```bash
cd product-mini/platforms/vxworks/
mkdir build
cd build
cmake ..
make
```
Create a VIP based on the VSB. Make sure the following components are added:
* INCLUDE_POSIX_PTHREADS
* INCLUDE_POSIX_PTHREAD_SCHEDULER
* INCLUDE_SHARED_DATA
* INCLUDE_SHL

Copy the generated iwasm executable, the test WASM binary as well as the needed
shared libraries (libc.so.1, libllvm.so.1 or libgnu.so.1 depending on the VSB,
libunix.so.1) to a supported file system (eg: romfs).

Note:
WAMR provides some features which can be easily configured by passing options to cmake, please see [WAMR vmcore cmake building configurations](../doc/build_wamr.md#wamr-vmcore-cmake-building-configurations) for details. Currently in VxWorks, interpreter and builtin libc are enabled by default.

## Zephyr

Please refer to this [README](./platforms/zephyr/simple/README.md) under the Zephyr sample directory for details.

Note:
WAMR provides some features which can be easily configured by passing options to cmake, please see [WAMR vmcore cmake building configurations](../doc/build_wamr.md#wamr-vmcore-cmake-building-configurations) for details. Currently in Zephyr, interpreter, AOT and builtin libc are enabled by default.


## RT-Thread


1. Get rt-thread [system codes](https://github.com/RT-Thread/rt-thread).

2. Enable WAMR software package with menuconfig tool which provided by RT-Thread.

   * Environment in Linux, run command below:

   ```bash
   scons --menuconfig
   ```

   * Environment in Windows ConEmu, run command below:

   ```bash
   menuconfig
   ```

   Select and enable `WAMR` in:

   * RT-Thread online packages
     * tools packages
       * WebAssembly Micro Runtime (WAMR)

3. Configure `WAMR` with menuconfig tool.

   you can choice features of iwasm below:

   * Enable testing parameters of iwasm
   * Enable interpreter Mode / Fast interpreter Mode
   * Use built-libc
   * Enable AOT

4. Exit menuconfig tool and save configure, update and download package.

   ```bash
   pkgs --update
   ```

5. build project and download the binary to boards.

   ```bash
   scons
   ```

   or build project with 8-thread by using command below:

   ```bash
   scons -j8
   ```

   after project building, you can got an binary file named `rtthread.bin`, then you can download this file to the MCU board.

## Android

able to generate a shared library support Android platform.
- need an [android SDK](https://developer.android.com/studio). Go and get the "Command line tools only"
- look for a command named *sdkmanager* and download below components. version numbers might need to check and pick others
   - "build-tools;29.0.3"
   - "cmake;3.10.2.4988404"
   - "ndk;latest"
   - "patcher;v4"
   - "platform-tools"
   - "platforms;android-29"
- add bin/ of the downloaded cmake to $PATH
- export ANDROID_HOME=/the/path/of/downloaded/sdk/
- export ANDROID_NDK_LATEST_HOME=/the/path/of/downloaded/sdk/ndk/2x.xxx/
- ready to go

Use such commands, you are able to compile with default configurations. Any compiling requirement should be satisfied by modifying product-mini/platforms/android/CMakeList.txt. For example, chaning ${WAMR_BUILD_TARGET} in CMakeList could get different libraries support different ABIs.

``` shell
$ cd product-mini/platforms/android/
$ mkdir build
$ cd build
$ cmake ..
$ make
$ # check output in distribution/wasm
$ # include/ includes all necesary head files
$ # lib includes libiwasm.so
```

## NuttX

WAMR is intergrated with NuttX, just enable the WAMR in Kconfig option (Application Configuration/Interpreters).

## ESP-IDF

WAMR integrates with ESP-IDF both for the XTENSA and RISC-V chips (esp32x and esp32c3 respectively).

In order to use this, you need at least version 4.3.1 of ESP-IDF.
If you don't have it installed, follow the instructions [here](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/#get-started-get-prerequisites).
ESP-IDF also installs the toolchains needed for compiling WAMR and ESP-IDF.
A small demonstration of how to use WAMR and ESP-IDF can be found under [product_mini](./platforms/esp-idf).
The demo builds WAMR for ESP-IDF and runs a small wasm program.
In order to run it for your specific Espressif chip, edit the [build_and_run.sh](./platforms/esp-idf/build_and_run.sh) file and put the correct toolchain file (see #Cross-compilation) and `IDF_TARGET`.
Before compiling it is also necessary to call ESP-IDF's `export.sh` script to bring all compile time relevant information in scope.

## Docker

[Docker](https://www.docker.com/) will download all the dependencies and build WAMR Core on your behalf.

Make sure you have Docker installed on your machine: [macOS](https://docs.docker.com/docker-for-mac/install/), [Windows](https://docs.docker.com/docker-for-windows/install/) or [Linux](https://docs.docker.com/install/linux/docker-ce/ubuntu/).

Build *iwasm* with the Docker image:

``` Bash
$ cd ci
$ ./build_wamr.sh
$ ls ../build_out/
```

*build_wamr.sh* will generate *linux* compatible libraries ( libiwasm.so and
libvmlib.a ) and an executable binary (*iwasm*) and copy *iwasm* to
*build_out*. All original generated files are still under
*product-mini/platforms/linux/build*.

## FreeBSD

First, install the dependent packages:
```shell
sudo pkg install gcc cmake wget
```

Then you can run the following commands to build iwasm with default configurations:
```shell
cd product-mini/platforms/freebsd
mkdir build && cd build
cmake ..
make
```


## AliOS-Things

1. a developerkit board id needed for testing
2. download the AliOS-Things code
   ``` Bash
   git clone https://github.com/alibaba/AliOS-Things.git
   ```
3. copy <wamr_root_dir>/product-mini/platforms/alios-things directory to AliOS-Things/middleware, and rename it as iwasm
   ``` Bash
   cp -a <wamr_root_dir>/product-mini/platforms/alios-things middleware/iwasm
   ```
4. create a link to <wamr_root_dir> in middleware/iwasm/ and rename it to wamr
   ``` Bash
   ln -s <wamr_root_dir> middleware/iwasm/wamr
   ```
5. modify file app/example/helloworld/helloworld.c, patch as:
   ``` C
   #include <stdbool.h>
   #include <aos/kernel.h>
   extern bool iwasm_init();
   int application_start(int argc, char *argv[])
   {
        int count = 0;
        iwasm_init();
       ...
   }
   ```
6. modify file app/example/helloworld/aos.mk
   ``` C
      $(NAME)_COMPONENTS := osal_aos iwasm
   ```
7. build source code and run
   For linux host:

   ``` Bash
   aos make helloworld@linuxhost -c config
   aos make
   ./out/helloworld@linuxhost/binary/helloworld@linuxhost.elf
   ```

   For developerkit:
   Modify file middleware/iwasm/aos.mk, patch as:

   ``` C
   WAMR_BUILD_TARGET := THUMBV7M
   ```

   ``` Bash
   aos make helloworld@developerkit -c config
   aos make
   ```
   download the binary to developerkit board, check the output from serial port

## Cosmopolitan Libc
Currently, only x86_64 architecture with interpreter modes is supported.

Setup `cosmocc` as described in [Getting Started](https://github.com/jart/cosmopolitan/#getting-started) being sure to get its `bin` directory into `PATH`.

Build iwasm
``` Bash
export CC=x86_64-unknown-cosmo-cc
export CXX=x86_64-unknown-cosmo-c++
rm -rf build
mkdir build
cmake -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_FAST_INTERP=1 -B build
cmake --build build -j
```

Run like
``` Bash
./build/iwasm.com <wasm file>
```
