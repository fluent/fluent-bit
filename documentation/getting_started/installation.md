# Build and Install

[Fluent Bit](http://fluentbit.io) uses [CMake](http://cmake.org) as it build system. The suggested procedure to prepare the build system consist on the following steps:

## Prepare environment

> In the following steps you can find exact commands to build and install the project with the default options. If you already know how CMake works you can skip this part and look at the build options available.

Create a temporary _build/_ directory inside the Fluent Bit sources:

```bash
$ mkdir build
$ cd build/
```

Let [CMake](http://cmake.org) configure the project specifying where the root path is located:


```bash
$ cmake ../
-- The C compiler identification is GNU 4.9.2
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- The CXX compiler identification is GNU 4.9.2
-- Check for working CXX compiler: /usr/bin/c++
-- Check for working CXX compiler: /usr/bin/c++ -- works
...
-- Could NOT find Doxygen (missing:  DOXYGEN_EXECUTABLE)
-- Looking for accept4
-- Looking for accept4 - not found
-- Configuring done
-- Generating done
-- Build files have been written to: /home/edsiper/coding/fluent-bit/build
```

Now you are ready to start the compilation process through the simple _make_ command:

```bash
$ make
Scanning dependencies of target msgpack
[  2%] Building C object lib/msgpack-1.1.0/CMakeFiles/msgpack.dir/src/unpack.c.o
[  4%] Building C object lib/msgpack-1.1.0/CMakeFiles/msgpack.dir/src/objectc.c.o
[  7%] Building C object lib/msgpack-1.1.0/CMakeFiles/msgpack.dir/src/version.c.o
...
[ 19%] Building C object lib/monkey/mk_core/CMakeFiles/mk_core.dir/mk_file.c.o
[ 21%] Building C object lib/monkey/mk_core/CMakeFiles/mk_core.dir/mk_rconf.c.o
[ 23%] Building C object lib/monkey/mk_core/CMakeFiles/mk_core.dir/mk_string.c.o
...
Scanning dependencies of target fluent-bit-static
[ 66%] Building C object src/CMakeFiles/fluent-bit-static.dir/flb_pack.c.o
[ 69%] Building C object src/CMakeFiles/fluent-bit-static.dir/flb_input.c.o
[ 71%] Building C object src/CMakeFiles/fluent-bit-static.dir/flb_output.c.o
...
Linking C executable ../bin/fluent-bit
[100%] Built target fluent-bit-bin
```

to continue installing the binary on the system just do:

```bash
$ make install
```

it's likely you may need root privileges so you can try to prefixing the command with _sudo_.

## Build Options

Fluent Bit provides certain options to CMake that can be enabled or disabled when configuring, please refer to the following tables under the _General Options_, _Input Plugins_ and _Output Plugins_ sections.

### General Options

| option           |  description                         | default  |
|------------------|--------------------------------------|----------|
| WITH_ALL         | Enable all features available        | No       |
| WITH_DEBUG       | Build binaries with debug symbols    | No       |


### Input Plugins

The _input plugins_ provides certain features to gather information from a specific source type which can be a
network interface, some built-in metric or through a specific input device, the following input plugins are
available:

| option           |  description                         | default  |
|-------------------------------------|--------------------------------------|----------|
| [WITH_IN_CPU](../input/cpu.md)      | Enable CPU input plugin              | On       |
| [WITH_IN_KMSG](../input/kmsg.md)    | Enable Kernel log input plugin       | On       |
| [WITH_IN_MEM](../input/mem.md)      | Enable Memory input plugin           | On       |
| [WITH_IN_SERIAL](../input/serial.md)| Enable Serial input plugin           | On       |
| [WITH_IN_STDIN](../input/stdin.md)  | Enable Standard input plugin         | On       |
| [WITH_IN_XBEE](../input/xbee.md)    | Enable Xbee input plugin             | No       |

### Output Plugins

The _output plugins_ gives the capacity to flush the information to some external interface, service or terminal, the following table describes the output plugins available as of this version:

| option           |  description                         | default  |
|------------------|--------------------------------------|----------|
| [WITH_OUT_FLUENTD](../output/fluentd.md) | Enable [Fluentd](http://www.fluentd.org) output plugin | On |
| [WITH_OUT_STDOUT](../output/stdout.md) | Enable STDOUT output plugin          | On       |
| [WITH_OUT_TD](../output/td.md) | Enable [Treasure Data](http://www.treasuredata.com) output plugin | On |