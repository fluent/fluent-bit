# AoT-Analyzer: The AoT Binary analysis tool


## Cloning

Clone as normal:

```console
$ git clone 
$ cd aot-analyzer
```

## Building using CMake directly

You'll need [CMake](https://cmake.org). You can then run CMake, the normal way:

```console
$ mkdir build
$ cd build
$ cmake ..
$ cmake --build .
```

To analyze AoT files with GC feature enabled, you need to enable GC feature when compiling this tool:

```console
$ mkdir build
$ cd build
$ cmake -DWAMR_BUILD_GC=1 ..
$ cmake --build .
```

## Running aot-analyzer

Some examples:

```sh
# parse example.aot, and print basic information about AoT file
$ ./aot-analyzer -i example.aot

# parse example.aot, and print the size of text section of the AoT file
$ ./aot-analyzer -t example.aot

# compare these two files, and show the difference in function size between them
$ ./aot-analyzer -c example.aot example.wasm
```

**NOTE**: Using `-c` for file comparison, must ensure that the AoT file is generated based on this Wasm file.


You can use `--help` to get additional help:

```console
$ ./aot-analyzer --help
```