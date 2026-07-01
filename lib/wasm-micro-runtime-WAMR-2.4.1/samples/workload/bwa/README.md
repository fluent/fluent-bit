"bwa" sample introduction
==============

This sample demonstrates how to build [bwa](https://github.com/lh3/bwa) into
WebAssembly with simd support and run it with iwasm.

## Preparation

please refer to [installation instructions](../README.md).

## Build

``` shell
$ mkdir build && cd build
$ cmake ..
$ make
# to verify
$ ls bwa.wasm
```

## Download sample data

Download the bwa-0.7.15 binary package from
[such an address](https://sourceforge.net/projects/bio-bwa/files/bwakit/bwakit-0.7.15_x64-linux.tar.bz2/download),
a sample data file named **hs38DH.fa** will be used later.

If want more data, please refer to http://hgdownload.cse.ucsc.edu/goldenpath/hg19/bigZips/

## Run workload

Firstly please build iwasm with simd support:

``` shell
$ cd <wamr dir>/product-mini/platforms/linux/
$ mkdir build && cd build
$ cmake ..
$ make
```

Then compile wasm file to aot file and run:

``` shell
$ cd <wamr dir>/samples/workload/bwa/build
$ <wamr dir>/wamr-compiler/build/wamrc -o bwa.aot bwa.wasm
$ <wamr dir>/product-mini/platforms/linux/iwasm --dir=. bwa.aot index hs38DH-extra.fa
```
