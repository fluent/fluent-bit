WAMR supports *wasm-c-api* in both *interpreter* mode and *aot* mode.

Before staring, we need to download and intall [WABT](https://github.com/WebAssembly/wabt/releases/latest).

``` shell
$ cd /opt
$ wget https://github.com/WebAssembly/wabt/releases/download/1.0.31/wabt-1.0.31-ubuntu.tar.gz
$ tar -xzf wabt-1.0.31-ubuntu.tar.gz
$ mv wabt-1.0.31 wabt
```

By default, all samples are compiled and run in "interpreter" mode.


``` shell
$ mkdir build
$ cd build
$ cmake ..
$ make
$ # it will build a library with c-api supporting.
$ # Also copy *.wasm from ../src/
$ # and generate executable files
$ # now, it is ok to run samples
$ ./hello
$ ...
$ ./global
$ ...
$ ./callback
$ ...
```

They can be compiled and run in *aot* mode when some compiling flags are given.

``` shell
$ mkdir build
$ cd build
$ cmake -DWAMR_BUILD_INTERP=0 -DWAMR_BUILD_AOT=1 ..
$ make
$ # it will build a library with c-api supporting.
$ # Also copy *.wasm from ../src/
$ # and transform *.wasm to *.aot
$ # and generate executable files
$ # now, it is ok to run samples
$ ./hello
$ ...
$ ./global
$ ...
$ ./callback
$ ...
```
