# Introduction

[JetStream 2](https://browserbench.org/JetStream) is a JavaScript and WebAssembly benchmark suite focused on the most advanced web applications. It rewards browsers that start up quickly, execute code quickly, and run smoothly.

**Source**: https://browserbench.org/JetStream/in-depth.html

# Building

Please build iwasm and wamrc, refer to:
- [Build iwasm on Linux](../../../doc/build_wamr.md#linux), or [Build iwasm on MacOS](../../../doc/build_wamr.md#macos)
- [build wamrc AOT compiler](../../../README.md#build-wamrc-aot-compiler)

And install emsdk, refer to [the guide](https://emscripten.org/docs/getting_started/downloads.html). Don't forget to activate
 emsdk and set up environment variables. For example, use instructions below to install it under /opt and activate it:
``` bash
$ cd /opt
$ git clone https://github.com/emscripten-core/emsdk.git
$ cd emsdk
$ git pull
$ ./emsdk install latest
$ ./emsdk activate latest
$ echo "source /opt/emsdk/emsdk_env.sh" >> "${HOME}"/.bashrc
```

And then run `./build.sh` to build the source code, the folder `out` will be created and files will be generated under it.

# Running

Run `./run_aot.sh` to test the benchmark, the native mode and iwasm aot mode will be tested for each workload, and the file `report.txt` will be generated.
