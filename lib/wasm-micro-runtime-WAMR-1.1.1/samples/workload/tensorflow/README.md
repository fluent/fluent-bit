"tensorflow" sample introduction
==============

This sample demonstrates how to build [tensorflow](https://github.com/tensorflow/tensorflow) into WebAssembly with emsdk toolchain and run it with iwasm. Please first install [emsdk](https://github.com/emscripten-core/emsdk):
```bash
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk install 2.0.26
./emsdk activate 2.0.26
```
And set up ensdk environment:
```bash
source emsdk_env.sh
```
Then run
```bash
./build.sh
# for linux platform, or
./build.sh --sgx
# for linux-sgx platform or
./build.sh --threads
# for multi-thread execution (on linux platform)
```
to build tensorflow and run it with iwasm, which basically contains the following steps:
- hack emcc to delete some objects in libc.a
- build tf-lite with emcc compiler
- build iwasm with pthread enable and include libiary under libc-emcc
- run benchmark model with iwasm:
  --max-secs 300: means the max training time cost is 5 minutes, you can adjust it by yourself
