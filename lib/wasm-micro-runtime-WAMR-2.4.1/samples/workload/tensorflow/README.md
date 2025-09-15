"tensorflow" sample introduction
==============

This sample demonstrates how to build [tensorflow](https://github.com/tensorflow/tensorflow) into WebAssembly with emsdk toolchain and run it with iwasm.:
```bash
./build.sh
# for linux platform, or
./build.sh --threads
# for multi-threading on linux platform
./build.sh --sgx
# for linux-sgx platform
```
to build tensorflow and run it with iwasm, which basically contains the following steps:
- clone emsdk under `<wamr_dir>/core/deps`, install and activate 2.0.26
- hack emcc to delete some objects in libc.a
- build tf-lite with emcc compiler
- build iwasm with lib-pthread and libc-emcc enabled
- run benchmark model with iwasm:
  --max-secs 300: means the max training time cost is 5 minutes, you can adjust it by yourself
