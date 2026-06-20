# WAMR MULTI-MODUEL SAMPLE
**WAMR supports *multi-module* in both *interpreter* mode and *aot* mode.**

Multi-modules will determine the running mode based on the type of the main module.


``` shell
$ mkdir build
$ cd build
$ cmake ..
$ make
$ # It will build multi_module runtime and 
$ # wasm file under the ./build .
$ # If you have built wamrc,
$ # aot file will also generate.
$ ./multi_module mC.wasm
$ ...
$ ./multi_module mC.aot
$ ...

