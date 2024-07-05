

The "basic" sample project
==============

This sample demonstrates a few basic usages of embedding WAMR:
- initialize runtime
- load wasm app and instantiate the module
- call wasm function and pass arguments
- export native functions to the WASM apps
- wasm function calls native function and pass arguments
- deinitialize runtime

Build this sample
==============
Execute the ```build.sh``` script then all binaries including wasm application files would be generated in 'out' directory.

```
$ ./build.sh
```

Run the sample
==========================
Enter the out directory.
```
$ cd ./out/
$
$ ./basic -f wasm-apps/testapp.wasm
calling into WASM function: generate_float
Native finished calling wasm function generate_float(), returned a float value: 102009.921875f
calling into WASM function: float_to_string
calling into native function: intToStr
calling into native function: get_pow
calling into native function: intToStr
Native finished calling wasm function: float_to_string, returned a formatted string: 102009.921
```
Or execute the ```run.sh``` script in ```samples/basic``` folder.
```
$ ./run.sh
calling into WASM function: generate_float
Native finished calling wasm function generate_float(), returned a float value: 102009.921875f
calling into WASM function: float_to_string
calling into native function: intToStr
calling into native function: get_pow
calling into native function: intToStr
Native finished calling wasm function: float_to_string, returned a formatted  string: 102009.921
```




