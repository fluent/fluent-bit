# Malformed Test Cases
This folder contains malformed test cases collected from github and peach fuzzer. More cases should be added to here when found.

# Note
Malformed tests are currently for testing running mode of interpreter including classic interpreter and fast interpreter.

# Test
Use the provided python script to test a wasm runtime:
``` shell
python malformed_test.py -r "path/to/runtime"
```

For example you can test wasmtime with:
``` shell
python malformed_test.py -r "/usr/bin/wasmtime"
```
If no args is passed to the script, the default runtime `/usr/bin/iwasm` will be used.

