# Native Symbol

This sample demonstrates how to declare a Python function as `NativeSymbol`.

Steps of the example:
1. Load WASM from Python
2. Call `c_func` from WASM.
3. `c_func` calls `python_func` from Python.
4. `python_func` calls `add` from WASM.
5. Result shown by Python.

## Build

Follow instructions [build wamr Python package](../../README.md). 

Compile WASM app example,

```sh
./compile.sh
```

## Run sample

```sh
python main.py
```

Output:

```
python: calling c_func(10)
c: in c_func with input: 10
c: calling python_func(11)
python: in python_func with input: 11
python: calling add(11, 1000)
python: result from add: 1011
c: result from python_func: 1012
c: returning 1013
python: result from c_func: 1013
deleting ExecEnv
deleting Instance
deleting Module
deleting Engine
```
