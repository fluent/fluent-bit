# wamr-python

## Installation

### Installing from the source code

Installing from local source tree is in _development mode_. The package appears to be installed but still is editable from the source tree.

```bash
$ python -m pip install -e /path/to/wamr-root/binding/python
```

## Usage

```python
import wamr.ffi as ffi
```

### Preparation

The binding will load the shared library _libiwasm.so_ from the WAMR repo. So before running the binding, you need to build the library yourself.

The default compile options are good enough.

Please be aware that `wasm_frame_xxx` and `wasm_trap_xxx` only work well when enabling `WAMR_BUILD_DUMP_CALL_STACK`.

### Examples

There is a [simple example](./samples/hello_procedural.py) to show how to use bindings. Actually, the python binding follows C-APIs. There it should be easy if be familiar with _programming with wasm-c-api_.

Unit test cases under _./tests_ could be another but more complete references.
