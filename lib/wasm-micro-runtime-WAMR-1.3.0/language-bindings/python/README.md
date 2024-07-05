# wamr-python

The WAMR Python package contains a set of high-level bindings for WAMR API and WASM-C-API.

## Installation

* **Notice**: This python package need python >= `3.9`.

To Install from local source tree in _development mode_ run the following command,

```bash
python -m pip install -e .
```

In this mode the package appears to be installed but still is editable from the source tree.

## Usage

From the same package you can use two set of APIs.

To use the WAMR API you can import the symbols as follows,

```py
from wamr.wamrapi.wamr import Engine, Module, Instance, ExecEnv
```

In the order hand, to use the WASM-C-API,

```py
import wamr.wasmcapi.ffi as ffi
```

For more information:

* [WAMR API](./wamr-api)
* [WASM-C-API](./wasm-c-api)
