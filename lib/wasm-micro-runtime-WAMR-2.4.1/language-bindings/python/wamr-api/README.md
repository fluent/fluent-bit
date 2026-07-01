# WAMR API

* **Notice**: The python package `wamr.wamrapi.wamr` requires a python version >= `3.10`.

## Setup

### Pre-requisites
#### Install requirements
Before proceeding it is necessary to make sure your Python environment is correctly configured. To do this open a terminal session in this directory and perform the following:


```shell
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Build native lib and update bindings

The following command builds the iwasm library and generates the Python bindings,

```sh
# In WAMR root directory
bash language-bindings/python/utils/create_lib.sh
```

This will build and copy libiwasm into the package.

## Samples

- **[basic](./samples/basic)**: Demonstrating how to use basic python bindings.
- **[native-symbol](./samples/native-symbol)**: Desmostrate how to call WASM from Python and how to export Python functions into WASM.
