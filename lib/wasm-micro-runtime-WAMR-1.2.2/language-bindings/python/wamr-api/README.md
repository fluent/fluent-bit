# WARM API

## Setup

### Pre-requisites

Install requirements,

```
pip install -r requirements.txt
```

### Build native lib and update bindings

The following command builds the iwasm library and generates the Python bindings,

```sh
bash language-bindings/python/utils/create_lib.sh
```

This will build and copy libiwasm into the package.

## Examples

There is a [simple example](./samples/main.py) to show how to use bindings.

```
python samples/main.py
```
