# WASI-NN

## How to use

Enable WASI-NN in the WAMR by spefiying it in the cmake building configuration as follows,

```
set (WAMR_BUILD_WASI_NN  1)
```

The definition of the functions provided by WASI-NN is in the header file `core/iwasm/libraries/wasi-nn/wasi_nn.h`.

By only including this file in your WASM application you will bind WASI-NN into your module.

## Tests

To run the tests we assume that the current directory is the root of the repository.


1. Build the docker image,

```
docker build -t wasi-nn -f core/iwasm/libraries/wasi-nn/test/Dockerfile .
```

2. Run the container

```
docker run wasi-nn
```

If all the tests have run properly you will the the following message in the terminal,

```
Tests: passed!
```

## What is missing

* Only 1 model at a time is supported.
    * `graph` and `graph-execution-context` are ignored.
* Only `tensorflow` (lite) is supported.
* Only `cpu` is supported.
