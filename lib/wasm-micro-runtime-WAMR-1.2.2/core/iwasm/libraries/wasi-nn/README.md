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


### Build the runtime

Build the runtime image for your execution target type.

`EXECUTION_TYPE` can be:
* `cpu`
* `nvidia-gpu`
* `vx-delegate`

```
EXECUTION_TYPE=cpu
docker build -t wasi-nn-${EXECUTION_TYPE} -f core/iwasm/libraries/wasi-nn/test/Dockerfile.${EXECUTION_TYPE} .
```


### Build wasm app

```
docker build -t wasi-nn-compile -f core/iwasm/libraries/wasi-nn/test/Dockerfile.compile .
```

```
docker run -v $PWD/core/iwasm/libraries/wasi-nn:/wasi-nn wasi-nn-compile
```


### Run wasm app

If all the tests have run properly you will the the following message in the terminal,

```
Tests: passed!
```

* CPU

```
docker run \
    -v $PWD/core/iwasm/libraries/wasi-nn/test:/assets wasi-nn-cpu \
    --dir=/assets \
    --env="TARGET=cpu" \
    /assets/test_tensorflow.wasm
```

* (NVIDIA) GPU

```
docker run \
    --runtime=nvidia \
    -v $PWD/core/iwasm/libraries/wasi-nn/test:/assets wasi-nn-nvidia-gpu \
    --dir=/assets \
    --env="TARGET=gpu" \
    /assets/test_tensorflow.wasm
```

* vx-delegate for NPU (x86 simulater)

```
docker run \
    -v $PWD/core/iwasm/libraries/wasi-nn/test:/assets wasi-nn-vx-delegate \
    --dir=/assets \
    --env="TARGET=gpu" \
    /assets/test_tensorflow.wasm
```



Requirements:
* [NVIDIA docker](https://github.com/NVIDIA/nvidia-docker).

## What is missing

Supported:

* Graph encoding: `tensorflowlite`.
* Execution target: `cpu` and `gpu`.
* Tensor type: `fp32`.
