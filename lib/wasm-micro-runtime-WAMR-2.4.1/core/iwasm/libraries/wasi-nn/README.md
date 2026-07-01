# WASI-NN

## How to use

### Host

Enable WASI-NN in the WAMR by specifying it in the cmake building configuration as follows,

```cmake
set (WAMR_BUILD_WASI_NN  1)
```

or in command line

```bash
$ cmake -DWAMR_BUILD_WASI_NN=1 <other options> ...
```

> ![Caution]
> Enabling WAMR_BUILD_WASI_NN will cause the IWASM to link to a shared WAMR library instead of a static one. The WASI-NN backends will then be loaded dynamically when the program is run. You must ensure that all shared libraries are included in the `LD_LIBRARY_PATH`.

#### Compilation options

- `WAMR_BUILD_WASI_NN`. This option enables support for WASI-NN. It cannot function independently and requires specifying a backend. It follows the original WASI-NN specification for naming conventions and uses wasi_nn for import module names.
- `WAMR_BUILD_WASI_EPHEMERAL_NN`. This option adheres to the most recent WASI-NN specification for naming conventions and uses wasi_ephemeral_nn for import module names.
- `WAMR_BUILD_WASI_NN_TFLITE`. This option designates TensorFlow Lite as the backend.
- `WAMR_BUILD_WASI_NN_OPENVINO`. This option designates OpenVINO as the backend.
- `WAMR_BUILD_WASI_NN_LLAMACPP`. This option designates Llama.cpp as the backend.

### Wasm

The definition of functions provided by WASI-NN (Wasm imports) is in the header file [wasi_nn.h](_core/iwasm/libraries/wasi-nn/wasi_nn.h_). By only including this file in a WASM application you will bind WASI-NN into your module.

For some historical reasons, there are two sets of functions in the header file. The first set is the original one, and the second set is the new one. The new set is recommended to use. In code, `WASM_ENABLE_WASI_EPHEMERAL_NN` is used to control which set of functions to use. If `WASM_ENABLE_WASI_EPHEMERAL_NN` is defined, the new set of functions will be used. Otherwise, the original set of functions will be used.

There is a big difference between the two sets of functions, `tensor_type`.

```c
#if WASM_ENABLE_WASI_EPHEMERAL_NN != 0
typedef enum { fp16 = 0, fp32, fp64, u8, i32, i64 } tensor_type;
#else
typedef enum { fp16 = 0, fp32, up8, ip32 } tensor_type;
#endif /* WASM_ENABLE_WASI_EPHEMERAL_NN != 0 */
```

It is required to recompile the Wasm application if you want to switch between the two sets of functions.

#### Openvino installation

If you're planning to use OpenVINO backends, the first step is to install OpenVINO on your computer. To do this correctly, please follow the official installation guide which you can find at this link: https://docs.openvino.ai/2024/get-started/install-openvino/install-openvino-archive-linux.html.

After you've installed OpenVINO, you'll need to let cmake system know where to find it. You can do this by setting an environment variable named `OpenVINO_DIR`. This variable should point to the place on your computer where OpenVINO is installed. By setting this variable, your system will be able to locate and use OpenVINO when needed. You can find installation path by running the following command if using APT `$dpkg -L openvino`. The path should be _/opt/intel/openvino/_ or _/usr/lib/openvino_.

## Tests

To run the tests we assume that the current directory is the root of the repository.

### Build the runtime

Build the runtime image for your execution target type.

`EXECUTION_TYPE` can be:

- `cpu`
- `nvidia-gpu`
- `vx-delegate`
- `tpu`

```bash
$ pwd
<somewhere>/wasm-micro-runtime

$ EXECUTION_TYPE=cpu docker build -t wasi-nn-${EXECUTION_TYPE} -f core/iwasm/libraries/wasi-nn/test/Dockerfile.${EXECUTION_TYPE} .
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

> [!TIP]
> Use _libwasi-nn-tflite.so_ as an example. You shall use whatever you have built.

- CPU

```bash
docker run \
    -v $PWD/core/iwasm/libraries/wasi-nn/test:/assets \
    -v $PWD/core/iwasm/libraries/wasi-nn/test/models:/models \
    wasi-nn-cpu \
    --dir=/ \
    --env="TARGET=cpu" \
    /assets/test_tensorflow.wasm
```

- (NVIDIA) GPU
  - Requirements:
    - [NVIDIA docker](https://github.com/NVIDIA/nvidia-docker).

```bash
docker run \
    --runtime=nvidia \
    -v $PWD/core/iwasm/libraries/wasi-nn/test:/assets \
    -v $PWD/core/iwasm/libraries/wasi-nn/test/models:/models \
    wasi-nn-nvidia-gpu \
    --dir=/ \
    --env="TARGET=gpu" \
    /assets/test_tensorflow.wasm
```

- vx-delegate for NPU (x86 simulator)

```bash
docker run \
    -v $PWD/core/iwasm/libraries/wasi-nn/test:/assets \
    wasi-nn-vx-delegate \
    --dir=/ \
    --env="TARGET=gpu" \
    /assets/test_tensorflow_quantized.wasm
```

- (Coral) TPU
  - Requirements:
    - [Coral USB](https://coral.ai/products/accelerator/).

```bash
docker run \
    --privileged \
    --device=/dev/bus/usb:/dev/bus/usb \
    -v $PWD/core/iwasm/libraries/wasi-nn/test:/assets \
    wasi-nn-tpu \
    --dir=/ \
    --env="TARGET=tpu" \
    /assets/test_tensorflow_quantized.wasm
```

## What is missing

Supported:

- Graph encoding: `tensorflowlite`, `openvino` and `ggml`
- Execution target: `cpu` for all. `gpu` and `tpu` for `tensorflowlite`.
- Tensor type: `fp32`.

## Smoke test

### Testing with WasmEdge-WASINN Examples

To make sure everything is configured properly, refer to the examples provided at [WasmEdge-WASINN-examples](https://github.com/second-state/WasmEdge-WASINN-examples/tree/master). These examples are useful for confirming that the WASI-NN support in WAMR is working correctly.

Because each backend has its own set of requirements, we recommend using a Docker container to create a straightforward testing environment without complications.

#### Prepare the execution environment

```bash
$ pwd
/workspaces/wasm-micro-runtime/

$ docker build -t wasi-nn-smoke:v1.0 -f ./core/iwasm/libraries/wasi-nn/test/Dockerfile.wasi-nn-smoke .
```

#### Execute

```bash
$ pwd
/workspaces/wasm-micro-runtime/
$ docker run --rm wasi-nn-smoke:v1.0
```

It should be noted that the qwen example is selected as the default one about the Llama.cpp backend because it uses a small model and is easy to run.

```bash
- openvino_mobile_image. PASS
- openvino_mobile_raw. PASS
- openvino_road_segmentation_adas. PASS
- wasmedge_ggml_qwen. PASS
```

### Testing with bytecodealliance WASI-NN

For another example, check out [classification-example](https://github.com/bytecodealliance/wasi-nn/tree/main/rust/examples/classification-example), which focuses on OpenVINO. You can run it using the same Docker container mentioned above.
