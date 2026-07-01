# How to use WAMR with Zephyr

[Zephyr](https://www.zephyrproject.org/) is an open source real-time operating
system (RTOS) with a focus on security and broad hardware support. WAMR is
compatible with Zephyr via the [Zephyr WAMR
port](../../../../core/shared/platform/zephyr).

## Setup

Using WAMR with Zephyr can be accomplished by either using the provided Docker
image, or by installing Zephyr locally. Both approaches are described below.

### Docker

The provided Docker image sets up Zephyr and its dependencies for all
architectures, meaning that you are ready to build for any [supported
board](https://docs.zephyrproject.org/latest/boards/index.html). This comes at
the expense of building a rather large image, which both can take a long time to
build and uses up a large amount of storage (~15 GB).

Execute the following command to build the Docker image. This may take an
extended period of time to complete.

```shell
docker build -t wamr-zephyr .
```

Execute the following command to run the image built in the previous step. If
you are planning to flash a device after building, make sure to specify it with
[`--device`](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities).

```shell
docker run -it --rm --device=/dev/ttyUSB0 wamr-zephyr
```

### Local Environment

Zephyr can also be setup locally to enable building this sample application.
This allows you have have more control over what modules and tools are
installed, which can drastically reduce the storage required compared to the
Docker image.

Follow the steps provided in the [Zephyr Getting Started
guide](https://docs.zephyrproject.org/latest/develop/getting_started/index.html)
to setup for local development.

## Building for a Specific Board

With an environment setup either locally or in a Docker container, you can build
for a Zephyr supported board using
[`west`](https://docs.zephyrproject.org/latest/develop/west/index.html). There
are already [configuration files](./boards) for a few boards in this sample.
However, if you are using a new board, you will need to add your own file for
the board, or define configuration in the [`prj.conf](./prj.conf). After doing
so, use the following command with your board identifier to build the sample
application.

```shell
west build . -b <board-identifier> --pristine -- -DWAMR_BUILD_TARGET=<wamr-arch>
```

The `<board-identifier>` can be found in the Zephyr supported boards
documentation. It must also be used as the name of the board configuration file.
You must define the architecture for WAMR to target with `WAMR_BUILD_TARGET`.
The list of supported architectures can be found in the main project
[README.md](../../../../README.md#supported-architectures-and-platforms).

It may be necessary to define additional symbols for some boards. For example,
WAMR AOT execution may not be supported on all architectures. It and other
options can be disabled by modifying the [CMakeLists.txt](./CMakeLists.txt)
file, or by passing additional arguments at build (e.g. `-DWAMR_BUILD_AOT=0`).

### Example Targets

[ESP32-C3](https://docs.zephyrproject.org/latest/boards/riscv/esp32c3_devkitm/doc/index.html)
is a 32-bit RISC-V target that does not currently support AOT.

```shell
west build . -b esp32c3_devkitm -p always -- -DWAMR_BUILD_TARGET=RISCV32_ILP32 -DWAMR_BUILD_AOT=0
```

[ARM Cortex-A53 QEMU
(ARM)](https://docs.zephyrproject.org/latest/boards/arm64/qemu_cortex_a53/doc/index.html)
is a 64-bit ARM target for emulating the Cortex-A53 platform.

```shell
west build . -b qemu_cortex_a53 -p always -- -DWAMR_BUILD_TARGET=AARCH64 
```

[ARC QEMU](https://docs.zephyrproject.org/latest/boards/qemu/arc/doc/index.html)
is a 32-bit ARC target for emulating the ARC platform.

```shell
west build . -b qemu_arc/qemu_arc_em  -p always -- -DWAMR_BUILD_TARGET=ARC
```

## Flashing or Running Image

The board can be flashed with the built image with the following command.

```shell
west flash
```

`west` will automatically identify the board if it is connected to the host
machine.

When using emulated targets, such as those that utilize QEMU, there is no
physical device to flash, but `west` can be used to run the image under
emulation.

```shell
west build -t run
```
