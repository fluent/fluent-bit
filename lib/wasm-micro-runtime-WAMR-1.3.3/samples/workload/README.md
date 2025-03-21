All workloads have similar requirment of software dependencies, including **emsdk** and **binaryen**

> There might be slight differences when using MacOS and other Linux distro than Ubuntu. This document targets
Ubuntu 20.04 as an example.

## Installation instructions

use [preparation.sh](./preparation.sh) to install all dependencies before compiling any workload. Or use [*vscode DevContainer*](../../.devcontainer/)

The script installs below software:

- **emsdk**. Refer to [the guide](https://emscripten.org/docs/getting_started/downloads.html). Don't forget to activate
  emsdk and set up environment variables. Verify it with `echo ${EMSDK}`. Please be sure to install and activate the building
  of 3.0.0

``` bash
$ cd /opt
$ git clone https://github.com/emscripten-core/emsdk.git
$ cd emsdk
$ git pull
$ ./emsdk install 3.0.0
$ ./emsdk activate 3.0.0
$ echo "source /opt/emsdk/emsdk_env.sh" >> "${HOME}"/.bashrc
```

- **binaryen**. Install
  [latest release](https://github.com/WebAssembly/binaryen/releases/download/version_111/binaryen-version_111-x86_64-linux.tar.gz)
  to */opt/binaryen*

``` bash
$ wget https://github.com/WebAssembly/binaryen/releases/download/${BINARYEN_VER}/${BINARYEN_FILE}
$ tar zxf ${BINARYEN_FILE} -C /opt
$ ln -sf /opt/binaryen-${BINARYEN_VER} /opt/binaryen
```
