All workloads have similar requirment of software dependencies, including
**emsdk**, **wabt** and **binaryen**

> There might be slight differences when using MacOS and other Linux distro than Ubuntu. This document only target
Ubuntu 18.04 as example.

## Installation instructions

use [preparation.sh](./preparation.sh) to install all dependencies before compiling any workload.

for details, the script includes below steps:

- **wabt**. Install
  [latest release](https://github.com/WebAssembly/wabt/releases/download/1.0.23/wabt-1.0.23-ubuntu.tar.gz)
  to */opt/wabt*

``` bash
$ wget https://github.com/WebAssembly/wabt/releases/download/${WABT_VER}/${WABT_FILE}
$ tar zxf ${WABT_FILE} -C /opt
$ ln -sf /opt/wabt-${WABT_VER} /opt/wabt
```

- **emsdk**. Refer to [the guide](https://emscripten.org/docs/getting_started/downloads.html). Don't forget to activate
  emsdk and set up environment variables. Verify it with `echo ${EMSDK}`. Please be sure to install and activate the building
  of 2.0.26

``` bash
$ cd /opt
$ git clone https://github.com/emscripten-core/emsdk.git
$ cd emsdk
$ git pull
$ ./emsdk install 2.0.26
$ ./emsdk activate 2.0.26
$ echo "source /opt/emsdk/emsdk_env.sh" >> "${HOME}"/.bashrc
```

- **binaryen**. Install
  [latest release](https://github.com/WebAssembly/binaryen/releases/download/version_101/binaryen-version_101-x86_64-linux.tar.gz)
  to */opt/binaryen*

``` bash
$ wget https://github.com/WebAssembly/binaryen/releases/download/${BINARYEN_VER}/${BINARYEN_FILE}
$ tar zxf ${BINARYEN_FILE} -C /opt
$ ln -sf /opt/binaryen-${BINARYEN_VER} /opt/binaryen
```
