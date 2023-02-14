"sgx-ra" sample introduction
==============

This sample demonstrates how to execute Remote Attestation on SGX with [librats](https://github.com/inclavare-containers/librats) and run it with iwasm. It can only build on [SGX supported processors](https://www.intel.com/content/www/us/en/support/articles/000028173/processors.html), please check it.

## Preparation

Before staring, we need to download and intall [SGX SDK](https://download.01.org/intel-sgx/latest/linux-latest/distro) and [SGX DCAP Library](https://download.01.org/intel-sgx/latest/dcap-latest) referring to this [guide](https://download.01.org/intel-sgx/sgx-dcap/1.8/linux/docs/Intel_SGX_DCAP_Linux_SW_Installation_Guide.pdf).

The following command is the example of the SGX environment installation on ubuntu18.04.
``` shell
$ cd $HOME
$ # Set your platform, you can get the platforms list on 
$ # https://download.01.org/intel-sgx/latest/linux-latest/distro
$ SGX_PALTFORM=ubuntu18.04-server
$ SGX_SDK_VERSION=2.17.100.3
$ SGX_DRIVER_VERSION=1.41
$ # install SGX Driver
$ wget https://download.01.org/intel-sgx/latest/linux-latest/distro/$SGX_PALTFORM/sgx_linux_x64_driver_$SGX_DRIVER_VERSION.bin
$ chmod +x sgx_linux_x64_driver_$SGX_DRIVER_VERSION.bin
$ sudo ./sgx_linux_x64_driver_$SGX_DRIVER_VERSION.bin
$ # install SGX SDK
$ wget https://download.01.org/intel-sgx/latest/linux-latest/distro/$SGX_PALTFORM/sgx_linux_x64_sdk_$SGX_SDK_VERSION.bin
$ chmod +x sgx_linux_x64_sdk_$SGX_SDK_VERSION.bin
$ sudo ./sgx_linux_x64_sdk_$SGX_SDK_VERSION.bin
$ # install SGX DCAP Library
$ echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list > /dev/null
$ wget -O - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
$ sudo apt update
$ sudo apt install libsgx-uae-service libsgx-dcap-default-qpl-dev libsgx-dcap-ql-dev libsgx-dcap-quote-verify-dev
```

## Build
``` shell
$ mkdir build && cd build
$ cmake ..
$ make
$ # run the sample
$ ./iwasm wasm-app/test.wasm
```

The sample will print the evidence in json and "Evidence is trusted." by default.