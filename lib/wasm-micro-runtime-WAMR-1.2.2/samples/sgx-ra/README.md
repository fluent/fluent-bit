"sgx-ra" sample introduction
==============

This sample demonstrates how to execute Remote Attestation on SGX with [librats](https://github.com/inclavare-containers/librats) and run it with iwasm. It can only build on [SGX supported processors](https://www.intel.com/content/www/us/en/support/articles/000028173/processors.html), please check it.

## Preparation

SGX-RA requires to have installed:
 - the WASI-SDK, located in `/opt/wasi-sdk`
 - CMake >= 3.11, which is not provided on Ubuntu 18.04 (use [Kitware APT Repository](https://apt.kitware.com/))

### Intel SGX dependencies

Before starting, we need to download and install [SGX SDK](https://download.01.org/intel-sgx/latest/linux-latest/distro) and [SGX DCAP Library](https://download.01.org/intel-sgx/latest/dcap-latest) referring to this [guide](https://download.01.org/intel-sgx/sgx-dcap/1.8/linux/docs/Intel_SGX_DCAP_Linux_SW_Installation_Guide.pdf).

The following commands are an example of the SGX environment installation on Ubuntu 18.04.
``` shell
# Set your platform, you can get the platforms list on
# https://download.01.org/intel-sgx/latest/linux-latest/distro
$ cd $HOME
$ SGX_PLATFORM=ubuntu18.04-server
$ SGX_SDK_VERSION=2.17.100.3
$ SGX_DRIVER_VERSION=1.41

# install the dependencies
$ sudo apt-get update
$ sudo apt-get install -y dkms

# install SGX Driver
$ wget https://download.01.org/intel-sgx/latest/linux-latest/distro/$SGX_PLATFORM/sgx_linux_x64_driver_$SGX_DRIVER_VERSION.bin
$ chmod +x sgx_linux_x64_driver_$SGX_DRIVER_VERSION.bin
$ sudo ./sgx_linux_x64_driver_$SGX_DRIVER_VERSION.bin

# install SGX SDK
$ wget https://download.01.org/intel-sgx/latest/linux-latest/distro/$SGX_PLATFORM/sgx_linux_x64_sdk_$SGX_SDK_VERSION.bin
$ chmod +x sgx_linux_x64_sdk_$SGX_SDK_VERSION.bin
$ sudo ./sgx_linux_x64_sdk_$SGX_SDK_VERSION.bin

# install SGX DCAP Library
$ echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list > /dev/null
$ wget -O - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
$ sudo apt-get update
$ sudo apt-get install -y libsgx-uae-service libsgx-dcap-default-qpl-dev libsgx-dcap-ql-dev libsgx-dcap-quote-verify-dev

# install SGX SSL Library
$ git clone https://github.com/intel/linux-sgx.git
$ cd linux-sgx && make preparation
$ sudo cp external/toolset/{current_distr}/* /usr/local/bin
$ # Verify that the paths are correctly set
$ which ar as ld objcopy objdump ranlib
$ cd ../
$ git clone https://github.com/intel/intel-sgx-ssl.git
$ wget https://www.openssl.org/source/openssl-1.1.1q.tar.gz
$ cp openssl-1.1.1q.tar.gz intel-sgx-ssl/openssl_source
$ rm -f openssl-1.1.1q.tar.gz
$ cd intel-sgx-ssl/Linux
$ source /opt/intel/sgxsdk/environment
$ make all
$ sudo make install
```

You can optionally grant users to communicate with the SDK platform using the following command.
Otherwise, enclaves must be launched with root privileges.

```shell
sudo usermod -a -G sgx_prv <username>
```

### Intel Provisioning Certification Service (Intel PCS)

Intel DCAP connects to Intel PCS to download the attestation collateral for SGX-enabled machines.
Intel provides a [quick install guide](https://www.intel.com/content/www/us/en/developer/articles/guide/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html) to set up a simplified environment.
This section summarizes the commands to issue for setting up a working environment on Ubuntu 18.04.

### Subscribe to Intel PCS Web services

Intel SGX DCAP requires a complimentary subscription to the Intel PCS.
To subscribe to the service, browse the [Intel SGX Software Services](https://api.portal.trustedservices.intel.com/) page.
A the end of the subscription process, save the primary and the secondary keys.

### Set up the Intel Provisioning Certification Caching Service (Intel PCCS)

Intel PCCS is a caching mechanism for attestation collateral, preventing continuously communicating with Intel PCS during attestation.
Intel provides an implementation of the cache mechanism.

The following commands set up Intel PCCS.
```shell
# install Node.js
$ curl -o setup.sh -sL https://deb.nodesource.com/setup_14.x
$ chmod a+x setup.sh
$ sudo ./setup.sh
# install PCCS software
$ sudo apt-get install -y cracklib-runtime sqlite3 python build-essential
$ sudo apt-get install -y sgx-dcap-pccs
```

The installation will run the PCCS setup script, asking you several questions.

```
Do you want to configure PCCS now? (Y/N)
```

Answer "Y" to this question.

```
Set HTTPS listening port [8081] (1024-65535)
```

Accept the default listening port of 8081.

```
Set the PCCS service to accept local connections only? [Y] (Y/N)
```

Answer "N" to this question. We want the PCCS service to accept connections from other systems.

```
Set your Intel PCS API key (Press ENTER to skip)
```

Enter either your primary or secondary key retrieved from the previous subsection.
If you already subscribed, you can retrieve them [here](https://api.portal.trustedservices.intel.com/developer).

```
Choose caching fill method : [LAZY] (LAZY/OFFLINE/REQ)
```

Answer "REQ" to this question. This places the caching service in the "on request" mode, which means it will fetch the attestation collateral for hosts as provisioning requests are received.

```
Set PCCS server administrator password:
Re-enter administrator password:
Set PCCS server user password:
Re-enter user password:
```

Enter two passwords for the PCCS server.

```
Do you want to generate insecure HTTPS key and cert for PCCS service? [Y] (Y/N)
```

Answer "Y" to this question.

### Provisioning a system into Intel PCCS

Now that the PCCS is up and running, it's time to provision an Intel SGX-enabled platform.
We use the tool `PCKIDRetrievalTool` to get the attestation collateral of the current machine.

``` shell
$ sudo apt-get install -y sgx-pck-id-retrieval-tool
```

Adapt the configuration file of `PCKIDRetrievalTool` located in `/opt/intel/sgx-pck-id-retrieval-tool/network_setting.conf` and make the following changes:
- Change the **PCCS_URL** to match your caching service's location.
- Uncomment the **user_token** parameter, and set it to the user password you created when configuring the PCCS.
- Set the **proxy_type** to fit your environment (most likely, this will be `direct`)
- Ensure **USE_SECURE_CERT** is set to `FALSE` since we're using a self-signed certificate for testing purposes.

Save your changes and run the provisioning tool.

```shell
$ PCKIDRetrievalTool
Intel(R) Software Guard Extensions PCK Cert ID Retrieval Tool Version 1.14.100.3

the data has been sent to cache server successfully and pckid_retrieval.csv has been generated successfully!
```

You may get some warnings during this execution of the tool.
A correct insertion into the cache server usually means the retrieval of the attestation collateral worked.
Execute the following command to verify the collateral could be stored in your instance of Intel PCCS:

```
curl -k https://localhost:8081/sgx/certification/v3/qe/identity
```

This should print a JSON value with the attestation collateral.

### Runtime configuration

Edit the configuration file, `/etc/sgx_default_qcnl.conf`, and make the following changes:
- Set the **PCCS_URL** parameter to the location of our PCCS server.
- Set **USE_SECURE_CERT** to `FALSE` since we're using a self-signed certificate for testing purposes.

This system is now ready to run Intel SGX workloads with generate evidence for remote attestation.

## Build and executing the sample

``` shell
$ mkdir build && cd build
$ cmake ..
$ make
$ # run the sample
$ ./iwasm wasm-app/test.wasm
```

The sample will print the evidence in JSON and the message: *Evidence is trusted.*

## Further readings

- [Intel SGX Software Installation Guide For Linux OS](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf)
- [Intel Software Guard Extensions (Intel® SGX) Data Center Attestation Primitives: Library API ](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf)
- [Remote Attestation for Multi-Package Platforms using Intel SGX Datacenter Attestation Primitives (DCAP)](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_DCAP_Multipackage_SW.pdf)
