# "file" sample introduction

This sample demonstrates the supported file interaction API of WASI.
This sample can also demonstrate the SGX IPFS (Intel Protected File System), enabling an enclave to seal and unseal data at rest.

## Preparation

Please install WASI SDK, download the [wasi-sdk release](https://github.com/WebAssembly/wasi-sdk/releases) and extract the archive to default path `/opt/wasi-sdk`.
For testing with SGX IPFS, follow the instructions in [the documentation of SGX for WAMR](../../doc/linux_sgx.md#sgx-intel-protected-file-system).

## Build the sample

```bash
mkdir build
cd build
cmake ..
make
```

The WebAssembly application is the file located at `wasm-app/file.wasm`.

## Run workload

Either use [iwasm-sample](../../product-mini/platforms/linux/) for Linux, or [enclave-sample](../../product-mini/platforms/linux-sgx/enclave-sample/) for Intel SGX to run the sample, with the argument to allow the file system interaction with the current folder (`--dir=.`).

The output with Linux and POSIX is like:

```bash
Opening a file..
[Test] File opening passed.
Writing to the file..
[Test] File writing passed.
Moving the cursor to the start of the file..
Reading from the file, up to 1000 characters..
Text read: Hello, world!
[Test] File reading passed.
Determine whether we reach the end of the file..
Is the end of file? 1
[Test] End of file detection passed.
Getting the plaintext size..
The plaintext size is 13.
[Test] Retrieving file offset passed.
Force actual write of all the cached data to the disk..
[Test] Retrieving file offset passed.
Writing 5 characters at offset 7..
File current offset: 13
[Test] Writing at specified offset passed.
Reading 5 characters at offset 7..
Text read: James
File current offset: 13
[Test] Reading at specified offset passed.
Allocate more space to the file..
File current offset: 13
Moving to the end..
File current offset: 23
[Test] Allocation or more space passed.
Extend the file size of 10 bytes using ftruncate..
File current offset: 23
Moving to the end..
File current offset: 33
[Test] Extension of the file size passed.
Closing from the file..
[Test] Closing file passed.
Getting the size of the file on disk..
The file size is 33.
All the tests passed!
```

The output with SGX and IPFS is like:

```bash
Opening a file..
[Test] File opening passed.
Writing to the file..
[Test] File writing passed.
Moving the cursor to the start of the file..
Reading from the file, up to 1000 characters..
Text read: Hello, world!
[Test] File reading passed.
Determine whether we reach the end of the file..
Is the end of file? 1
[Test] End of file detection passed.
Getting the plaintext size..
The plaintext size is 13.
[Test] Retrieving file offset passed.
Force actual write of all the cached data to the disk..
[Test] Retrieving file offset passed.
Writing 5 characters at offset 7..
File current offset: 13
[Test] Writing at specified offset passed.
Reading 5 characters at offset 7..
Text read: James
File current offset: 13
[Test] Reading at specified offset passed.
Allocate more space to the file..
File current offset: 23
Moving to the end..
File current offset: 23
[Test] Allocation or more space passed.
Extend the file size of 10 bytes using ftruncate..
File current offset: 23
Moving to the end..
File current offset: 33
[Test] Extension of the file size passed.
Closing from the file..
[Test] Closing file passed.
Getting the size of the file on disk..
The file size is 4096.
All the tests passed!
```

For SGX IPFS, refer to [SGX Intel Protected File System](../../doc/linux_sgx.md#sgx-intel-protected-file-system) for more details.
