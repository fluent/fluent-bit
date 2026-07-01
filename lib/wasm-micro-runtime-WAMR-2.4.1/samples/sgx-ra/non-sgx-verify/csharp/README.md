# Examples of evidence verification without Intel SGX using C#
This sample demonstrates how to validate WAMR-generated evidence without using an Intel SGX-enabled platform.
A typical use case is a Web service hosted on trusted premises.

## Prerequisites
 - [dotnet-sdk](https://learn.microsoft.com/en-us/dotnet/core/install/linux) (8+)
 - [librats](https://github.com/inclavare-containers/librats)
 - Intel infrastructure for validating evidence, [see here](../../README.md#validate-quotes-on-non-sgx-platforms)

This sample has been tested on Linux Ubuntu 20.04+.
Any other Linux platforms should be supported.
This sample should also work on other OS, provided librats can be compiled on those other OS.

## How to use
 - Supply the reference values to consider trustworthy in [Program.cs](Program.cs#L15-L27).
 - Generate a valid JSON evidence using WAMR on an Intel SGX-enabled platform.
 - Fill in the JSON evidence in [Program.cs](Program.cs#L28).
 - Run the command `dotnet run` in this directory.
