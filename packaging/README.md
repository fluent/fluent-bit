# Fluent Bit Packaging

This directory contains files to support building and releasing Fluent Bit.

For PRs, add the `ok-package-test` label to trigger an automated build of all supported Linux, macOS, Windows and container image targets to verify a PR correctly builds for all supported platforms.
This can take some time to complete so is only triggered via the label on-demand.

## Linux

The [`distros`](./distros/) directory contains OCI container definitions used to build [Fluent Bit](http://fluentbit.io) Linux packages for different distros, the following table describe the supported targets:

| Distro        |   Version / Code Name     | Arch    | Target Option            |
|---------------|---------------------------|---------|--------------------------|
| AmazonLinux   |   2                       | x86_64  | amazonlinux/2            |
| AmazonLinux   |   2                       | arm64v8 | amazonlinux/2.arm64v8    |
| AmazonLinux   |   2023                    | x86_64  | amazonlinux/2023         |
| AmazonLinux   |   2023                    | arm64v8 | amazonlinux/2023.arm64v8 |
| AlmaLinux     |   8                       | x86_64  | almalinux/8              |
| AlmaLinux     |   8                       | arm64v8 | almalinux/8.arm64v8      |
| AlmaLinux     |   9                       | x86_64  | almalinux/9              |
| AlmaLinux     |   9                       | arm64v8 | almalinux/9.arm64v8      |
| AlmaLinux     |   10                      | x86_64  | almalinux/10             |
| AlmaLinux     |   10                      | arm64v8 | almalinux/10.arm64v8     |
| CentOS Stream |   9                       | x86_64  | centos/9                 |
| CentOS Stream |   9                       | arm64v8 | centos/9.arm64v8         |
| CentOS        |   8                       | x86_64  | centos/8                 |
| CentOS        |   8                       | arm64v8 | centos/8.arm64v8         |
| CentOS        |   7                       | x86_64  | centos/7                 |
| CentOS        |   7                       | arm64v8 | centos/7.arm64v8         |
| Debian        |   13                      | x86_64  | debian/trixie            |
| Debian        |   13                      | arm64v8 | debian/trixie.arm64v8    |
| Debian        |   12                      | x86_64  | debian/bookworm          |
| Debian        |   12                      | arm64v8 | debian/bookworm.arm64v8  |
| Debian        |   11                      | x86_64  | debian/bullseye          |
| Debian        |   11                      | arm64v8 | debian/bullseye.arm64v8  |
| Debian        |   10                      | x86_64  | debian/buster            |
| Debian        |   10                      | arm64v8 | debian/buster.arm64v8    |
| Ubuntu        |   24.04 / Noble Numbat    | x86_64  | ubuntu/24.04             |
| Ubuntu        |   24.04 / Noble Numbat    | arm64v8 | ubuntu/24.04.arm64v8     |
| Ubuntu        |   22.04 / Jammy Jellyfish | x86_64  | ubuntu/22.04             |
| Ubuntu        |   22.04 / Jammy Jellyfish | arm64v8 | ubuntu/22.04.arm64v8     |
| Ubuntu        |   20.04 / Focal Fossa     | x86_64  | ubuntu/20.04             |
| Ubuntu        |   20.04 / Focal Fossa     | arm64v8 | ubuntu/20.04.arm64v8     |
| Ubuntu        |   18.04 / Bionic Beaver   | x86_64  | ubuntu/18.04             |
| Ubuntu        |   18.04 / Bionic Beaver   | arm64v8 | ubuntu/18.04.arm64v8     |
| Ubuntu        |   16.04 / Xenial Xerus    | x86_64  | ubuntu/16.04             |
| Raspbian      |   12 / Bookworm           | arm32v7 | raspbian/bookworm        |
| Raspbian      |   11 / Bullseye           | arm32v7 | raspbian/bullseye        |
| Raspbian      |   10 / Buster             | arm32v7 | raspbian/buster          |

These container images are intended to be built from the root of this repo to build the locally checked out/updated version of the source easily for any target.

### Usage

The _build.sh_ script can be used to build packages for a specific target, the command understand the following format:

```shell
./build.sh -d DISTRO
```

Replace `DISTRO` with the `Target option` column above.

All Linux builds happen in a container so can be run on any supported platform with QEMU installed and a container runtime.

## Windows

Windows builds are carried out by the [dedicated workflow](../.github/workflows/call-build-windows.yaml) in CI.
This builds using the standard CMake process on a dedicated Windows runner within Github actions.
The steps involved and additional requirements can all be found there.

## macOS

Windows builds are carried out by the [dedicated workflow](../.github/workflows/call-build-macos.yaml) in CI.
This builds using the standard CMake process on a dedicated macOS runner within Github actions.
The steps involved and additional requirements can all be found there.
