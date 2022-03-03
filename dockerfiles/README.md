# Fluent Bit Docker Image

[Fluent Bit](https://fluentbit.io) container images are available on Docker Hub ready for production usage.

The stable AMD64 images are based on [Distroless](https://github.com/GoogleContainerTools/distroless) focusing on security containing just the Fluent Bit binary, minimal system libraries and basic configuration.

Optionally, we provide debug images which contain shells and tooling that can be used to troubleshoot or for testing purposes.

There are also images for ARM32 and ARM64 architectures but no debug versions of these.

For a detailed list of installation, usage and versions available, please refer to the the official documentation: https://docs.fluentbit.io/manual/installation/docker

## Building

All container images for the `1.8` branch are built from the separate `fluent/fluent-bit-docker-image` repository on the `1.8` branch: https://github.com/fluent/fluent-bit-docker-image/tree/1.8
