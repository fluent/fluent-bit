# Fluent Bit Docker Image

[Fluent Bit](https://fluentbit.io) container images are available on Docker Hub ready for production usage.

The stable AMD64 images are based on [Distroless](https://github.com/GoogleContainerTools/distroless) focusing on security containing just the Fluent Bit binary, minimal system libraries and basic configuration.

Optionally, we provide debug images which contain shells and tooling that can be used to troubleshoot or for testing purposes.

There are also images for ARM32 and ARM64 architectures but no debug versions of these.

For a detailed list of installation, usage and versions available, please refer to the the official documentation: https://docs.fluentbit.io/manual/installation/docker

## Building

All container images for the `1.8` branch are built from the separate `fluent/fluent-bit-docker-image` repository on the `1.8` branch: https://github.com/fluent/fluent-bit-docker-image/tree/1.8

## Windows

**The minimum version of fluent-bit supported is `1.3.7`.**

The Windows version can be specified when building the Windows image. The instructions below leverage the **Windows Server Core 2019 - 1809/ltsc2019** base image. The large Windows Server Core base image is leveraged as the builder, while the smaller Windows Nano base image is leveraged for the final runtime image.

More information is available at:

- [Windows Container Base Images](https://docs.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/container-base-images)
- [Windows Container Version Compatibility](https://docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/version-compatibility?tabs=windows-server-2019%2Cwindows-10-1909#tabpanel_CeZOj-G++Q_windows-server-2019)

In addition, metadata as defined in OCI image spec annotations, is leveraged in the generated image. This is the reason for the additional `--build-arg` parameters.

### Minimum set of build-args
```powershell
docker build --no-cache `
  --build-arg WINDOWS_VERSION=1809 --build-arg FLUENTBIT_VERSION=1.8.11 `
  -t fluent/fluent-bit:1.8.11-nanoserver -f ./dockerfiles/Dockerfile.windows ./dockerfiles/
```
### Full set of build-args
```powershell
docker build --no-cache `
  --build-arg WINDOWS_VERSION=1809 --build-arg FLUENTBIT_VERSION=1.8.11 `
  --build-arg IMAGE_CREATE_DATE="$(Get-Date((Get-Date).ToUniversalTime()) -UFormat '%Y-%m-%dT%H:%M:%SZ')" `
  --build-arg IMAGE_SOURCE_REVISION="$(git rev-parse HEAD)" `
  -t fluent/fluent-bit:1.8.11-nanoserver -f ./dockerfiles/Dockerfile.windows ./dockerfiles/
```
