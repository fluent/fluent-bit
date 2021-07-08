# Dockerfile

The Fluent Bit Docker images should be built as follows:

## Linux

```bash
docker build --no-cache -t fluent/fluent-bit:1.3.7 -f Dockerfile .
```

## Windows

> Note:
>
> The minimum version of fluent-bit supported is `1.3.7`.

The Windows version can be specified when building the Windows image. The instructions below leverage the **Windows Server Core 2019 - 1809/ltsc2019** base image. The large Windows Server Core base image is leveraged as the builder, while the smaller Windows Nano base image is leveraged for the final runtime image.

More information is available at:

- [Windows Container Base Images](https://docs.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/container-base-images)
- [Windows Container Version Compatibility](https://docs.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/version-compatibility?tabs=windows-server-2019%2Cwindows-10-1909#tabpanel_CeZOj-G++Q_windows-server-2019)

In addition, metadata as defined in OCI image spec annotations, is leveraged in the generated image. This is the reason for the additional `--build-arg` parameters.

```powershell
# Minimum set of build-args
docker build --no-cache `
  --build-arg WINDOWS_VERSION=1809 --build-arg FLUENTBIT_VERSION=1.3.7 `
  -t fluent/fluent-bit:1.3.7-nanoserver -f Dockerfile.windows .

# Full set of build-args
docker build --no-cache `
  --build-arg WINDOWS_VERSION=1809 --build-arg FLUENTBIT_VERSION=1.3.7 `
  --build-arg IMAGE_CREATE_DATE="$(Get-Date((Get-Date).ToUniversalTime()) -UFormat '%Y-%m-%dT%H:%M:%SZ')" `
  --build-arg IMAGE_SOURCE_REVISION="$(git rev-parse HEAD)" `
  -t fluent/fluent-bit:1.3.7-nanoserver -f Dockerfile.windows .
```