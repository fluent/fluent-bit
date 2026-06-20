# Fluent Bit Docker Image

[Fluent Bit](https://fluentbit.io) container images are available on Docker Hub ready for production usage.

The stable AMD64 images are based on [Distroless](https://github.com/GoogleContainerTools/distroless) focusing on security containing just the Fluent Bit binary, minimal system libraries and basic configuration.

Optionally, we provide debug images which contain shells and tooling that can be used to troubleshoot or for testing purposes.

There are also images for ARM32 and ARM64 architectures but no debug versions of these.

For a detailed list of installation, usage and versions available, please refer to the the official documentation: https://docs.fluentbit.io/manual/installation/docker

## Multiple architecture support

A good introduction to the available approaches is here: https://www.docker.com/blog/multi-arch-build-and-images-the-simple-way/

To build for multiple architectures the [QEMU tooling](https://www.qemu.org/) can be used with the [BuildKit extension for Docker](https://docs.docker.com/buildx/working-with-buildx).

With QEMU set up and buildkit support, you can build all targets in one simple call.

To set up for Ubuntu 20.04 development PC as an example:

1. Add QEMU: https://askubuntu.com/a/1369504
```
sudo add-apt-repository ppa:jacob/virtualisation
sudo apt-get update && sudo apt-get install qemu qemu-user qemu-user-static
```
2. Install buildkit: https://docs.docker.com/buildx/working-with-buildx/#install
```
wget https://github.com/docker/buildx/releases/download/v0.7.1/buildx-v0.7.1.linux-amd64
mv buildx-v0.7.1.linux-amd64 ~/.docker/cli-plugins/docker-buildx
chmod a+x ~/.docker/cli-plugins/docker-buildx
```
3. Configure and use: https://stackoverflow.com/a/60667468
```
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
docker buildx rm builder
docker buildx create --name builder --use
docker buildx inspect --bootstrap
```
4. Build Fluent Bit from the **root of the Git repo (not from this directory)**:
```
docker buildx build --platform "linux/amd64,linux/arm64,linux/arm/v7,linux/s390x" --target=production -f dockerfiles/Dockerfile .
```

## Build and test

1. Checkout the branch you want, e.g. 1.8 for 1.8.X containers.
2. Build Fluent Bit from the **root of the Git repo (not from this directory)**:
```
$ docker build -t fluent/fluent-bit --target=production -f dockerfiles/Dockerfile .
```
3. Test the container.
```
$ docker run --rm -it fluent/fluent-bit:latest
```

By default, the configuration uses the CPU input plugin and the stdout output plugin which means you should see regular output in the log showing the CPU loading.

```
Fluent Bit v4.2.0
* Copyright (C) 2015-2025 The Fluent Bit Authors
* Fluent Bit is a CNCF graduated project under the Fluent organization
* https://fluentbit.io

______ _                  _    ______ _ _             ___   _____
|  ___| |                | |   | ___ (_) |           /   | / __  \
| |_  | |_   _  ___ _ __ | |_  | |_/ /_| |_  __   __/ /| | `' / /'
|  _| | | | | |/ _ \ '_ \| __| | ___ \ | __| \ \ / / /_| |   / /
| |   | | |_| |  __/ | | | |_  | |_/ / | |_   \ V /\___  |_./ /___
\_|   |_|\__,_|\___|_| |_|\__| \____/|_|\__|   \_/     |_(_)_____/

             Fluent Bit v4.2 – Direct Routes Ahead
         Celebrating 10 Years of Open, Fluent Innovation!

[2025/11/09 10:59:11.46951388] [ info] [fluent bit] version=4.2.0, commit=b63bcf40cc, pid=2833142
[2025/11/09 10:59:11.47022363] [ info] [storage] ver=1.5.4, type=memory, sync=normal, checksum=off, max_chunks_up=128
[2025/11/09 10:59:11.47037121] [ info] [simd    ] disabled
[2025/11/09 10:59:11.47042051] [ info] [cmetrics] version=1.0.5
[2025/11/09 10:59:11.47051870] [ info] [ctraces ] version=0.6.6
[2025/11/09 10:59:11.47133035] [ info] [input:cpu:cpu.0] initializing
[2025/11/09 10:59:11.47143244] [ info] [input:cpu:cpu.0] storage_strategy='memory' (memory only)
[2025/11/09 10:59:11.47503863] [ info] [sp] stream processor started
[2025/11/09 10:59:11.47543138] [ info] [engine] Shutdown Grace Period=5, Shutdown Input Grace Period=2
[2025/11/09 10:59:11.47544701] [ info] [output:stdout:stdout.0] worker #0 started

[0] cpu.local: [1642085324.503383520, {"cpu_p"=>0.437500, "user_p"=>0.250000, "system_p"=>0.187500, "cpu0.p_cpu"=>0.000000, "cpu0.p_user"=>0.000000, "cpu0.p_system"=>0.000000, "cpu1.p_cpu"=>0.000000, "cpu1.p_user"=>0.000000, "cpu1.p_system"=>0.000000, "cpu2.p_cpu"=>1.000000, "cpu2.p_user"=>1.000000, "cpu2.p_system"=>0.000000, "cpu3.p_cpu"=>1.000000, "cpu3.p_user"=>1.000000, "cpu3.p_system"=>0.000000, "cpu4.p_cpu"=>1.000000, "cpu4.p_user"=>1.000000, "cpu4.p_system"=>0.000000, "cpu5.p_cpu"=>1.000000, "cpu5.p_user"=>0.000000, "cpu5.p_system"=>1.000000, "cpu6.p_cpu"=>0.000000, "cpu6.p_user"=>0.000000, "cpu6.p_system"=>0.000000, "cpu7.p_cpu"=>0.000000, "cpu7.p_user"=>0.000000, "cpu7.p_system"=>0.000000, "cpu8.p_cpu"=>2.000000, "cpu8.p_user"=>1.000000, "cpu8.p_system"=>1.000000, "cpu9.p_cpu"=>1.000000, "cpu9.p_user"=>1.000000, "cpu9.p_system"=>0.000000, "cpu10.p_cpu"=>0.000000, "cpu10.p_user"=>0.000000, "cpu10.p_system"=>0.000000, "cpu11.p_cpu"=>0.000000, "cpu11.p_user"=>0.000000, "cpu11.p_system"=>0.000000, "cpu12.p_cpu"=>0.000000, "cpu12.p_user"=>0.000000, "cpu12.p_system"=>0.000000, "cpu13.p_cpu"=>0.000000, "cpu13.p_user"=>0.000000, "cpu13.p_system"=>0.000000, "cpu14.p_cpu"=>2.000000, "cpu14.p_user"=>1.000000, "cpu14.p_system"=>1.000000, "cpu15.p_cpu"=>0.000000, "cpu15.p_user"=>0.000000, "cpu15.p_system"=>0.000000}]
```

## ghcr.io topology

Containers are "staged" prior to release in the following ways to `ghcr.io`:
* `ghcr.io/fluent/fluent-bit` - official releases, identical to DockerHub
* `ghcr.io/fluent/fluent-bit/staging` - all architectures staging images used for testing prior to release
* `ghcr.io/fluent/fluent-bit/master` - x86_64/AMD64 only images built on each push to master, used for integration tests
* `ghcr.io/fluent/fluent-bit/pr-X` - x86_64/AMD64 only PR images where `X` is the PR number

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
  --build-arg WINDOWS_VERSION=ltsc2019 `
  -t fluent/fluent-bit:master-windows -f ./dockerfiles/Dockerfile.windows .
```

## Contact

Feel free to join us on our Mailing List or IRC:

 - Slack: http://slack.fluentd.org / channel #fluent-bit
 - Mailing List: https://groups.google.com/forum/#!forum/fluent-bit
 - IRC: irc.freenode.net #fluent-bit
 - Twitter: http://twitter.com/fluentbit

## License

This program is under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Authors

[Fluent Bit](http://fluentbit.io) is made and sponsored by [Treasure Data](http://treasuredata.com) among other [contributors](https://github.com/fluent/fluent-bit/graphs/contributors).
