# Fluent Bit Docker Image

[Fluent Bit](https://fluentbit.io) container images are available on Docker Hub ready for production usage.

The stable AMD64 images are based on [Distroless](https://github.com/GoogleContainerTools/distroless) focusing on security containing just the Fluent Bit binary, minimal system libraries and basic configuration.

Optionally, we provide debug images which contain Busybox that can be used to troubleshoot or testing purposes.

There are also images for ARM32 and ARM64 architectures but no debug version.

For a detailed list of installation, usage and versions available, please refer to the the official documentation: https://docs.fluentbit.io/manual/installation/docker

## Build and test

1. Checkout the branch you want, e.g. 1.8 for 1.8.X containers.
2. Build the container image using the appropriate Dockerfile in this directory.
```
$ docker build -t fluent/fluent-bit -f ./dockerfiles/Dockerfile.x86_64 ./dockerfiles
```
3. Test the container.
```
$ docker run --rm -it fluent/fluent-bit:latest
```

By default, the configuration uses the CPU input plugin and the stdout output plugin which means you should see regular output in the log showing the CPU loading.

```
Fluent Bit v1.8.11
* Copyright (C) 2019-2021 The Fluent Bit Authors
* Copyright (C) 2015-2018 Treasure Data
* Fluent Bit is a CNCF sub-project under the umbrella of Fluentd
* https://fluentbit.io

[2022/01/13 14:48:44] [ info] [engine] started (pid=1)
[2022/01/13 14:48:44] [ info] [storage] version=1.1.5, initializing...
[2022/01/13 14:48:44] [ info] [storage] in-memory
[2022/01/13 14:48:44] [ info] [storage] normal synchronization mode, checksum disabled, max_chunks_up=128
[2022/01/13 14:48:44] [ info] [cmetrics] version=0.2.2
[2022/01/13 14:48:44] [ info] [sp] stream processor started
[0] cpu.local: [1642085324.503383520, {"cpu_p"=>0.437500, "user_p"=>0.250000, "system_p"=>0.187500, "cpu0.p_cpu"=>0.000000, "cpu0.p_user"=>0.000000, "cpu0.p_system"=>0.000000, "cpu1.p_cpu"=>0.000000, "cpu1.p_user"=>0.000000, "cpu1.p_system"=>0.000000, "cpu2.p_cpu"=>1.000000, "cpu2.p_user"=>1.000000, "cpu2.p_system"=>0.000000, "cpu3.p_cpu"=>1.000000, "cpu3.p_user"=>1.000000, "cpu3.p_system"=>0.000000, "cpu4.p_cpu"=>1.000000, "cpu4.p_user"=>1.000000, "cpu4.p_system"=>0.000000, "cpu5.p_cpu"=>1.000000, "cpu5.p_user"=>0.000000, "cpu5.p_system"=>1.000000, "cpu6.p_cpu"=>0.000000, "cpu6.p_user"=>0.000000, "cpu6.p_system"=>0.000000, "cpu7.p_cpu"=>0.000000, "cpu7.p_user"=>0.000000, "cpu7.p_system"=>0.000000, "cpu8.p_cpu"=>2.000000, "cpu8.p_user"=>1.000000, "cpu8.p_system"=>1.000000, "cpu9.p_cpu"=>1.000000, "cpu9.p_user"=>1.000000, "cpu9.p_system"=>0.000000, "cpu10.p_cpu"=>0.000000, "cpu10.p_user"=>0.000000, "cpu10.p_system"=>0.000000, "cpu11.p_cpu"=>0.000000, "cpu11.p_user"=>0.000000, "cpu11.p_system"=>0.000000, "cpu12.p_cpu"=>0.000000, "cpu12.p_user"=>0.000000, "cpu12.p_system"=>0.000000, "cpu13.p_cpu"=>0.000000, "cpu13.p_user"=>0.000000, "cpu13.p_system"=>0.000000, "cpu14.p_cpu"=>2.000000, "cpu14.p_user"=>1.000000, "cpu14.p_system"=>1.000000, "cpu15.p_cpu"=>0.000000, "cpu15.p_user"=>0.000000, "cpu15.p_system"=>0.000000}]
```

## ghcr.io topology

Containers are "staged" prior to release in the following ways to `ghcr.io`:
* `ghcr.io/fluent/fluent-bit` - official releases, identical to DockerHub
* `ghcr.io/fluent/fluent-bit/staging` - all architectures staging images used for testing prior to release
* `ghcr.io/fluent/fluent-bit/master` - x86_64/AMD64 only images built on each push to master, used for integration tests
* `ghcr.io/fluent/fluent-bit/pr-X` - x86_64/AMD64 only PR images where `X` is the PR number
* `ghcr.io/fluent/fluent-bit/multiarch` - developer preview multi-arch images built from `Dockerfile.multiarch`

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
