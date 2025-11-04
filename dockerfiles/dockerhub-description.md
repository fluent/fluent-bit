# Fluent Bit

[Fluent Bit](https://fluentbit.io/) is a lightweight and high performance log processor.
In this repository you will find the container images ready for production usage.
Our stable images are based in [Distroless](https://github.com/GoogleContainerTools/distroless) focusing on security containing just the Fluent Bit binary, minimal system libraries and basic configuration.

Optionally, we provide debug images which contain shells and tooling that can be used to troubleshoot or for testing purposes.

For a detailed list of tags and versions available, please refer to the the official documentation:

<https://docs.fluentbit.io/manual/installation/downloads/docker>

## Getting Started

Run a Fluent Bit instance that will receive messages over TCP port 24224 through the [Forward](https://docs.fluentbit.io/manual/pipeline/outputs/forward) protocol, and send the messages to the STDOUT interface in JSON format every second:

```shell
docker run -p 127.0.0.1:24224:24224 fluent/fluent-bit /fluent-bit/bin/fluent-bit -i forward -o stdout -p format=json_lines -f 1
```

Now run a separate container that will send a test message.
This time the Docker container will use the Fluent Forward Protocol as the logging driver:

```shell
docker run --log-driver=fluentd -t ubuntu echo "Testing a log message"
```

On Fluent Bit container, it will print to stdout something like this:

```shell
Fluent Bit v1.9.8
* Copyright (C) 2015-2022 The Fluent Bit Authors
* Fluent Bit is a CNCF sub-project under the umbrella of Fluentd
* https://fluentbit.io

[2022/09/16 10:03:48] [ info] [fluent bit] version=1.9.8, commit=97a5e9dcf3, pid=1
[2022/09/16 10:03:48] [ info] [storage] version=1.2.0, type=memory-only, sync=normal, checksum=disabled, max_chunks_up=128
[2022/09/16 10:03:48] [ info] [cmetrics] version=0.3.6
[2022/09/16 10:03:48] [ info] [input:forward:forward.0] listening on 0.0.0.0:24224
[2022/09/16 10:03:48] [ info] [sp] stream processor started
[2022/09/16 10:03:48] [ info] [output:stdout:stdout.0] worker #0 started
{"date":1663322636.0,"source":"stdout","log":"Testing a log message\r","container_id":"e29e02e84ffa00116818a86f6f99305a7d0f77f25420eceeb9206b725f137af4","container_name":"/intelligent_austin"}
```

## Dockerfile

Refer to the definition in the source repository: <https://github.com/fluent/fluent-bit/blob/master/dockerfiles/Dockerfile>.

The container is built according to the instructions here: <https://github.com/fluent/fluent-bit/tree/master/dockerfiles>.

## Contact

Feel free to contact us through the following community channels:

- Slack: <https://slack.fluentd.org> / channel #fluent-bit
- Github: <https://github.com/fluent/fluent-bit>
- Twitter: <https://twitter.com/fluentbit>

## Fluent Bit & Fluentd

[Fluent Bit](https://fluentbit.io/) is a [CNCF](https://cncf.io/) sub-project under the umbrella of [Fluentd](https://www.fluentd.org/).

## License

This program is under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Authors

[Fluent Bit](https://fluentbit.io/) is a [CNCF](https://cncf.io/) sub-project under the umbrella of [Fluentd](https://www.fluentd.org/).

Made with love by [many contributors](https://github.com/fluent/fluent-bit/graphs/contributors) :).
