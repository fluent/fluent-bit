# Fluent Bit Docker Image

[Fluent Bit](https://fluentbit.io) container images are available on Docker Hub ready for production usage. Our stable images are based in [Distroless](https://github.com/GoogleContainerTools/distroless) focusing on security containing just the Fluent Bit binary, minimal system libraries and basic configuration.

Optionally, we provide debug images which contains Busybox that can be used to troubleshoot or testing purposes.

For a detailed list of Tags and versions available, please refer to the the official documentation:

https://docs.fluentbit.io/manual/installation/docker



## 1. Checkout Branch

Fluent Bit Dockerfiles are located in separated branches with proper tags:

| Branch | Tags Available                                               |
| ------ | ------------------------------------------------------------ |
| 1.2    | 1.2, 1.2-debug, 1.2.0, 1.2.0-debug, 1.2.1, 1.2.1-debug |
| 1.1    | 1.1, 1.1-debug, 1.1.0, 1.1.0-debug, 1.1.1, 1.1.1-debug, 1.1.2, 1.1.2-debug, 1.1.3, 1.1.3-debug |
| 1.0    | 1.0, 1.0-debug, 1.0.0, 1.0.1, 1.0.2, 1.0.3, 1.0.3-debug, 1.0.4, 1.0.4-debug, 1.0.5, 1.0.5-debug, 1.0.6, 1.0.6-debug |
| 0.14   | 0.14, 0.14.0, 0.14.1, 0.14.2, 0.14.3, 0.14.4, 0.14.5, 0.14.6, 0.14.7, 0.14.8, 0.14.9 |
| 0.13   | 0.13, 0.13.0, 0.13.1, 0.13.2, 0.13.3, 0.13.4, 0.13.5, 0.13.6, 0.13.7, 0.13.8 |
| 0.12   | 0.12, 0.12.19, 0.12.18, 0.12.17, 0.12.16, 0.12.15, 0.12.14, 0.12.13, 0.12.12, 0.12.11, 0.12.10, 0.12.9, 0.12.8, 0.12.7, 0.12.6, 0.12.5, 0.12.4, 0.12.3, 0.12.2, 0.12.1, 0.12.0 |

## 2. Build image

Use `docker build` command to build the image. This example names the image "fluent-bit:latest":

```
$ docker build -t fluent/fluent-bit:1.2 ./
```

## 3. Test it

Once the image is built, it's ready to run:

```
docker run -p 127.0.0.1:24224:24224 fluent/fluent-bit:latest
```

By default, the configuration set a listener on TCP port 24224 through Forward protocol and prints to the standard output interface each message. So this can be used to forward Docker log messages from one container to the Fluent Bit image, e.g:

```
$ docker run --log-driver=fluentd -t ubuntu echo "Testing a log message"
```


On Fluent Bit container will print to stdout something like this:

```
Fluent Bit v1.2.x
Copyright (C) Treasure Data

[0] docker.31c94ceb86ca: [1487548735, {"container_id"=>"31c94ceb86cae7055564eb4d65cd2e2897addd252fe6b86cd11bddd70a871c08", "container_name"=>"/admiring_shannon", "source"=>"stdout","}]og"=>"Testing a log message
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
