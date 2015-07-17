# CPU Usage

The __cpu__ input plugin, measure the overall CPU usage of the system between certain intervals of time, by design it do not get information per-core, instead just the total reported by the Kernel.

In order to measure the CPU usage of your system with [Fluent Bit](http://fluentbit.io), specify the following command line arguments:

```
$ ./bin/fluent-bit -i cpu -o stdout -V
Fluent-Bit v0.1.0
Copyright (C) Treasure Data

[2015/07/17 15:36:09] [ info] Configuration
flush time     : 5 seconds
input plugins  : cpu
collectors     :
[2015/07/17 15:36:09] [ info] starting engine
[2015/07/17 15:36:09] [debug] [in_cpu] CPU 3.25% (buffer=0)
[2015/07/17 15:36:10] [debug] [in_cpu] CPU 9.25% (buffer=1)
[2015/07/17 15:36:11] [debug] [in_cpu] CPU 4.50% (buffer=2)
[2015/07/17 15:36:12] [debug] [in_cpu] CPU 2.75% (buffer=3)
[0] [1437168969, {"cpu"=>3.250000}]
[1] [1437168970, {"cpu"=>9.250000}]
[2] [1437168971, {"cpu"=>4.500000}]
[3] [1437168972, {"cpu"=>2.750000}]
[2015/07/17 15:36:13] [ info] Flush buf 84 bytes

```

As described above, the CPU input plugin gather the overall usage every one second and flushed the information to the output on the fifth second. On this example we used the __stdout__ plugin to demonstrate the data output records.
