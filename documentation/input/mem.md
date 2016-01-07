# Memory Usage

The __mem__ input plugin, gather the information about the memory usage of the running system every certain interval of time and reports the total amount of memory and the amount of free available.

In order to measure read the memory usage with [Fluent Bit](http://fluentbit.io), use the  following command line arguments:

```bash
$ build/bin/fluent-bit -i mem -o stdout
Fluent-Bit v0.6.0
Copyright (C) Treasure Data

[2016/01/07 11:26:43] [ info] Configuration
flush time     : 5 seconds
input plugins  : mem
collectors     :
[2016/01/07 11:26:43] [ info] starting engine
[0] [1452187603, {"total"=>8081700, "free"=>697248}]
[1] [1452187604, {"total"=>8081700, "free"=>693372}]
[2] [1452187605, {"total"=>8081700, "free"=>701496}]
[3] [1452187606, {"total"=>8081700, "free"=>700720}]
```
