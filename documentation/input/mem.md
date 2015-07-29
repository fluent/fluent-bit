# Memory Usage

The __mem__ input plugin, gather the information about the memory usage of the running system every certain interval of time and reports the total amount of memory and the amount of free available.

In order to measure read the Kernel log messages with [Fluent Bit](http://fluentbit.io), specify the following command line arguments:

```bash
$ bin/fluent-bit -i mem -o stdout -V
Fluent-Bit v0.1.0
Copyright (C) Treasure Data

[2015/07/17 15:48:28] [ info] Configuration
flush time     : 5 seconds
input plugins  : mem
collectors     :
[2015/07/17 15:48:28] [ info] starting engine
[2015/07/17 15:48:28] [debug] [in_mem] memory total -314380288 kb, free 659427328 kb (buffer=0)
[2015/07/17 15:48:29] [debug] [in_mem] memory total -314380288 kb, free 659394560 kb (buffer=1)
[2015/07/17 15:48:30] [debug] [in_mem] memory total -314380288 kb, free 659046400 kb (buffer=2)
[2015/07/17 15:48:31] [debug] [in_mem] memory total -314380288 kb, free 658538496 kb (buffer=3)
[2015/07/17 15:48:32] [debug] [in_mem] memory total -314380288 kb, free 658190336 kb (buffer=4)
[0] [1437169708, {"total"=>8081596, "free"=>643972}]
[1] [1437169709, {"total"=>8081596, "free"=>643940}]
[2] [1437169710, {"total"=>8081596, "free"=>643600}]
[3] [1437169711, {"total"=>8081596, "free"=>643104}]
[4] [1437169712, {"total"=>8081596, "free"=>642764}]
[2015/07/17 15:48:32] [ info] Flush buf 150 bytes
```
