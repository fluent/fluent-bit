# Standard Output

The __stdout__ output plugin allows to print to the standard output the data received through the _input_ plugin. Their usage is very simple as follows:

```bash
$ bin/fluent-bit -i cpu -o stdout -V
```

We have specified to gather [CPU](../input/cpu.md) usage metrics and print them out to the standard output in a human readable way:

```bash
Fluent-Bit v0.1.0
Copyright (C) Treasure Data

[2015/07/29 15:06:06] [ info] Configuration
 flush time     : 5 seconds
 input plugins  : cpu
 collectors     :
[2015/07/29 15:06:06] [ info] starting engine
[2015/07/29 15:06:06] [debug] [in_cpu] CPU 1.25% (buffer=0)
[2015/07/29 15:06:07] [debug] [in_cpu] CPU 5.75% (buffer=1)
[2015/07/29 15:06:08] [debug] [in_cpu] CPU 9.25% (buffer=2)
[2015/07/29 15:06:09] [debug] [in_cpu] CPU 2.50% (buffer=3)
[2015/07/29 15:06:10] [debug] [in_cpu] CPU 3.25% (buffer=4)
[0] [1438203966, {"cpu"=>1.250000}]
[1] [1438203967, {"cpu"=>5.750000}]
[2] [1438203968, {"cpu"=>9.250000}]
[3] [1438203969, {"cpu"=>2.500000}]
[4] [1438203970, {"cpu"=>3.250000}]
[2015/07/29 15:06:10] [ info] Flush buf 105 bytes

```

No more, no less, it just works.
