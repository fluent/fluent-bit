# NATS

The __nats__ output plugin, allows to flush your records into a [NATS Server](http://nats.io/documentation/server/gnatsd-intro/) end point. The following instructions assumes that you have a fully operational NATS Server in place.

In order to flush records, the __nats__ plugin requires to know two parameters:

| parameter   | description          | default           |
|-------------|----------------------|-------------------|
| host        | IP address or hostname of the NATS Server | 127.0.0.1 |
| port        | TCP port of the target NATS Server | 4222 |

In order to override the default configuration values, the plugin uses the optional Fluent Bit network address format, e.g:

```
nats://host:port
```

## Running

[Fluent Bit](http://fluentbit.io) only requires to know that it needs to use the __nats__ output plugin, if no extra information is given, it will use the default values specified in the above table.

```bash
$ bin/fluent-bit -i cpu -o nats -V -f 5
Fluent-Bit v0.7.0
Copyright (C) Treasure Data

[2016/03/04 10:17:33] [ info] Configuration
flush time     : 5 seconds
input plugins  : cpu
collectors     :
[2016/03/04 10:17:33] [ info] starting engine
cpu[all] all=3.250000 user=2.500000 system=0.750000
cpu[i=0] all=3.000000 user=1.000000 system=2.000000
cpu[i=1] all=3.000000 user=2.000000 system=1.000000
cpu[i=2] all=2.000000 user=2.000000 system=0.000000
cpu[i=3] all=6.000000 user=5.000000 system=1.000000
[2016/03/04 10:17:33] [debug] [in_cpu] CPU 3.25%
...
```

As described above, the target service and storage point can be changed, e.g:


## Data format

For every set of records flushed to a NATS Server, Fluent Bit uses the following JSON format:

```json
[
  [UNIX_TIMESTAMP, JSON_MAP_1],
  [UNIX_TIMESTAMP, JSON_MAP_2],
  [UNIX_TIMESTAMP, JSON_MAP_N],
]
```

Each record is an individual entity represented in a JSON array that contains a UNIX_TIMESTAMP and a JSON map with a set of key/values. A summarized output of the CPU input plugin will looks as this:

```
[
  [1457108504,{"tag":"fluentbit","cpu_p":1.500000,"user_p":1,"system_p":0.500000}],
  [1457108505,{"tag":"fluentbit","cpu_p":4.500000,"user_p":3,"system_p":1.500000}],
  [1457108506,{"tag":"fluentbit","cpu_p":6.500000,"user_p":4.500000,"system_p":2}]
]
```
