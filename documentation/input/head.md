# File

The __head__ input plugin, allows to read events from the head of file. It's behavior is similar to the _tail_ command.

## Configuration File

[Fluent Bit](http://fluentbit.io) sources distribute an example configuration file for the plugin and it's located under _conf/in_head.conf_. The plugin recognize the following setup under a __HEAD__ section:

| Key           | Description |
| --------------|-------------|
| File          | Absolute path to the file, e.g: /proc/uptime |
| Buf_Size      | Buffer size to read the file. |
| Interval_Sec  | Polling interval. (second) |
| Interval_NSec | Polling interval. (nanosecond) |

Note: Total interval (sec) = Interval_Sec + (Interval_Nsec / 1000000000)

e.g. 1.5s = 1s + 500000000ns

Here is an example of configuration file:

```python
[HEAD]
    # File
    # ====
    # File path. e.g. /proc/uptime
    #
    File    /proc/uptime

    # Buf_Size
    # ====
    # Buffer size to read file. Default 256
    Buf_Size 256

    # Total Interval 
    #     = Interval Sec + ( Interval Nsec * 1000 * 1000 * 1000 )
    #
    # Interval Sec
    # ====
    # Read interval (sec) Default 1
    Interval_Sec 1

    # Interval NSec
    # ====
    # Read interval (nsec) Default 0
    Interval_NSec 0
```


## Getting Started

In order to read a file with [Fluent Bit](http://fluentbit.io), specify the following command line arguments:

```bash
$ bin/fluent-bit -i head -o stdout -c ../conf/in_head.conf  -V
Fluent-Bit v0.7.0
Copyright (C) Treasure Data

[2016/03/15 22:21:16] [ info] Configuration
 flush time     : 5 seconds
 input plugins  : head 
 collectors     : 
[2016/03/15 22:21:16] [ info] starting engine
[2016/03/15 22:21:16] [debug] Head config: buf_size=10 path=/proc/uptime
[2016/03/15 22:21:16] [debug] Head config: interval_sec=1 interval_nsec=0
[2016/03/15 22:21:16] [debug] in_head_init read_len=0 buf_size=8
[2016/03/15 22:21:17] [debug] in_head_collect read_len=10 buf_size=10
[2016/03/15 22:21:18] [debug] in_head_collect read_len=10 buf_size=10
[2016/03/15 22:21:19] [debug] in_head_collect read_len=10 buf_size=10
[2016/03/15 22:21:20] [debug] in_head_collect read_len=10 buf_size=10
[2016/03/15 22:21:21] [debug] [thread 0xbea920] created
[0] [1458048077, {"head"=>"90604.14 8"}]
[1] [1458048078, {"head"=>"90605.14 8"}]
[2] [1458048079, {"head"=>"90606.14 8"}]
[3] [1458048080, {"head"=>"90607.14 8"}]
[2016/03/15 22:21:21] [debug] [thread 0xbea920] ended
```