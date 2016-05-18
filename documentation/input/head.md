# Head

The __head__ input plugin, allows to read events from the head of file. It's behavior is similar to the _head_ command.

## Configuration Parameters

The plugin supports the following configuration parameters:

| Key           | Description |
| --------------|-------------|
| File          | Absolute path to the target file, e.g: /proc/uptime |
| Buf_Size      | Buffer size to read the file. |
| Interval_Sec  | Polling interval (seconds). |
| Interval_NSec | Polling interval (nanosecond). |

## Getting Started

In order to read the head of a file, you can run the plugin from the command line or through the configuration file:

### Command Line

The following example will read events from the /proc/uptime file, tag the records with the _uptime_ name and flush them back to the _stdout_ plugin:

```bash
$ fluent-bit -i head -t uptime -p File=/proc/uptime -o stdout -m '*'
Fluent-Bit v0.8.0
Copyright (C) Treasure Data

[2016/05/17 21:53:54] [ info] starting engine
[0] uptime: [1463543634, {"head"=>"133517.70 194870.97"}]
[1] uptime: [1463543635, {"head"=>"133518.70 194872.85"}]
[2] uptime: [1463543636, {"head"=>"133519.70 194876.63"}]
[3] uptime: [1463543637, {"head"=>"133520.70 194879.72"}]
```

### Configuration File

In your main configuration file append the following _Input_ & _Output_ sections:

```python
[INPUT]
    Name          head
    Tag           uptime
    File          /proc/uptime
    Buf_Size      256
    Interval_Sec  1
    Interval_NSec 0

[OUTPUT]
    Name   stdout
    Match  *
```

Note: Total interval (sec) = Interval_Sec + (Interval_Nsec / 1000000000).

e.g. 1.5s = 1s + 500000000ns
