# Memory Usage

The __mem__ input plugin, gathers the information about the memory usage of the running system every certain interval of time and reports the total amount of memory and the amount of free available.

## Getting Started

In order to get memory usage from your system, you can run the plugin from the command line or through the configuration file:

### Command Line

```bash
$ bin/fluent-bit -i mem -t memory -o stdout -m '*'
Fluent-Bit v0.8.0
Copyright (C) Treasure Data

[0] memory: [1463544745, {"total"=>8081140, "free"=>2548704}]
[1] memory: [1463544746, {"total"=>8081140, "free"=>2560020}]
[2] memory: [1463544747, {"total"=>8081140, "free"=>2559616}]
[3] memory: [1463544748, {"total"=>8081140, "free"=>2559568}]
```

### Configuration File

In your main configuration file append the following _Input_ & _Output_ sections:

```python
[INPUT]
    Name   mem
    Tag    memory

[OUTPUT]
    Name   stdout
    Match  *
```
