# Serial Interface

The __serial__ input plugin, allows to retrieve messages/data from a _Serial_ interface. In order to use this plugin is required to write a simple configuration file before to run [Fluent Bit](http://fluentbit.io).

## Configuration File

[Fluent Bit](http://fluentbit.io) sources distribute an example configuration file for the serial interface and it's located under _conf/serial_input.conf_. The plugin recognize the following setup under a __SERIAL__ section:

| Key             | Description       |
| ----------------|-------------------|
| File            | Absolute path to the device entry, e.g: /dev/ttyS0 |
| Bitrate         | The bitrate for the communication, e.g: 9600, 38400, 115200, etc |


Here is an example:

```python
[SERIAL]
    # File
    # ====
    # Filename of serial port. e.g. /dev/ttyS0, /dev/ttyAMA0

    File    /dev/ttyS0

    # Bitrate
    # ========
    # Specify the bitrate to communicate using the port.

    Bitrate 9600
```

## Running

Once the configuration file is in place, collecting data from the _Serial_ interface is very straighforward. Just let [Fluent Bit](http://fluentbit.io) know the input/output plugins plus the configuration file location, e.g:

```bash
$ bin/fluent-bit -c serial.conf -i serial -o stdout -V
Fluent-Bit v0.1.0
Copyright (C) Treasure Data

[2015/07/29 12:39:37] [ info] Configuration
flush time     : 5 seconds
input plugins  : serial
collectors     :
[2015/07/29 12:39:37] [ info] starting engine
[2015/07/29 12:39:37] [debug] Serial / file='/dev/ttyS0' bitrate='9600'
```

> the -V argument is optional just to print out verbose messages.

Now every message that arrives to the _/dev/ttyS0_ interface will be printed to the standard output:

```bash
$ bin/fluent-bit -c serial.conf -i serial -o stdout -V
Fluent-Bit v0.1.0
Copyright (C) Treasure Data

[2015/07/29 12:39:37] [ info] Configuration
flush time     : 5 seconds
input plugins  : serial
collectors     :
[2015/07/29 12:39:37] [ info] starting engine
[2015/07/29 12:39:37] [debug] Serial / file='/dev/ttyS0' bitrate='9600'
[0] [1438193365, {"msg"=>"test1"}]
[1] [1438193366, {"msg"=>"test2"}]
[2] [1438193367, {"msg"=>"test3"}]
[3] [1438193368, {"msg"=>"test4"}]
```

## Emulating Serial Interface on Linux

The following content is some extra information that will allow you to emulate a serial interface on your Linux system, so you can test this _Serial_ input plugin locally in case you don't have such interface in your computer. The following procedure have been tested on Ubuntu 15.04 running a Linux Kernel 4.0.

## Build and install the tty0tty module

Download the sources

```bash
$ git clone https://github.com/freemed/tty0tty
```

Unpack and compile

```bash
$ cd tty0tty/module
$ make
```

Copy the new kernel module into the kernel modules directory

```bash
$ sudo cp tty0tty.ko /lib/modules/$(uname -r)/kernel/drivers/misc/
```

Load the module

```bash
$ sudo depmod
$ sudo modprobe tty0tty
```

You should see new serial ports in /dev/ (ls /dev/tnt*) Give appropriate permissions to the new serial ports:

```bash
$ sudo chmod 666 /dev/tnt*
```

When the module is loaded, it will interconnect the following virtual interfaces:

```bash
/dev/tnt0 <=> /dev/tnt1
/dev/tnt2 <=> /dev/tnt3
/dev/tnt4 <=> /dev/tnt5
/dev/tnt6 <=> /dev/tnt7
```

Now you can configure [Fluent Bit](http://fluentbit.io) to listen on _/dev/tnt0_ and write messages over _/dev/tnt1_, e.g:

```bash
$ sudo bin/fluent-bit -c serial.conf -i serial -o stdout -V
Fluent-Bit v0.1.0
Copyright (C) Treasure Data

[2015/07/29 12:50:03] [ info] Configuration
flush time     : 5 seconds
input plugins  : serial
collectors     :
[2015/07/29 12:50:03] [ info] starting engine
[2015/07/29 12:50:03] [debug] Serial / file='/dev/tnt0' bitrate='9600'
[2015/07/29 12:50:14] [debug] [in_serial] 'testing'
[0] [1438195814, {"msg"=>"testing"}]
[2015/07/29 12:50:17] [ info] Flush buf 21 bytes
```

Write some messages

```bash
$ echo "testing" > /dev/tnt1
```
