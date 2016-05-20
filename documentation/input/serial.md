# Serial Interface

The __serial__ input plugin, allows to retrieve messages/data from a _Serial_ interface.

## Configuration Parameters

| Key             | Description       |
| ----------------|-------------------|
| File            | Absolute path to the device entry, e.g: /dev/ttyS0 |
| Bitrate         | The bitrate for the communication, e.g: 9600, 38400, 115200, etc |
| Min_Bytes       | The serial interface will expect at least _Min\_Bytes_ to be available before to process the message (default: 1)
| Separator       | Allows to specify a _separator_ string that's used to determinate when a message ends. |

## Getting Started

In order to retrieve messages over the _Serial_ interface, you can run the plugin from the command line or through the configuration file:

### Command Line

The following example loads the input _serial_ plugin where it set a Bitrate of 9600, listen from the _/dev/tnt0_ interface and use the custom tag _data_ to route the
message.

```
$ fluent-bit -i serial -t data -p File=/dev/tnt0 -p BitRate=9600 -o stdout -m '*'
```

The above interface (/dev/tnt0) is an emulation of the serial interface (more details at bottom), for demonstrative purposes we will write some message to the other end of the interface, in this case _/dev/tnt1_, e.g:

```
$ echo 'this is some message' > /dev/tnt1

```

In Fluent Bit you should see an output like this:

```bash
$ fluent-bit -i serial -t data -p File=/dev/tnt0 -p BitRate=9600 -o stdout -m '*'
Fluent-Bit v0.8.0
Copyright (C) Treasure Data

[2016/05/20 15:44:39] [ info] starting engine
[0] data: [1463780680, {"msg"=>"this is some message"}]

```

Now using the _Separator_ configuration, we could send multiple messages at once (run this command after starting Fluent Bit):


```
$ echo 'aaXbbXccXddXee' > /dev/tnt1
```

```
$ fluent-bit -i serial -t data -p File=/dev/tnt0 -p BitRate=9600 -p Separator=X -o stdout -m '*'
Fluent-Bit v0.8.0
Copyright (C) Treasure Data

[2016/05/20 16:04:51] [ info] starting engine
[0] data: [1463781902, {"msg"=>"aa"}]
[1] data: [1463781902, {"msg"=>"bb"}]
[2] data: [1463781902, {"msg"=>"cc"}]
[3] data: [1463781902, {"msg"=>"dd"}]
```

### Configuration File

In your main configuration file append the following _Input_ & _Output_ sections:

```python
[INPUT]
    Name      serial
    Tag       data
    File      /dev/tnt0
    BitRate   9600
    Separator X

[OUTPUT]
    Name   stdout
    Match  *
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
