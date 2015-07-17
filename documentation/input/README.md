# Input Plugins

The _input plugins_ defines the source from where [Fluent Bit](http://fluentbit.io) can collect data, it can be through a network interface, radio hardware or some built-in metric. As of this version the following input plugins are available:

| name                        |  title             | description     |
|-----------------------------|--------------------|-----------------|
| [cpu](cpu.md)         | CPU Usage  | measure total CPU usage of the system.|
| [kmsg](kmsg.md)       | Kernel Log Buffer | read the Linux Kernel log buffer messages.|
| [mem](mem.md)         | Memory Usage | measure the total amount of memory used on the system.|
| [serial](serial.md)   | Serial Interface | read data information from the serial interface.|
| [stdin](stdin.md)     | Standard Input | read data from the standard input. |
| [xbee](xbee.md)       | XBee Radio | read data through an XBee Radio device. |
