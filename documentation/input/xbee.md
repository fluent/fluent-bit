# XBee Radio

The __xbee__ plugin allows to listen for data through an [XBee Radio](http://www.digi.com/lp/xbee/) device. These devices uses ZigBee for their communication and the __xbee__ plugin allows to retrieve those messages when using an [XBee](http://www.digi.com/lp/xbee/). In order to use this plugin is required to write a siple configuration file before to run [Fluent Bit](http://fluentbit.io).

## Configuration File

[Fluent Bit](http://fluentbit.io) sources distribute an example configuration file for the serial interface and it's located under _conf/serial_input.conf_. The plugin recognize the following setup under a __XBEE__ section:

| Key             | Description       |
| ----------------|-------------------|
| File            | Absolute path to the device entry, e.g: /dev/ttyUSB0 |
| Baudrate        | Specify the baudrate for the communication, e.g: 9600, 38400, 115200, etc |


Here is an example:

```python
[SERIAL]
    # File
    # ====
    # Filename of serial port. e.g. /dev/ttyS0, /dev/ttyAMA0

    File    /dev/ttyS0

    # Bitrate
    # ========
    # Specify the baudrate

    Bitrate 9600
```

## Running

Once the configuration file is in place, make sure your XBee device is recognized by your operating system before starting [Fluent Bit](http://fluentbit.io), then you can start it with the following way:

```bash
$ bin/fluent-bit -c xbee.conf -i xbee -o stdout -V
```

As input data the _xbee_ plugin recognize the following JSON data formats:

```bash
1. { map => val, map => val, map => val }
2. [ time, { map => val, map => val, map => val } ]
```
