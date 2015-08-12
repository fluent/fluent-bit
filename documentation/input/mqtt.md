# MQTT

The __MQTT__ input plugin, allows to retrieve messages/data from MQTT control packets over a TCP connection.

## Configuration File

[Fluent Bit](http://fluentbit.io) sources distribute an example configuration file for the MQTT plugin and it's located under _conf/in_mqtt.conf_. The plugin recognize the following setup under a __MQTT__ section:

| Key      | Description       |
| ---------|-------------------|
| Listen   | Listener network interface, default: 0.0.0.0 |
| Port     | TCP port where listening for connections, default: 1883 |


Here is an example:

```python
[MQTT]
    # The Listen interface, by default we listen on all of them
    Listen 0.0.0.0

    # Default MQTT TCP port
    Port   1883
```

## Running

Once the configuration file is in place, collecting data is very straighforward. Just let [Fluent Bit](http://fluentbit.io) know the input/output plugins plus the configuration file location, e.g:

```bash
$ bin/fluent-bit -c ../conf/in_mqtt.conf -i mqtt -o stdout -V
Fluent-Bit v0.2.0
Copyright (C) Treasure Data

[2015/08/12 16:52:37] [ info] Configuration
 flush time     : 5 seconds
 input plugins  : mqtt
 collectors     :
[2015/08/12 16:52:37] [ info] starting engine
[2015/08/12 16:52:37] [debug] MQTT Listen='0.0.0.0' TCP_Port=1883
[2015/08/12 16:52:37] [debug] [mqtt] binding 0.0.0.0:1883
[2015/08/12 16:52:51] [debug] [mqtt] new TCP connection arrived FD=6
[2015/08/12 16:52:51] [debug] [mqtt] 37 bytes in
[2015/08/12 16:52:51] [debug] [mqtt] 23 bytes in
[2015/08/12 16:52:51] [debug] JSON to pack: '{"key": 1}/29497-monotop'
[2015/08/12 16:52:51] [debug] json_pack: token=0 is OBJECT (size=1)
[2015/08/12 16:52:51] [debug] json_pack: token=1 is STRING (len=3)
[2015/08/12 16:52:51] [debug] json_pack: token=2 is INT64
[2015/08/12 16:52:51] [debug] [mqtt] 2 bytes in
[2015/08/12 16:52:51] [debug] [mqtt] fd=6 closed connection
[0] {"key"=>1}
[2015/08/12 16:52:51] [ info] Flush buf 7 bytes
```

> the -V argument is optional just to print out verbose messages.

In order to simulate the data above you need to install the _mosquitto_ tool and try to publish a message with the following command line:

```bash
$ mosquitto_pub  -m '{"key": 1}' -t some/topic
```
