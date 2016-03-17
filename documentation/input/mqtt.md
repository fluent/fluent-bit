# MQTT

The __MQTT__ input plugin, allows to retrieve messages/data from MQTT control packets over a TCP connection.

## Configuration File

[Fluent Bit](http://fluentbit.io) sources distribute an example configuration file for the MQTT plugin and it's located under _conf/in_mqtt.conf_. The plugin recognizes the following setup under a __MQTT__ section:

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
$ bin/fluent-bit -i mqtt -o stdout -V
Fluent-Bit v0.3.0
Copyright (C) Treasure Data

[2015/10/19 15:16:42] [ info] Configuration
flush time     : 5 seconds
input plugins  : mqtt
collectors     :
[2015/10/19 15:16:42] [ info] starting engine
[2015/10/19 15:16:42] [debug] MQTT Listen='0.0.0.0' TCP_Port=1883
[2015/10/19 15:16:42] [debug] [mqtt] binding 0.0.0.0:1883
[2015/10/19 15:16:42] [debug] [stats] register in plugin: mqtt
[2015/10/19 15:16:42] [debug] [stats] register out plugin: stdout
[2015/10/19 15:16:46] [debug] [mqtt] ... bytes in
[2015/10/19 15:16:46] [debug] [mqtt] fd=14 closed connection
[2015/10/19 15:16:46] [debug] [thread 0x1db2110] created
[0] [1445289404, {"topic"=>"some/topic", "key"=>1}]
[1] [1445289405, {"topic"=>"some/topic", "key"=>1}]
[2] [1445289406, {"topic"=>"some/topic", "key"=>2}]
```

> the -V argument is optional just to print out verbose messages.

In order to simulate the data above you need to install the _mosquitto_ tool and try to publish a message with the following command line:

```bash
$ mosquitto_pub  -m '{"key": 1}' -t some/topic
```

As you can see in the example above, the final record will contain your JSON map keys plus the topic set when the publish message was sent.
