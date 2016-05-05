# Forward

_Forward_ is the protocol used by [Fluentd](http://www.fluentd.org) to route messages between peers. The __forward__ output plugin allows to integrate [Fluent Bit](http://fluentbit.io) with [Fluentd](http://fluentd.org) easily. There are not configuration steps required besides to specify where [Fluentd](http://fluentd.org) is located, it can be on the local host or a in a remote machine.

## Forward Setup

Before to proceed, make sure that [Fluentd](http://fluentd.org) is installed in your system, if it's not the case please refer to the following [Fluentd Installation](http://docs.fluentd.org/v0.12/categories/installation) document and go ahead with that.

Once [Fluentd](http://fluentd.org) is installed, create the following configuration file example that will allow us to stream data into it:

```
<source>
  type forward
  bind 0.0.0.0
  port 12225
</source>

<match fluent_bit>
  type stdout
</match>
```

That configuration file specify that will listen for _TCP_ connections on the port _12225_ through the __forward__ input type. Then for every message with a _fluent\_bit_ __TAG, will print it out to the standard output.

In one terminal launch [Fluentd](http://fluentd.org) specifying the new configuration file created (in_fluent-bit.conf):

```bash
$ fluentd -c in_fluent-bit.conf
2015-07-29 14:50:47 -0600 [info]: reading config file path="in_fluent-bit.conf"
2015-07-29 14:50:47 -0600 [info]: starting fluentd-0.12.14
2015-07-29 14:50:47 -0600 [info]: gem 'fluent-plugin-mongo' version '0.7.9'
2015-07-29 14:50:47 -0600 [info]: gem 'fluent-plugin-multi-format-parser' version '0.0.2'
2015-07-29 14:50:47 -0600 [info]: gem 'fluent-plugin-rewrite-tag-filter' version '1.5.1'
2015-07-29 14:50:47 -0600 [info]: gem 'fluentd' version '0.12.8'
2015-07-29 14:50:47 -0600 [info]: gem 'fluentd' version '0.12.5'
2015-07-29 14:50:47 -0600 [info]: gem 'fluentd' version '0.10.61'
2015-07-29 14:50:47 -0600 [info]: adding match pattern="fluent_bit" type="stdout"
2015-07-29 14:50:47 -0600 [info]: adding source type="forward"
2015-07-29 14:50:47 -0600 [info]: using configuration file: <ROOT>
<source>
  type forward
  bind 0.0.0.0
  port 12225
</source>
<match fluent_bit>
  type stdout
  </match>
</ROOT>
2015-07-29 14:50:47 -0600 [info]: listening fluent socket on 0.0.0.0:12225
```

## Fluent Bit Setup

Now that [Fluentd](http://fluentd.org) is ready to receive messages, we need to specify where the __forward__ output plugin will flush the information using the following format:

```
bin/fluent-bit -i INPUT -o forward://HOST:PORT/TAG
```

If the __TAG__ parameter is not set, the plugin will set the tag as _fluent\_bit_. Keep in mind that __TAG__ is important for routing rules inside [Fluentd](http://fluentd.org).

Using the [CPU](../input/cpu.md) input plugin as an example we will flush CPU metrics to [Fluentd](http://fluentd.org):

```bash
$ bin/fluent-bit -i cpu -o forward://127.0.0.1:12225
```

In [Fluent Bit](http://fluentbit.io) we should see the following output:

```
Fluent Bit v0.3.0
Copyright (C) Treasure Data

[2015/07/29 14:58:02] [ info] Configuration
 flush time     : 5 seconds
 input plugins  : cpu
 collectors     :
[2015/07/29 14:58:02] [ info] starting engine
[2015/07/29 14:58:02] [debug] [in_cpu] CPU 4.25% (buffer=0)
[2015/07/29 14:58:03] [debug] [in_cpu] CPU 13.00% (buffer=1)
[2015/07/29 14:58:04] [debug] [in_cpu] CPU 8.50% (buffer=2)
[2015/07/29 14:58:05] [debug] [in_cpu] CPU 2.50% (buffer=3)
[2015/07/29 14:58:06] [ info] Flush buf 98 bytes
```

Now on the [Fluentd](http://fluentd.org) side the following:

```bash
2015-07-29 14:50:47 -0600 [info]: listening fluent socket on 0.0.0.0:12225
2015-07-29 14:58:02 -0600 fluent_bit: {"cpu":4.25}
2015-07-29 14:58:03 -0600 fluent_bit: {"cpu":13.0}
2015-07-29 14:58:04 -0600 fluent_bit: {"cpu":8.5}
2015-07-29 14:58:05 -0600 fluent_bit: {"cpu":2.5}
```

So we gathered [CPU](../input/cpu.md) metrics and flush them out to [Fluentd](http://fluentd.org) properly.
