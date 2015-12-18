# Elastic Search

The __es__ output plugin, allows to flush your records into a [Elastic Search](http://www.elastic.co) instance. The following instructions assumes that you have a fully operational Elastic service running.

In order to flush records, the __es__ plugin requires to know a few parameters, the following table describes a list of them:

| parameter   | description          | default           |
|-------------|----------------------|-------------------|
| host        | IP address or hostname of the target Elasticsearch instance | 127.0.0.1 |
| port        | TCP port of the target Elasticsearch instance | 92000 |
| index       | Elastic index | fluentbit |
| type        | Elastic type      | test      |

> The parameters _index_ and _type_ can be confusing if you are new to Elastic, if you have used a common relational database before, they can be compared to the _database_ and _table_ concepts.

In order to override the default configuration values, the plugin uses the Fluent Bit network address format, e.g:

```
es://host:port/index/type
```

## Running

[Fluent Bit](http://fluentbit.io) only requires to know that it needs to use the __es__ output plugin, if no extra information is given it will use the default values specified in the above table.

```bash
$ bin/fluent-bit -i cpu -o es
Fluent-Bit v0.5.0
Copyright (C) Treasure Data

[2015/12/18 10:27:23] [ info] starting engine
[2015/12/18 10:27:23] [ info] [es] host=127.0.0.1 port=9200 index=fluentbit type=test
...
```

As described above, the target service and storage point can be changed, e.g:

```bash
$ bin/fluent-bit -i cpu -o es://192.168.9.3/metrics/cpu
Fluent-Bit v0.5.0
Copyright (C) Treasure Data

[2015/12/18 10:33:03] [ info] starting engine
[2015/12/18 10:33:03] [ info] [es] host=192.168.9.3 port=9200 index=metrics type=cpu
...
```

In order to check your incoming data, make sure to setup a Kibana service that visualize the rights _index_ and _types_ used by [Fluent Bit](http://fluentbit.io).
