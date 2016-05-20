# Elasticsearch

The __es__ output plugin, allows to flush your records into a [Elastic Search](http://www.elastic.co) instance. The following instructions assumes that you have a fully operational Elasticsearch service running.

## Configuration Parameters

| Key         | Description          | default           |
|-------------|----------------------|-------------------|
| Host        | IP address or hostname of the target Elasticsearch instance | 127.0.0.1 |
| Port        | TCP port of the target Elasticsearch instance | 9200 |
| Index       | Elastic index | fluentbit |
| Type        | Elastic type      | test      |

> The parameters _index_ and _type_ can be confusing if you are new to Elastic, if you have used a common relational database before, they can be compared to the _database_ and _table_ concepts.

## Getting Started

In order to insert records into a Elasticsearch service, you can run the plugin from the command line or through the configuration file:

### Command Line

The __es__ plugin, can read the parameters from the command line in two ways, through the __-p__ argument (property) or setting them directly through the service URI. The URI format is the following:

```
es://host:port/index/type
```

Using the format specified, you could start Fluent Bit through:

```
$ fluent-bit -i cpu -t cpu -o es://192.168.2.3:9200/my_index/my_type \
    -o stdout -m '*'
```

which is similar to do:

```
$ fluent-bit -i cpu -t cpu -o es -p Host=192.168.2.3 -p Port=9200 \
    -p Index=my_index -p Type=my_type -o stdout -m '*'
```

### Configuration File

In your main configuration file append the following _Input_ & _Output_ sections:

```Python
[INPUT]
    Name  cpu
    Tag   cpu

[OUTPUT]
    Name  es
    Match *
    Host  192.168.2.3
    Port  9200
    Index my_index
    Type  my_type
```

## About Elasticsearch field names

Some input plugins may generate messages where the field names contains dots, since Elasticsearch 2.0 this is not longer allowed, so the current __es__ plugin replace them with an underscore, e.g:

```
{"cpu0.p_cpu"=>17.000000}
```

becomes

```
{"cpu0_p_cpu"=>17.000000}
```
