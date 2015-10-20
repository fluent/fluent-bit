# Treasure Data

The __td__ output plugin, allows to flush your records to the [Treasure Data](http://treasuredata.com) cloud service.


## Configuration File

[Fluent Bit](http://fluentbit.io) sources distribute an example configuration file for the [Treasure Data](http://www.treasuredata.com) plugin and it's located under conf/td.conf. The plugin recognize the following setup under a TD section:

| Key      | Description       |
| ---------|-------------------|
| API      | The [Treasure Data](http://treasuredata.com) API key. To obtain it please log into the [Console](https://console.treasuredata.com) and in the API keys box, copy the API key hash.|
| Database | Specify the name of your target database. |
| Table    | Specify the name of your target table where the records will be stored.|

Here is an example:

```python
[TD]
    API      5713/e75be23caee19f8041dfa635ddfbd0dcd8c8d981
    Database fluentbit
    Table    samples
```

## Running

One the configuration file, just let [Fluent Bit](http://fluentbit.io) know the input/output plugins plus the configuration file location, e.g:

```bash
$ bin/fluent-bit -i cpu -o td -c ../conf/td.conf -V
Fluent-Bit v0.3.0
Copyright (C) Treasure Data

[2015/10/20 12:48:12] [ info] Configuration
flush time     : 5 seconds
input plugins  : cpu
collectors     :
[2015/10/20 12:48:12] [ info] starting engine
[2015/10/20 12:48:12] [debug] TreasureData / database='fluentbit' table='samples'
[2015/10/20 12:48:12] [debug] [upstream] connecting to api.treasuredata.com:443
...
```

> the -V argument is optional just to print out verbose messages.

Once the service is running, you can check how data imported into the [Treasure Data Console](https://console.treasuredata.com) selecting your target database and table. Note that the records can take a few seconds to show up into the interface.
