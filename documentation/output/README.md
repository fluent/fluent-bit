# Output Plugins

The _output plugins_ defines where [Fluent Bit](http://fluentbit.io) should flush the information it gather from the input. At the moment the available options are the following:

| name                      |  title             | description     |
|---------------------------|--------------------|-----------------|
| [fluentd](fluentd.md)     | [Fluentd](http://fluentd.org)  | Flush data records to a [Fluentd](http://fluentd.org) instance.|
| [stdout](stdout.md)       | Standard Output | Flush records to the standard output.|
| [td](td.md)     | [Treasure Data](http://www.treasuredata.com) | Flush records to the [Treasure Data](http://www.treasuredata.com) cloud service for analytics.|
| [es](es.md)     | Elasticsearch | flush records to a Elasticsearch server. |
| [nats](nats.md) | NATS          | flush records to a NATS server. |