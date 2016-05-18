# Output Plugins

The _output plugins_ defines where [Fluent Bit](http://fluentbit.io) should flush the information it gather from the input. At the moment the available options are the following:

| name                      |  title             | description     |
|---------------------------|--------------------|-----------------|
| [forward](forward.md)     | Forward  | Fluentd forward protocol. |
| [http](http.md)           | HTTP|    | Flush records to an HTTP end point. |
|[stdout](stdout.md)       | Standard Output | Flush records to the standard output.|
| [td](td.md)     | [Treasure Data](http://www.treasuredata.com) | Flush records to the [Treasure Data](http://www.treasuredata.com) cloud service for analytics.|
| [es](elasticsearch.md)     | Elasticsearch | flush records to a Elasticsearch server. |
| [nats](nats.md) | NATS          | flush records to a NATS server. |
