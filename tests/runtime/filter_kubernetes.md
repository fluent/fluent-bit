# Filter Kubernetes Tests

The tests implemented on [filter_kubernets.c]() file aims to take different Kubernetes Pod log files (formats) and play with different setups. These files resides in the [data/kubernetes]() directory and each .log file have it corresponding .meta  which contains the metadata associated with the Pod.

The unit test implements a fake Kubernetes API server to expose .meta files when the filter query for such data. This make things easier to test without to spawn a real cluster.

If you find that a specific test is missing, don't hesitate to open an issue on our Github repository.

## Tests Available

All log files used in these tests have been generated in a single Kubernetes cluster with Minikube.

- [Apache Logs](#apache-logs)

- [Apache Logs Annotated](#apache-logs-annotated)

- [Apache Logs Annotated Invalid](#apache-logs-annotated-invalid)

- [JSON Stringify](#json-stringify)

- [JSON Invalid](#json-invalid)

- No Log

  ​

#### Apache Logs

|||
|-|-|
| Description | Simple Apache access log line                                |
| Log File    | apache-logs_default_apache-logs-ac6095b6c715d823d732dcc9067f75b1299de5cc69a012b08d616a6058bdc0ad.log |
| Command     | $ kubectl run apache-logs --rm --attach --restart=Never --image=edsiper/apache_logs |

#### Apache Logs Annotated

|             |                                                              |
| ----------- | ------------------------------------------------------------ |
| Description | Simple Apache access log line with annotation suggesting a registered Parser |
| Log File    | apache-logs-annotated_default_apache-logs-annotated-5c79b78d458d86fff56127cc8657058c10b837d0f2c147b61afea4c8bc65fad7.log |
| Command     | $ kubectl run apache-logs-annotated --rm --attach --restart=Never --image=edsiper/apache_logs |
| Command     | $ kubectl annotate pods apache-logs-annotated logging.parser='apache' |



#### Apache Logs Annotated Invalid

|             |                                                              |
| ----------- | ------------------------------------------------------------ |
| Description | Simple Apache access log line with annotation suggesting an invalid Parser |
| Log File    | apache-logs-annotated-invalid_default_apache-logs-annotated-invalid-b8aab41f6104d7d7ea121852cd00276d8fe42d2a3192b3ae8f949477a272b91b.log |
| Command     | $ kubectl run apache-logs-annotated-invalid --rm --attach --restart=Never --image=edsiper/apache_logs |
| Command     | $ kubectl annotate pods apache-logs-annotated-invalid logging.parser='404' |

#### JSON Stringify

|             |                                                              |
| ----------- | ------------------------------------------------------------ |
| Description | Application writes a JSON message, it become stringified by Docker. |
| Log File    | json-logs_default_json-logs-c053db7370be9c33d64677f9759863d850ebe35104069bec241cd1bb4674bd19.log |
| Command     | $ kubectl run json-logs --rm --attach --restart=Never --image=edsiper/json_logs |

#### JSON Invalid

|             |                                                              |
| ----------- | ------------------------------------------------------------ |
| Description | Application writes an invalid JSON message.                  |
| Log File    | json-logs-invalid_default_json-logs-invalid-054e8bb83c2cc890bae4a184e7a2f96f18dfb121f83e4c5c5541dd452fa4e58e.log |
| Command     | $ kubectl run json-logs-invalid --rm --attach --restart=Never --image=edsiper/json_logs_invalid |