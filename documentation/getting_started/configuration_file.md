# Configuration File

There are some cases where using the command line to start Fluent Bit is not ideal for some escenarios, when running it as a service a configuration file it's times better.

Fluent Bit allows to use one configuration file which works at a global scope and uses the [schema](configuration_schema.md) defined previously.

The configuration file support three types of sections:

- Service
- Input
- Output

## Service

The _Service_ section defines global properties of the service, the keys available as of this version are described in the following table:

| Key             | Description                    | Default Value |
|-----------------|--------------------------------|---------------|
| Flush           | Set the flush time in seconds. Everytime it timeouts, the engine will flush the records to the output plugin.| 5 |
| Daemon          | Boolean value to set if Fluent Bit should run as a Daemon (background) or not. Allowed values are: yes, no, on and off. | Off |
| Log_Level       | Set the logging verbosity level. Allowed values are: error, info, debug and trace. Values are accumulative, e.g: if 'debug' is set, it will include error, info and debug. Note that _trace_ mode is only available if Fluent Bit was built with the _WITH\_TRACE_ option enabled.| info |
| HTTP_Monitor    | Enable web service monitoring interface. | Off |
| HTTP_Port       | TCP port for web service monitoring interface. | 2020 |

### Example

The following is an example of a _SERVICE_ section:

```Python
[SERVICE]
    Flush           5
    Daemon          off
    Log_Level       debug
    HTTP_Monitoring On
    HTTP_Port       2020
```

## Input

An _INPUT_ section defines a source (related to an input plugin), here we will describe the base configuration for each _INPUT_ section. Note that each input plugin may add it own configuration keys:

| Key    | Description               |
|--------|---------------------------|
| Name   | Name of the input plugin. |
| Tag    | Tag name associated to all records comming from this plugin. |


The _Name_ is mandatory and it let Fluent Bit know which input plugin should be loaded. The _Tag_ is mandatory for all plugins except for the _input forward_ plugin (as it provides dynamic tags).

### Example

The following is an example of an _INPUT_ section:

```Python
[INPUT]
    Name cpu
    Tag  my_cpu
```

## Output

The _OUTPUT_ section specify a destination that certain records should follow after a Tag match. The configuration support the following keys:

| Key    | Description                |
|--------|----------------------------|
| Name   | Name of the output plugin. |
| Match  | It set a pattern to match certain records Tag. It's case sensitive and support the start (*) character as a wildcard. |

### Example

The following is an example of an _INPUT_ section:

```Python
[OUTPUT]
    Name  stdout
    Match my*cpu
```

## Example: collecting CPU metrics

The following configuration file example demonstrate how to collect CPU metrics and flush the results every five seconds to the standard output:

```Python
[SERVICE]
    Flush     5
    Daemon    off
    Log_Level debug

[INPUT]
    Name  cpu
    Tag   my_cpu

[OUTPUT]
    Name  stdout
    Match my*cpu
```
