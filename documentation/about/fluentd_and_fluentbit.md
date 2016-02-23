# Fluentd and Fluent Bit

Data collection matters and nowadays the scenarios from where the information can _come from_ are very variable. For hence to be more flexible on certain markets needs, we may need different options. On this page we will describe the relationship between the [Fluentd](http://fluentd.org) and [Fluent Bit](http://fluentbit.io) open source projects.

[Fluentd](http://fluentd.org) and [Fluent Bit](http://fluentbit.io) projects are both created and sponsored by [Treasure Data](http://treasuredata.com) and they aim to solve the data collection needs but on different scenarios and environments, the following table describe a comparisson on different areas of the projects:

|                       | Fluentd               | Fluent Bit            |
|-----------------------|-----------------------|-----------------------|
| Scope                 | Servers               | Embedded & IoT devices|
| Language              | C & Ruby              | C                     |
| Memory                | ~20MB                 | ~150KB                |
| Performance           | High Performance      | High Performance      |
| Dependencies          | Built as a Ruby Gem, it requires a certain number of gems. | Zero dependencies, unless some special plugin requires them. |
| Plugins               | More than 300 plugins available | Around 15 plugins available|
| License               | [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0) | [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0)|

As described in the table, if the target environment is a server with common capacity, [Fluentd](http://fluentd.org) is a great option due to it flexibility and availability of plugins (more than 300 extensions!) but if the _data collection_ will happen in an Embedded environment or an IoT device where the system capacity is restricted, [Fluent Bit](http://fluentbit.io) is the solution to use.

Both tools are not mutual exclusive, [Fluent Bit](http://fluentbit.io) provides and _output_ plugin to flush the information to a [Fluentd](http://fluentd.org) instance, so they can work together in your architecture or as independent services.
