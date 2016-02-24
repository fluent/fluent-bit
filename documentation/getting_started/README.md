# Getting Started

[Fluent Bit](http://fluentbit.io) is a straightforward tool and to get started with it we need to understand a few concepts involved.

The nature of Fluent Bit is to gather data from an __input__ interface, do buffering and then flush the records through an __output__. Every input and output interfaces are implemented through a __plugin__.

When a __plugin__ is loaded, multiple instances of it can be started and in order to instruct the core how to route the records between input and output instances, a __tag__ and a __match__ are required:

- Input plugin instances are _tagged_
- Output plugin instances defines a _match_

When a record is buffered it contains a __tag__, then the router lookup the output instances that have a __match__ for it, then it deliver the data as required.

## Input

[Fluent Bit](http://fluentbit.io) provides different input plugins to gather information from, some of them just collect operating system metrics while others interact with radio devices or listen from specific protocols data.

When an input plugin is loaded, an internal _instance_ of it is created,

# FIXME...
