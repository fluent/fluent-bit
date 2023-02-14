# CFL

CFL is a tiny library that provides interfaces for data structures, originally created to satisfy the needs of Fluent Bit and other libraries used internally like CMetrics and CTraces projects.

note: The name doesn't mean anything specific, you can call it `c:\ floppy` if you want.

## Interfaces

- cfl_sds: string manipulation
- cfl_list: linked list 
- cfl_kv: key value pairs by using a linked list (cfl_list)
- cfl_array: array of elements
- cfl_variant: interface to manage contexts with vairant types
- cfl_time: time utilities
- cfl_hash: 64bit hashing functions

## License

This program is under the terms of the [Apache License v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Authors

Copyright is assigned to the `CFL Authors`, you can see a list of contributors [here](https://github.com/fluent/cfl/graphs/contributors).
