# Lightweight ring buffer manager

Library provides generic FIFO ring buffer implementation.

<h3>Read first: <a href="http://docs.majerle.eu/projects/lwrb/">Documentation</a></h3>

## Features

* Written in ANSI C99, compatible with ``size_t`` for size data types
* Platform independent, no architecture specific code
* FIFO (First In First Out) buffer implementation
* No dynamic memory allocation, data is static array
* Uses optimized memory copy instead of loops to read/write data from/to memory
* Thread safe when used as pipe with single write and single read entries
* Interrupt safe when used as pipe with single write and single read entries
* Suitable for DMA transfers from and to memory with zero-copy overhead between buffer and application memory
* Supports data peek, skip for read and advance for write
* Implements support for event notifications
* User friendly MIT license

## Contribute

Fresh contributions are always welcome. Simple instructions to proceed::

1. Fork Github repository
2. Respect [C style & coding rules](https://github.com/MaJerle/c-code-style) used by the library
3. Create a pull request to develop branch with new features or bug fixes

Alternatively you may:

1. Report a bug
2. Ask for a feature request