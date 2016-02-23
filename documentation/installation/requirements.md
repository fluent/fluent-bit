# Requirements

[Fluent Bit](http://fluentbit.io) uses very low CPU and Memory consumption, it's compatible with any x86 and x86_64 based platforms. In order to build it you need the following components in your system:

- Compiler: GCC or clang
- CMake

There are not other dependencies besides _libc_ and _pthreads_ in the most basic mode. For certain features that depends on thrid party components, those are included in the main source code repository.
