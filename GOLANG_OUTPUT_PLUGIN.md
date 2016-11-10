# Fluent Bit + Golang output plugins

The current development version of Fluent Bit, integrates support to load _shared_ plugins built in Golang. The interface still needs some adjustment but is functional, the expectation is to release Fluent Bit v0.10 with fully support for Go.

## Getting Started

Compile Fluent Bit with Golang support, e.g:

```
$ cd build/
$ cmake -DFLB_DEBUG=On -DFLB_PROXY_GO=On ../
$ make
```

once compiled, we can see a new option in the binary _-e_ which stands for _external plugin_, e.g:

```
$ bin/fluent-bit -h
Usage: fluent-bit [OPTION]

Available Options
  -c  --config=FILE	specify an optional configuration file
  -d, --daemon		run Fluent Bit in background mode
  -f, --flush=SECONDS	flush timeout in seconds (default: 5)
  -i, --input=INPUT	set an input
  -m, --match=MATCH	set plugin match, same as '-p match=abc'
  -o, --output=OUTPUT	set an output
  -p, --prop="A=B"	set plugin configuration property
  -e, --plugin=FILE	load an external plugin (shared lib)
  ...
```

## Build a plugin in Go

To make easier to build plugins, we have published a _fluent-bit-go_ package:

http://github.com/fluent/fluent-bit-go

In the same repository we have published a plugin example called __out_gstdout__ that when runs, it just print the records to the standard output:

https://github.com/fluent/fluent-bit-go/tree/master/examples/out_gstdout

As minimum, a Go plugin looks like this:

```go
package main

import "github.com/fluent/fluent-bit-go/output"

//export FLBPluginInit
func FLBPluginInit(ctx unsafe.Pointer) int {
	return output.FLBPluginRegister(ctx, "gstdout", "Stdout GO!")
}

//export FLBPluginFlush
func FLBPluginFlush(data unsafe.Pointer, length C.int, tag *C.char) int {
    // do something with the data
    return 0
}

//export FLBPluginExit
func FLBPluginExit() int {
	return 0
}

func main() {
}
```

the code above is a template to write an output plugin, it's really important to keep the package name as  _main_ and add an explicit _main()_ function. This is a requirement as the code will be build as a shared library.

To build the code above, use the following line:

```go
$ go build -buildmode=c-shared -o out_gstdout.so out_gstdout.go
```

after a few seconds a shared library called _out\_gstdout.so_ will be available. It's really important to double check the final .so file is what do we expect. Doing a _ldd_ over the library we should see something similar to this:

```
$ ldd out_gstdout.so
	linux-vdso.so.1 =>  (0x00007fff561dd000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fc4aeef0000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fc4aeb27000)
	/lib64/ld-linux-x86-64.so.2 (0x000055751a4fd000)
```

## Run Fluent Bit + the new plugin

```
$ bin/fluent-bit -e /path/to/out_gstdout.so -i cpu -o gstdout
```

for more details or assistance write to eduardo@treasure-data.com
