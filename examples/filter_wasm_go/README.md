# Fluent Bit / filter_wasm_go

This source source tree provides an example of WASM filter program with WASI mode.

## Prerequisites

Tested on

* TinyGo
  * [tinygo](https://tinygo.org/) tinygo version 0.32.0 linux/amd64 (using go version go1.22.5 and LLVM version 18.1.2)

For Ubuntu, it's easy to install with:

```console
$ wget https://github.com/tinygo-org/tinygo/releases/download/v0.32.0/tinygo_0.32.0_amd64.deb
$ sudo dpkg -i tinygo_0.32.0_amd64.deb
```

## How to build

Execute _tinygo build_ as follows:

```console
$ tinygo build -target=wasi -o filter.wasm filter.go
```

Finally, under the same directory, `*.wasm` file will be created:

```console
$ ls *.wasm
filter.wasm
```

## How to confirm WASM filter integration

Create fluent-bit configuration file as follows:

```ini
[SERVICE]
    Flush        1
    Daemon       Off
    Log_Level    info
    HTTP_Server  Off
    HTTP_Listen  0.0.0.0
    HTTP_Port    2020

[INPUT]
    Name dummy
    Tag dummy.local

[FILTER]
    Name wasm
    match dummy.*
    Event_Format json
    WASM_Path /path/to/filter.wasm
    Function_Name go_filter
    accessible_paths .,/path/to/fluent-bit

[OUTPUT]
    Name  stdout
    Match *
```

## ABI v2: value-length return

The runnable [v2 example](v2/filter.go) uses the same six input arguments as
v1, but returns `uint64` instead of a string pointer:

```go
//export filter_v2
func filter_v2(tag *byte, tagLength uint32, seconds uint32, nanoseconds uint32,
    record *byte, recordLength uint32) uint64 {
    return uint64(recordLength)<<32 | uint64(uint32(uintptr(unsafe.Pointer(record))))
}
```

The low 32 bits contain the value (WASM memory offset); the high 32 bits contain
its byte length. Return zero to drop a record. Fluent Bit copies the returned
bytes, preserving embedded NUL bytes, before releasing input storage.

Build from this directory with TinyGo and its required `wasm-opt` (Binaryen):

```sh
tinygo build -target=wasi -scheduler=none -o filter_v2.wasm v2/filter.go
```

TinyGo 0.35 requires Go 1.19–1.23. To use Homebrew Go 1.23:

```sh
GOROOT="$(brew --prefix go@1.23)/libexec" \
PATH="$(brew --prefix go@1.23)/bin:$PATH" \
tinygo build -target=wasi -scheduler=none -o filter_v2.wasm v2/filter.go
```

```ini
[FILTER]
    Name          wasm
    Match         *
    WASM_Path     filter_v2.wasm
    Function_Name filter_v2
    ABI_Version   2
    Event_Format  json
```

The example also exports `filter_binary_v2`, which returns the MessagePack map
`{"n": 0, "s": "a\u0000b"}` from module-owned static storage. Select it with
`Function_Name filter_binary_v2` and `Event_Format msgpack`. The
`filter_drop_v2` export returns zero to drop records.

If a function constructs a Go output slice, keep it reachable (for example in
a package-level variable) until the next call; converting a pointer to
`uint64` alone does not keep its backing storage alive. The supplied examples
borrow the input or use a package-level array and require no allocation.

Runtime tests compile this source into
`tests/runtime/data/wasm/filter_go_v2.wasm` with
`make -C tests/runtime/wasm/go v2` from the repository root.
See [the full value-length specification](../../plugins/filter_wasm/README.md).
