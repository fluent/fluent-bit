## Introduction

MPack is a C implementation of an encoder and decoder for the [MessagePack](http://msgpack.org/) serialization format. It is:

 * Simple and easy to use
 * Secure against untrusted data
 * Lightweight, suitable for embedded
 * [Extensively documented](http://ludocode.github.io/mpack/)
 * [Extremely fast](https://github.com/ludocode/schemaless-benchmarks#speed---desktop-pc)

The core of MPack contains a buffered reader and writer, and a tree-style parser that decodes into a tree of dynamically typed nodes. Helper functions can be enabled to read values of expected type, to work with files, to grow buffers or allocate strings automatically, to check UTF-8 encoding, and more.

The MPack code is small enough to be embedded directly into your codebase. Simply download the [amalgamation package](https://github.com/ludocode/mpack/releases) and add `mpack.h` and `mpack.c` to your project.

MPack supports all modern compilers, all desktop and smartphone OSes, WebAssembly, [inside the Linux kernel](https://github.com/ludocode/mpack-linux-kernel), and even 8-bit microcontrollers such as Arduino. The MPack featureset can be customized at compile-time to set which features, components and debug checks are compiled, and what dependencies are available.

## Build Status

[![Unit Tests](https://github.com/ludocode/mpack/workflows/Unit%20Tests/badge.svg)](https://github.com/ludocode/mpack/actions?query=workflow%3A%22Unit+Tests%22)
[![Coverage](https://coveralls.io/repos/ludocode/mpack/badge.svg?branch=develop&service=github)](https://coveralls.io/github/ludocode/mpack?branch=develop)

## The Node API

The Node API parses a chunk of MessagePack data into an immutable tree of dynamically-typed nodes. A series of helper functions can be used to extract data of specific types from each node.

```C
// parse a file into a node tree
mpack_tree_t tree;
mpack_tree_init_filename(&tree, "homepage-example.mp", 0);
mpack_tree_parse(&tree);
mpack_node_t root = mpack_tree_root(&tree);

// extract the example data on the msgpack homepage
bool compact = mpack_node_bool(mpack_node_map_cstr(root, "compact"));
int schema = mpack_node_i32(mpack_node_map_cstr(root, "schema"));

// clean up and check for errors
if (mpack_tree_destroy(&tree) != mpack_ok) {
    fprintf(stderr, "An error occurred decoding the data!\n");
    return;
}
```

Note that no additional error handling is needed in the above code. If the file is missing or corrupt, if map keys are missing or if nodes are not in the expected types, special "nil" nodes and false/zero values are returned and the tree is placed in an error state. An error check is only needed before using the data.

The above example allocates nodes automatically. A fixed node pool can be provided to the parser instead in memory-constrained environments. For maximum performance and minimal memory usage, the [Expect API](docs/expect.md) can be used to parse data of a predefined schema.

## The Write API

The Write API encodes structured data to MessagePack.

```C
// encode to memory buffer
char* data;
size_t size;
mpack_writer_t writer;
mpack_writer_init_growable(&writer, &data, &size);

// write the example on the msgpack homepage
mpack_build_map(&writer);
mpack_write_cstr(&writer, "compact");
mpack_write_bool(&writer, true);
mpack_write_cstr(&writer, "schema");
mpack_write_uint(&writer, 0);
mpack_complete_map(&writer);

// finish writing
if (mpack_writer_destroy(&writer) != mpack_ok) {
    fprintf(stderr, "An error occurred encoding the data!\n");
    return;
}

// use the data
do_something_with_data(data, size);
free(data);
```

In the above example, we encode to a growable memory buffer. The writer can instead write to a pre-allocated or stack-allocated buffer (with up-front sizes for compound types), avoiding the need for memory allocation. The writer can also be provided with a flush function (such as a file or socket write function) to call when the buffer is full or when writing is done.

If any error occurs, the writer is placed in an error state. The writer will flag an error if too much data is written, if the wrong number of elements are written, if an allocation failure occurs, if the data could not be flushed, etc. No additional error handling is needed in the above code; any subsequent writes are ignored when the writer is in an error state, so you don't need to check every write for errors.

The above example uses `mpack_build_map()` to automatically determine the number of key-value pairs contained. If you know up-front the number of elements needed, you can pass it to `mpack_start_map()` instead. In that case the corresponding `mpack_finish_map()` will assert in debug mode that the expected number of elements were actually written, which is something that other MessagePack C/C++ libraries may not do.

## Comparison With Other Parsers

MPack is rich in features while maintaining very high performance and a small code footprint. Here's a short feature table comparing it to other C parsers:

[mpack]: https://github.com/ludocode/mpack
[msgpack-c]: https://github.com/msgpack/msgpack-c
[cmp]: https://github.com/camgunz/cmp
[cwpack]: https://github.com/clwi/CWPack

|    | [MPack][mpack]<br>(v1.1) | [msgpack-c][msgpack-c]<br>(v3.3.0) | [CMP][cmp]<br>(v19) | [CWPack][cwpack]<br>(v1.3.1) |
|:------------------------------------|:---:|:---:|:---:|:---:|
| No libc requirement                 | ✓   |     | ✓   | ✓   |
| Growable memory writer              | ✓   | ✓   |     | ✓\* |
| File I/O helpers                    | ✓   | ✓   |     | ✓\* |
| Stateful error handling             | ✓   |     | ✓   |     |
| Incremental parser                  | ✓   |     | ✓   | ✓   |
| Tree stream parser                  | ✓   | ✓   |     |     |
| Compound size tracking              | ✓   |     |     |     |
| Automatic compound size             | ✓   |     |     |     |

A larger feature comparison table is available [here](docs/features.md) which includes descriptions of the various entries in the table.

[This benchmarking suite](https://github.com/ludocode/schemaless-benchmarks) compares the performance of MPack to other implementations of schemaless serialization formats. MPack outperforms all JSON and MessagePack libraries (except [CWPack][cwpack]), and in some tests MPack is several times faster than [RapidJSON](https://github.com/miloyip/rapidjson) for equivalent data.

## Why Not Just Use JSON?

Conceptually, MessagePack stores data similarly to JSON: they are both composed of simple values such as numbers and strings, stored hierarchically in maps and arrays. So why not just use JSON instead? The main reason is that JSON is designed to be human-readable, so it is not as efficient as a binary serialization format:

- Compound types such as strings, maps and arrays are delimited, so appropriate storage cannot be allocated upfront. The whole object must be parsed to determine its size.

- Strings are not stored in their native encoding. Special characters such as quotes and backslashes must be escaped when written and converted back when read.

- Numbers are particularly inefficient (especially when parsing back floats), making JSON inappropriate as a base format for structured data that contains lots of numbers.

- Binary data is not supported by JSON at all. Small binary blobs such as icons and thumbnails need to be Base64 encoded or passed out-of-band.

The above issues greatly increase the complexity of the decoder. Full-featured JSON decoders are quite large, and minimal decoders tend to leave out such features as string unescaping and float parsing, instead leaving these up to the user or platform. This can lead to hard-to-find platform-specific and locale-specific bugs, as well as a greater potential for security vulnerabilites. This also significantly decreases performance, making JSON unattractive for use in applications such as mobile games.

While the space inefficiencies of JSON can be partially mitigated through minification and compression, the performance inefficiencies cannot. More importantly, if you are minifying and compressing the data, then why use a human-readable format in the first place?

## Testing MPack

The MPack build process does not build MPack into a library; it is used to build and run the unit tests. You do not need to build MPack or the unit testing suite to use MPack.

See [test/README.md](test/README.md) for information on how to test MPack.
