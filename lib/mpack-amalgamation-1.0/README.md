## Introduction

MPack is a C implementation of an encoder and decoder for the [MessagePack](http://msgpack.org/) serialization format. It is:

 * Simple and easy to use
 * Secure against untrusted data
 * Lightweight, suitable for embedded
 * [Extensively documented](http://ludocode.github.io/mpack/)
 * [Extremely fast](https://github.com/ludocode/schemaless-benchmarks#speed---desktop-pc)

The core of MPack contains a buffered reader and writer, and a tree-style parser that decodes into a tree of dynamically typed nodes. Helper functions can be enabled to read values of expected type, to work with files, to allocate strings automatically, to check UTF-8 encoding, and more.

The MPack code is small enough to be embedded directly into your codebase. Simply download the [amalgamation package](https://github.com/ludocode/mpack/releases) and add `mpack.h` and `mpack.c` to your project.

The MPack featureset can be customized at compile-time to set which features, components and debug checks are compiled, and what dependencies are available.

## Build Status

MPack is beta software under development.

[travis-home]: https://travis-ci.org/
[travis-mpack]: https://travis-ci.org/ludocode/mpack/branches
[appveyor-home]: https://ci.appveyor.com/
[appveyor-mpack-master]: https://ci.appveyor.com/project/ludocode/mpack/branch/master
[appveyor-mpack-develop]: https://ci.appveyor.com/project/ludocode/mpack/branch/develop
[coveralls-home]: https://coveralls.io/
[coveralls-mpack-master]: https://coveralls.io/github/ludocode/mpack?branch=master
[coveralls-mpack-develop]: https://coveralls.io/github/ludocode/mpack?branch=develop

<!-- we use some deprecated HTML attributes here to get these stupid badges to line up properly -->
| [Travis-CI][travis-home] | [AppVeyor][appveyor-home] | [Coveralls.io][coveralls-home] |
| :-------: | :----------: | :----------: |
| [<img src="https://travis-ci.org/ludocode/mpack.svg?branch=develop" alt="Build Status" align="top" vspace="4">][travis-mpack] | [<img src="https://ci.appveyor.com/api/projects/status/tux06aefpqq83k30/branch/develop?svg=true" alt="Build Status" align="top" vspace="4">][appveyor-mpack-develop] | [<img src="https://coveralls.io/repos/ludocode/mpack/badge.svg?branch=develop&service=github" alt="Build Status" align="top" vspace="4">][coveralls-mpack-develop] |

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

The above example decodes into allocated pages of nodes. A fixed node pool can be provided to the parser instead in memory-constrained environments. For maximum performance and minimal memory usage, the [Expect API](docs/expect.md) can be used to parse data of a predefined schema.

## The Write API

The Write API encodes structured data to MessagePack.

```C
// encode to memory buffer
char* data;
size_t size;
mpack_writer_t writer;
mpack_writer_init_growable(&writer, &data, &size);

// write the example on the msgpack homepage
mpack_start_map(&writer, 2);
mpack_write_cstr(&writer, "compact");
mpack_write_bool(&writer, true);
mpack_write_cstr(&writer, "schema");
mpack_write_uint(&writer, 0);
mpack_finish_map(&writer);

// finish writing
if (mpack_writer_destroy(&writer) != mpack_ok) {
    fprintf(stderr, "An error occurred encoding the data!\n");
    return;
}

// use the data
do_something_with_data(data, size);
free(data);
```

In the above example, we encode to a growable memory buffer. The writer can instead write to a pre-allocated or stack-allocated buffer, avoiding the need for memory allocation. The writer can also be provided with a flush function (such as a file or socket write function) to call when the buffer is full or when writing is done.

If any error occurs, the writer is placed in an error state. The writer will flag an error if too much data is written, if the wrong number of elements are written, if the data could not be flushed, etc. No additional error handling is needed in the above code; any subsequent writes are ignored when the writer is in an error state, so you don't need to check every write for errors.

Note in particular that in debug mode, the `mpack_finish_map()` call above ensures that two key/value pairs were actually written as claimed, something that other MessagePack C/C++ libraries may not do.

## Comparison With Other Parsers

MPack is rich in features while maintaining very high performance and a small code footprint. Here's a short feature table comparing it to other C parsers:

[mpack]: https://github.com/ludocode/mpack
[msgpack-c]: https://github.com/msgpack/msgpack-c
[cmp]: https://github.com/camgunz/cmp

|    | [MPack][mpack]<br>(v0.8) | [msgpack-c][msgpack-c]<br>(v1.3.0) | [CMP][cmp]<br>(v14) |
|:------------------------------------|:---:|:---:|:---:|
| No libc requirement                 | ✓   |     | ✓   |
| Growable memory writer              | ✓   | ✓   |     |
| File I/O helpers                    | ✓   | ✓   |     |
| Tree parser                         | ✓   | ✓   |     |
| Propagating errors                  | ✓   |     | ✓   |
| Compound size tracking              | ✓   |     |     |
| Incremental parser                  | ✓   |     | ✓   |
| Incremental range/match helpers     | ✓   |     |     |
| Tree stream parser                  |     | ✓   |     |
| UTF-8 verification                  | ✓   |     |     |

A larger feature comparison table is available [here](docs/features.md) which includes descriptions of the various entries in the table.

[This benchmarking suite](https://github.com/ludocode/schemaless-benchmarks) compares the performance of MPack to other implementations of schemaless serialization formats. MPack outperforms all JSON and MessagePack libraries, and in some tests MPack is several times faster than [RapidJSON](https://github.com/miloyip/rapidjson) for equivalent data.

## Why Not Just Use JSON?

Conceptually, MessagePack stores data similarly to JSON: they are both composed of simple values such as numbers and strings, stored hierarchically in maps and arrays. So why not just use JSON instead? The main reason is that JSON is designed to be human-readable, so it is not as efficient as a binary serialization format:

- Compound types such as strings, maps and arrays are delimited, so appropriate storage cannot be allocated upfront. The whole object must be parsed to determine its size.

- Strings are not stored in their native encoding. Special characters such as quotes and backslashes must be escaped when written and converted back when read.

- Numbers are particularly inefficient (especially when parsing back floats), making JSON inappropriate as a base format for structured data that contains lots of numbers.

- Binary data is not supported by JSON at all. Small binary blobs such as icons and thumbnails need to be Base64 encoded or passed out-of-band.

The above issues greatly increase the complexity of the decoder. Full-featured JSON decoders are quite large, and minimal decoders tend to leave out such features as string unescaping and float parsing, instead leaving these up to the user or platform. This can lead to hard-to-find platform-specific and locale-specific bugs, as well as a greater potential for security vulnerabilites. This also significantly decreases performance, making JSON unattractive for use in applications such as mobile games.

While the space inefficiencies of JSON can be partially mitigated through minification and compression, the performance inefficiencies cannot. More importantly, if you are minifying and compressing the data, then why use a human-readable format in the first place?

## Running the Unit Tests

The MPack build process does not build MPack into a library; it is used to build and run the unit tests. You do not need to build MPack or the unit testing suite to use MPack.

On Linux, the test suite uses SCons and requires Valgrind, and can be run in the repository or in the amalgamation package. Run `scons` to build and run the test suite in full debug configuration.

On Windows, there is a Visual Studio solution, and on OS X, there is an Xcode project for building and running the test suite.

You can also build and run the test suite in all supported configurations, which is what the continuous integration server will build and run. If you are on 64-bit, you will need support for cross-compiling to 32-bit, and running 32-bit binaries with 64-bit Valgrind. On Ubuntu, you'll need `libc6-dbg:i386`. On Arch you'll need `gcc-multilib` or `lib32-clang`, and `valgrind-multilib`. Use `scons all=1 -j16` (or some appropriate thread count) to build and run all tests.
