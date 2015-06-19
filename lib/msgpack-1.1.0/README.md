`msgpack` for C/C++
===================

Version 1.1.0 [![Build Status](https://travis-ci.org/msgpack/msgpack-c.svg?branch=master)](https://travis-ci.org/msgpack/msgpack-c)

It's like JSON but small and fast.

Overview
--------

[MessagePack](http://msgpack.org/) is an efficient binary serialization
format, which lets you exchange data among multiple languages like JSON,
except that it's faster and smaller. Small integers are encoded into a
single byte while typical short strings require only one extra byte in
addition to the strings themselves.

Example
-------

In C:

```c
#include <msgpack.h>
#include <stdio.h>

int main(void)
{
    /* msgpack::sbuffer is a simple buffer implementation. */
    msgpack_sbuffer sbuf;
    msgpack_sbuffer_init(&sbuf);

    /* serialize values into the buffer using msgpack_sbuffer_write callback function. */
    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&pk, 3);
    msgpack_pack_int(&pk, 1);
    msgpack_pack_true(&pk);
    msgpack_pack_str(&pk, 7);
    msgpack_pack_str_body(&pk, "example", 7);

    /* deserialize the buffer into msgpack_object instance. */
    /* deserialized object is valid during the msgpack_zone instance alive. */
    msgpack_zone mempool;
    msgpack_zone_init(&mempool, 2048);

    msgpack_object deserialized;
    msgpack_unpack(sbuf.data, sbuf.size, NULL, &mempool, &deserialized);

    /* print the deserialized object. */
    msgpack_object_print(stdout, deserialized);
    puts("");

    msgpack_zone_destroy(&mempool);
    msgpack_sbuffer_destroy(&sbuf);

    return 0;
}
```

See [`QUICKSTART-C.md`](./QUICKSTART-C.md) for more details.

In C++:

```c++
#include <msgpack.hpp>
#include <string>
#include <iostream>
#include <sstream>

int main(void)
{
    msgpack::type::tuple<int, bool, std::string> src(1, true, "example");

    // serialize the object into the buffer.
    // any classes that implements write(const char*,size_t) can be a buffer.
    std::stringstream buffer;
    msgpack::pack(buffer, src);

    // send the buffer ...
    buffer.seekg(0);

    // deserialize the buffer into msgpack::object instance.
    std::string str(buffer.str());

    msgpack::unpacked result;

    msgpack::unpack(result, str.data(), str.size());

    // deserialized object is valid during the msgpack::unpacked instance alive.
    msgpack::object deserialized = result.get();

    // msgpack::object supports ostream.
    std::cout << deserialized << std::endl;

    // convert msgpack::object instance into the original type.
    // if the type is mismatched, it throws msgpack::type_error exception.
    msgpack::type::tuple<int, bool, std::string> dst;
    deserialized.convert(&dst);

    return 0;
}
```

See [`QUICKSTART-CPP.md`](./QUICKSTART-CPP.md) for more details.

Usage
-----

### C++ Header Only Library

When you use msgpack on C++03 and C++11, you can just add
msgpack-c/include to your include path:

    g++ -I msgpack-c/include your_source_file.cpp

If you want to use C version of msgpack, you need to build it. You can
also install the C and C++ versions of msgpack.

### Building and Installing

#### Install from git repository

##### Using autotools

You will need:

 - `gcc >= 4.1.0` or `clang >= 3.3.0`
 - `autoconf >= 2.60`
 - `automake >= 1.10`
 - `libtool >= 2.2.4`

The build steps below are for C and C++03. If compiling for C++11,
add `-std=c++11` to the environmental variable `CXXFLAGS` with
`export CXXFLAGS="$CXXFLAGS -std=c++11"` prior to following the
directions below.

```bash
$ git clone https://github.com/msgpack/msgpack-c
$ cd msgpack-c
$ ./bootstrap
$ ./configure
$ make
```

You can install the resulting library like this:

```bash
$ sudo make install
```
##### Using cmake

###### Using the Terminal (CLI)

You will need:

 - `gcc >= 4.1.0`
 - `cmake >= 2.8.0`

C and C++03:

    $ git clone https://github.com/msgpack/msgpack-c.git
    $ cd msgpack-c
    $ cmake .
    $ make
    $ sudo make install

If you want to setup C++11 version of msgpack instead,
execute the following commands:

    $ git clone https://github.com/msgpack/msgpack-c.git
    $ cd msgpack-c
    $ cmake -DMSGPACK_CXX11=ON .
    $ sudo make install

##### GUI on Windows

Clone msgpack-c git repository.

    $ git clone https://github.com/msgpack/msgpack-c.git

or using GUI git client.

e.g.) tortoise git https://code.google.com/p/tortoisegit/

1. Launch [cmake GUI client](http://www.cmake.org/cmake/resources/software.html).

2. Set 'Where is the source code:' text box and 'Where to build
the binaries:' text box.

3. Click 'Configure' button.

4. Choose your Visual Studio version.

5. Click 'Generate' button.

6. Open the created msgpack.sln on Visual Studio.

7. Build all.

### Documentation

You can get addtional information on the
[wiki](https://github.com/msgpack/msgpack-c/wiki).

Contributing
------------

`msgpack-c` is developed on GitHub at [msgpack/msgpack-c](https://github.com/msgpack/msgpack-c).
To report an issue or send a pull request, use the
[issue tracker](https://github.com/msgpack/msgpack-c/issues).

Here's the list of [great contributors](https://github.com/msgpack/msgpack-c/graphs/contributors).

License
-------

`msgpack-c` is licensed under the Apache License Version 2.0. See
the [`LICENSE`](./LICENSE) file for details.
