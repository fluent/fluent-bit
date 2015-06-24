# Msgpack for C/C++

It's like JSON but small and fast.


## Overview

MessagePack is an efficient binary serialization format. It lets you exchange data among multiple languages like JSON. But it's faster and smaller. Small integers are encoded into a single byte, and typical short strings require only one extra byte in addition to the strings themselves.


## License

Msgpack is Copyright (C) 2008-2014 FURUHASHI Sadayuki and licensed under the Apache License, Version 2.0 (the "License"). For details see the `COPYING` file in this directory.


## Contributing

The source for msgpack-c is held at [msgpack-c](https://github.com/msgpack/msgpack-c) github.com site.

To report an issue, use the [msgpack-c issue tracker](https://github.com/msgpack/msgpack-c/issues) at github.com.

## Version
0.5.9 [![Build Status](https://travis-ci.org/msgpack/msgpack-c.svg?branch=master)](https://travis-ci.org/msgpack/msgpack-c)

## Using Msgpack

### Header only library for C++
When you use msgpack on C++03 and C++11, you just add msgpack-c/include to your include path. You don't need to link any msgpack libraries.

e.g.)

    g++ -I msgpack-c/include your_source_file.cpp

If you want to use C version of msgpack, you need to build it. You can also install C and C++ version of msgpack.

### Building and Installing

#### Install from git repository

##### Using autotools
You will need gcc (4.1.0 or higher), autotools.

For C:
C++03 and C:

    $ git clone https://github.com/redboltz/msgpack-c/tree/cxx_separate
    $ cd msgpack-c
    $ ./bootstrap
    $ ./configure
    $ make
    $ sudo make install

For C++11:

    $ git clone https://github.com/msgpack/msgpack-c.git
    $ cd msgpack-c
    $ ./bootstrap
    $ ./configure CXXFLAGS="-std=c++11"
    $ make
    $ sudo make install

You need the compiler that fully supports C++11.

##### Using cmake

###### CUI

You will need gcc (4.1.0 or higher), cmake.

    $ git clone https://github.com/msgpack/msgpack-c.git
    $ cd msgpack-c
    $ cmake .
    $ make
    $ sudo make install

If you want to setup C++11 version of msgpack, execute the following command:

    $ git clone https://github.com/msgpack/msgpack-c.git
    $ cd msgpack-c
    $ cmake -DMSGPACK_CXX11=ON .
    $ sudo make install

You need the compiler that fully supports C++11.

##### GUI on Windows

Clone msgpack-c git repository.

    $ git clone https://github.com/msgpack/msgpack-c.git

or using GUI git client.

e.g.) tortoise git https://code.google.com/p/tortoisegit/

1. Launch cmake GUI client. http://www.cmake.org/cmake/resources/software.html

1. Set 'Where is the source code:' text box and 'Where to build the binaries:' text box.

1. Click 'Configure' button.

1. Choose your Visual Studio version.

1. Click 'Generate' button.

1. Open the created msgpack.sln on Visual Studio.

1. Build all.

### Code Example

    #include <msgpack.hpp>
    #include <vector>
    #include <string>
    #include <iostream>

    int main() {
        // This is target object.
        std::vector<std::string> target;
        target.push_back("Hello,");
        target.push_back("World!");

        // Serialize it.
        msgpack::sbuffer sbuf;  // simple buffer
        msgpack::pack(&sbuf, target);

        // Deserialize the serialized data.
        msgpack::unpacked msg;    // includes memory pool and deserialized object
        msgpack::unpack(msg, sbuf.data(), sbuf.size());
        msgpack::object obj = msg.get();

        // Print the deserialized object to stdout.
        std::cout << obj << std::endl;    // ["Hello," "World!"]

        // Convert the deserialized object to staticaly typed object.
        std::vector<std::string> result;
        obj.convert(&result);

        // If the type is mismatched, it throws msgpack::type_error.
        obj.as<int>();  // type is mismatched, msgpack::type_error is thrown
    }

### Documents

You can get addtional information on the wiki:

https://github.com/msgpack/msgpack-c/wiki/cpp_overview

