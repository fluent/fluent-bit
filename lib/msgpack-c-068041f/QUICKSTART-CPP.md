# Implementation Status

The serialization library is production-ready.

Currently, RPC implementation is in testing phase. Requires newer kernel, not running on RHEL5/CentOS5.

# Install

Same as QuickStart for C Language.

# Serialization QuickStart for C+\+

## First program

Include `msgpack.hpp` header and link `msgpack` library to use MessagePack on your program.

```cpp
#include <msgpack.hpp>
#include <vector>
#include <string>
#include <iostream>

int main(void) {
        // serializes this object.
        std::vector<std::string> vec;
        vec.push_back("Hello");
        vec.push_back("MessagePack");

        // serialize it into simple buffer.
        msgpack::sbuffer sbuf;
        msgpack::pack(sbuf, vec);

        // deserialize it.
        msgpack::object_handle oh =
            msgpack::unpack(sbuf.data(), sbuf.size());

        // print the deserialized object.
        msgpack::object obj = oh.get();
        std::cout << obj << std::endl;  //=> ["Hello", "MessagePack"]

        // convert it into statically typed object.
        std::vector<std::string> rvec;
        obj.convert(rvec);
}
```

Compile it as follows:

```
$ g++ -Ipath_to_msgpack/include hello.cc -o hello
$ ./hello
["Hello", "MessagePack"]
```

## Streaming feature

```cpp
#include <msgpack.hpp>
#include <iostream>
#include <string>

int main(void) {
        // serializes multiple objects using msgpack::packer.
        msgpack::sbuffer buffer;

        msgpack::packer<msgpack::sbuffer> pk(&buffer);
        pk.pack(std::string("Log message ... 1"));
        pk.pack(std::string("Log message ... 2"));
        pk.pack(std::string("Log message ... 3"));

        // deserializes these objects using msgpack::unpacker.
        msgpack::unpacker pac;

        // feeds the buffer.
        pac.reserve_buffer(buffer.size());
        memcpy(pac.buffer(), buffer.data(), buffer.size());
        pac.buffer_consumed(buffer.size());

        // now starts streaming deserialization.
        msgpack::object_handle oh;
        while(pac.next(&oh)) {
            std::cout << oh.get() << std::endl;
        }

        // results:
        // $ g++ -Ipath_to_msgpack/include stream.cc -o stream
        // $ ./stream
        // "Log message ... 1"
        // "Log message ... 2"
        // "Log message ... 3"
}
```

### Streaming into an array or map

```cpp
#include <msgpack.hpp>
#include <iostream>
#include <string>

int main(void) {
        // serializes multiple objects into one message containing an array using msgpack::packer.
        msgpack::sbuffer buffer;

        msgpack::packer<msgpack::sbuffer> pk(&buffer);
        pk.pack_array(3);
        pk.pack(std::string("Log message ... 1"));
        pk.pack(std::string("Log message ... 2"));
        pk.pack(std::string("Log message ... 3"));

        // serializes multiple objects into one message containing a map using msgpack::packer.
        msgpack::sbuffer buffer2;

        msgpack::packer<msgpack::sbuffer> pk2(&buffer2);
        pk2.pack_map(2);
        pk2.pack(std::string("x"));
        pk2.pack(3);
        pk2.pack(std::string("y"));
        pk2.pack(3.4321);

}
```


## User-defined classes

You can use serialize/deserializes user-defined classes using `MSGPACK_DEFINE` macro.

```cpp
#include <msgpack.hpp>
#include <vector>
#include <string>

class myclass {
private:
    std::string m_str;
    std::vector<int> m_vec;
public:
    MSGPACK_DEFINE(m_str, m_vec);
};

int main(void) {
        std::vector<myclass> vec;
        // add some elements into vec...

        // you can serialize myclass directly
        msgpack::sbuffer sbuf;
        msgpack::pack(sbuf, vec);

        msgpack::object_handle oh =
            msgpack::unpack(sbuf.data(), sbuf.size());

        msgpack::object obj = oh.get();

        // you can convert object to myclass directly
        std::vector<myclass> rvec;
        obj.convert(rvec);
}
```
