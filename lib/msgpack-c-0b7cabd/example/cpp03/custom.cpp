// MessagePack for C++ example
//
// Copyright (C) 2008-2015 FURUHASHI Sadayuki and KONDO Takatoshi
//
//    Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//    http://www.boost.org/LICENSE_1_0.txt)
//

#include <msgpack.hpp>
#include <sstream>
#include <string>
#include <iostream>

class old_class {
public:
    old_class() : value("default") { }

    std::string value;

    MSGPACK_DEFINE(value);
};

class new_class {
public:
    new_class() : value("default"), flag(-1) { }

    std::string value;
    int flag;

    MSGPACK_DEFINE(value, flag);
};

int main(void)
{
    {
        old_class oc;
        new_class nc;

        std::stringstream sbuf;
        msgpack::pack(sbuf, oc);

        msgpack::object_handle oh =
            msgpack::unpack(sbuf.str().data(), sbuf.str().size());
        msgpack::object obj = oh.get();

        obj.convert(nc);

        std::cout << obj << " value=" << nc.value << " flag=" << nc.flag << std::endl;
    }

    {
        new_class nc;
        old_class oc;

        std::stringstream sbuf;
        msgpack::pack(sbuf, nc);

        msgpack::object_handle oh =
            msgpack::unpack(sbuf.str().data(), sbuf.str().size());
        msgpack::object obj = oh.get();

        obj.convert(oc);

        std::cout << obj << " value=" << oc.value << std::endl;
    }
}
