// MessagePack for C++ example
//
// Copyright (C) 2015 KONDO Takatoshi
//
//    Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//    http://www.boost.org/LICENSE_1_0.txt)
//

#include <sstream>
#include <iostream>
#include <cassert>

#include <msgpack.hpp>

enum my_enum {
    elem1,
    elem2,
    elem3
};

MSGPACK_ADD_ENUM(my_enum);

int main(void)
{
    {   // pack, unpack
        std::stringstream sbuf;
        msgpack::pack(sbuf, elem1);
        msgpack::pack(sbuf, elem2);
        my_enum e3 = elem3;
        msgpack::pack(sbuf, e3);

        msgpack::object_handle oh;
        std::size_t off = 0;

        msgpack::unpack(oh, sbuf.str().data(), sbuf.str().size(), off);
        std::cout << oh.get().as<my_enum>() << std::endl;
        assert(oh.get().as<my_enum>() == elem1);

        msgpack::unpack(oh, sbuf.str().data(), sbuf.str().size(), off);
        std::cout << oh.get().as<my_enum>() << std::endl;
        assert(oh.get().as<my_enum>() == elem2);

        msgpack::unpack(oh, sbuf.str().data(), sbuf.str().size(), off);
        std::cout << oh.get().as<my_enum>() << std::endl;
        assert(oh.get().as<my_enum>() == elem3);
    }
    {   // create object without zone
        msgpack::object obj(elem2);
        std::cout << obj.as<my_enum>() << std::endl;
        assert(obj.as<my_enum>() == elem2);
    }
    {   // create object with zone
        msgpack::zone z;
        msgpack::object objz(elem3, z);
        std::cout << objz.as<my_enum>() << std::endl;
        assert(objz.as<my_enum>() == elem3);
    }
}
