// MessagePack for C++ example
//
// Copyright (C) 2015 KONDO Takatoshi
//
//    Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//    http://www.boost.org/LICENSE_1_0.txt)
//

#include <msgpack.hpp>
#include <string>
#include <iostream>
#include <sstream>

// This example uses obsolete APIs
// See protocol_new.cpp
namespace myprotocol {
    struct Get {
        Get() {}
        Get(uint32_t f, const std::string& k) : flags(f), key(k) {}
        uint32_t flags;
        std::string key;
        MSGPACK_DEFINE(flags, key);
    };

    typedef std::vector<Get> MultiGet;
}


int main(void)
{
    // send Get request
    std::stringstream stream;
    {
        myprotocol::Get req;
        req.flags = 0;
        req.key   = "key0";
        msgpack::pack(stream, req);
    }

    stream.seekg(0);

    // receive Get request
    {
        std::string buffer(stream.str());

        msgpack::object_handle oh =
            msgpack::unpack(buffer.data(), buffer.size());
        msgpack::object o = oh.get();

        myprotocol::Get req;
        o.convert(req);
        std::cout << "received: " << o << std::endl;
    }


    stream.str("");


    // send MultiGet request
    {
        myprotocol::MultiGet req;
        req.push_back( myprotocol::Get(1, "key1") );
        req.push_back( myprotocol::Get(2, "key2") );
        req.push_back( myprotocol::Get(3, "key3") );
        msgpack::pack(stream, req);
    }

    stream.seekg(0);

    // receive MultiGet request
    {
        std::string buffer(stream.str());

        msgpack::object_handle oh =
            msgpack::unpack(buffer.data(), buffer.size());
        msgpack::object o = oh.get();


        myprotocol::MultiGet req;
        o.convert(req);
        std::cout << "received: " << o << std::endl;
    }
}
