// MessagePack for C++ example
//
// Copyright (C) 2015 KONDO Takatoshi
//
//    Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//    http://www.boost.org/LICENSE_1_0.txt)
//

#include <string>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>

#include <msgpack.hpp>

struct user {
    std::string name;
    int age;
    std::string address;
    MSGPACK_DEFINE(name, age, address);
};

struct proc:boost::static_visitor<void> {
    void operator()(std::string& v) const {
        std::cout << "  match std::string& v" << std::endl;
        std::cout << "    v: " << v << std::endl;
        std::cout << "    capitalize" << std::endl;
        for (std::string::iterator it = v.begin(), end = v.end();
             it != end;
             ++it) {
            *it = std::toupper(*it);
        }
    }
    void operator()(std::vector<msgpack::type::variant>& v) const {
        std::cout << "match vector (msgpack::type::ARRAY)" << std::endl;
        std::vector<msgpack::type::variant>::iterator it = v.begin();
        std::vector<msgpack::type::variant>::const_iterator end = v.end();
        for (; it != end; ++it) {
            boost::apply_visitor(*this, *it);
        }
    }
    template <typename T>
    void operator()(T const&) const {
        std::cout << "  match others" << std::endl;
    }
};

void print(std::string const& buf) {
    for (std::string::const_iterator it = buf.begin(), end = buf.end();
         it != end;
         ++it) {
        std::cout
            << std::setw(2)
            << std::hex
            << std::setfill('0')
            << (static_cast<int>(*it) & 0xff)
            << ' ';
    }
    std::cout << std::dec << std::endl;
}


int main() {
    std::stringstream ss1;
    user u;
    u.name = "Takatoshi Kondo";
    u.age = 42;
    u.address = "Tokyo, JAPAN";

    std::cout << "Packing object." << std::endl;
    msgpack::pack(ss1, u);
    print(ss1.str());

    msgpack::object_handle oh1 = msgpack::unpack(ss1.str().data(), ss1.str().size());
    msgpack::object const& obj1 = oh1.get();
    std::cout << "Unpacked msgpack object." << std::endl;
    std::cout << obj1 << std::endl;

    msgpack::type::variant v = obj1.as<msgpack::type::variant>();
    std::cout << "Applying proc..." << std::endl;
    boost::apply_visitor(proc(), v);

    std::stringstream ss2;
    std::cout << "Packing modified object." << std::endl;
    msgpack::pack(ss2, v);
    print(ss2.str());

    msgpack::object_handle oh2 = msgpack::unpack(ss2.str().data(), ss2.str().size());
    msgpack::object const& obj2 = oh2.get();
    std::cout << "Modified msgpack object." << std::endl;
    std::cout << obj2 << std::endl;
}
