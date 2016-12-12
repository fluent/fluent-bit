// MessagePack for C++ example
//
// Copyright (C) 2015 KONDO Takatoshi
//
//    Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//    http://www.boost.org/LICENSE_1_0.txt)
//

#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cassert>

#include <msgpack.hpp>


class my_class {
public:
    my_class() {} // When you want to convert from msgpack::object to my_class,
                  // my_class should be default constractible.
                  // If you use C++11, you can adapt non-default constructible
                  // classes to msgpack::object.
                  // See https://github.com/msgpack/msgpack-c/wiki/v1_1_cpp_adaptor#non-default-constructible-class-support-c11-only
    my_class(std::string const& name, int age):name_(name), age_(age) {}

    friend bool operator==(my_class const& lhs, my_class const& rhs) {
        return lhs.name_ == rhs.name_ && lhs.age_ == rhs.age_;
    }

private:
    std::string name_;
    int age_;

public:
    MSGPACK_DEFINE_MAP(name_, age_);
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
    {   // pack, unpack
        my_class my("John Smith", 42);
        std::stringstream ss;
        msgpack::pack(ss, my);

        print(ss.str());

        msgpack::object_handle oh =
            msgpack::unpack(ss.str().data(), ss.str().size());
        msgpack::object obj = oh.get();
        std::cout << obj << std::endl;
        assert(obj.as<my_class>() == my);
    }
    {   // create object with zone
        my_class my("John Smith", 42);
        msgpack::zone z;
        msgpack::object obj(my, z);
        std::cout << obj << std::endl;
        assert(obj.as<my_class>() == my);
    }
}
