// MessagePack for C++ example
//
// Copyright (C) 2008-2015 FURUHASHI Sadayuki and KONDO Takatoshi
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

// When you want to adapt map instead of array, you can enable these macro definition.
//
// #define MSGPACK_USE_DEFINE_MAP


#include <msgpack.hpp>

struct my_base1 {
    int a;
    MSGPACK_DEFINE(a);
};
inline bool operator==(my_base1 const& lhs, my_base1 const& rhs) {
    return lhs.a == rhs.a;
}

struct my_base2 {
    std::string b;
    std::string c;
    MSGPACK_DEFINE(b, c);
};
inline bool operator==(my_base2 const& lhs, my_base2 const& rhs) {
    return lhs.b == rhs.b && lhs.c == rhs.c;
}

class my_class : public my_base1, private my_base2 {
public:
    my_class() {} // When you want to convert from msgpack::object to my_class,
                  // my_class should be default constractible.
    my_class(std::string const& name, int age):name_(name), age_(age) {}
    void set_b(std::string const& str) { b = str; }
    void set_c(std::string const& str) { c = str; }
    friend bool operator==(my_class const& lhs, my_class const& rhs) {
        return
            static_cast<my_base1 const&>(lhs) == static_cast<my_base1 const&>(rhs) &&
            static_cast<my_base2 const&>(lhs) == static_cast<my_base2 const&>(rhs) &&
            lhs.name_ == rhs.name_ && lhs.age_ == rhs.age_;
    }

private:
    std::string name_;
    int age_;

public:
    MSGPACK_DEFINE(name_, age_, MSGPACK_BASE(my_base1), MSGPACK_BASE(my_base2));
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
        my.a = 123;
        my.set_b("ABC");
        my.set_c("DEF");
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
        my.a = 123;
        my.set_b("ABC");
        my.set_c("DEF");
        msgpack::zone z;
        msgpack::object obj(my, z);
        std::cout << obj << std::endl;
        assert(obj.as<my_class>() == my);
    }
}
