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

#include <msgpack.hpp>

class my_class {
public:
    my_class() {} // When you want to convert from msgpack::object to my_class,
                  // my_class should be default constractible.
    my_class(std::string const& name, int age):name_(name), age_(age) {}

    // my_class should provide getters for the data members you want to pack.
    std::string const& get_name() const { return name_; }
    int get_age() const { return age_; }

    friend bool operator==(my_class const& lhs, my_class const& rhs) {
        return lhs.name_ == rhs.name_ && lhs.age_ == rhs.age_;
    }

private:
    std::string name_;
    int age_;
};

// User defined class template specialization
namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {

template<>
struct convert<my_class> {
    msgpack::object const& operator()(msgpack::object const& o, my_class& v) const {
        if (o.type != msgpack::type::ARRAY) throw msgpack::type_error();
        if (o.via.array.size != 2) throw msgpack::type_error();
        v = my_class(
            o.via.array.ptr[0].as<std::string>(),
            o.via.array.ptr[1].as<int>());
        return o;
    }
};

template<>
struct pack<my_class> {
    template <typename Stream>
    packer<Stream>& operator()(msgpack::packer<Stream>& o, my_class const& v) const {
        // packing member variables as an array.
        o.pack_array(2);
        o.pack(v.get_name());
        o.pack(v.get_age());
        return o;
    }
};

template <>
struct object_with_zone<my_class> {
    void operator()(msgpack::object::with_zone& o, my_class const& v) const {
        o.type = type::ARRAY;
        o.via.array.size = 2;
        o.via.array.ptr = static_cast<msgpack::object*>(
            o.zone.allocate_align(sizeof(msgpack::object) * o.via.array.size));
        o.via.array.ptr[0] = msgpack::object(v.get_name(), o.zone);
        o.via.array.ptr[1] = msgpack::object(v.get_age(), o.zone);
    }
};

} // namespace adaptor
} // MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS)
} // namespace msgpack


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
