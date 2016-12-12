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

#include <msgpack.hpp>

struct user {
    std::string name;
    int age;
    std::string address;
    MSGPACK_DEFINE_MAP(name, age, address);
};

struct proc:boost::static_visitor<void> {
    // msgpack::type::MAP is converted to std::multimap, not std::map.
    void operator()(std::multimap<msgpack::type::variant_ref, msgpack::type::variant_ref>& v) const {
        std::cout << "match map" << std::endl;
        std::multimap<msgpack::type::variant_ref, msgpack::type::variant_ref>::iterator it = v.begin();
        std::multimap<msgpack::type::variant_ref, msgpack::type::variant_ref>::iterator end = v.end();
        while(it != end) {
            boost::string_ref const& key = it->first.as_boost_string_ref();
            if (key == "name") {
                boost::string_ref const& value = it->second.as_boost_string_ref();
                if (value == "Takatoshi Kondo") {
                    // You can add values to msgpack::type::variant_ref.
                    v.insert(
                        std::multimap<msgpack::type::variant_ref, msgpack::type::variant_ref>::value_type(
                            "role",
                            "msgpack-c committer"
                        )
                    );
                }
                ++it;
            }
            else if (key == "age") {
                // You can remove key-value pair from msgpack::type::variant_ref

#if defined(MSGPACK_USE_CPP03)
#  if MSGPACK_LIB_STD_CXX
                v.erase(std::multimap<msgpack::type::variant_ref, msgpack::type::variant_ref>::const_iterator(it++));
#  else  // MSGPACK_LIB_STD_CXX
                v.erase(it++);
#  endif // MSGPACK_LIB_STD_CXX
#else  // defined(MSGPACK_USE_CPP03)
#  if MSGPACK_LIB_STD_CXX
                it = v.erase(std::multimap<msgpack::type::variant_ref, msgpack::type::variant_ref>::const_iterator(it));
#  else  // MSGPACK_LIB_STD_CXX
                it = v.erase(it);
#  endif // MSGPACK_LIB_STD_CXX
#endif // defined(MSGPACK_USE_CPP03)
            }
            else if (key == "address") {
                // When you want to append string
                // "Tokyo" -> "Tokyo, JAPAN"
                // Use msgpack::type::variant instead of msgpack::type::variant_ref
                // or do as follows:
                boost::string_ref const& value = it->second.as_boost_string_ref();
                it->second = std::string(&value.front(), value.size()) + ", JAPAN";
                ++it;
            }
        }
    }
    template <typename T>
    void operator()(T const&) const {
        std::cout << "  match others" << std::endl;
    }
};

int main() {
    std::stringstream ss;
    user u;
    u.name = "Takatoshi Kondo";
    u.age = 42;
    u.address = "Tokyo";
    msgpack::pack(ss, u);

    msgpack::object_handle oh = msgpack::unpack(ss.str().data(), ss.str().size());
    msgpack::object const& obj = oh.get();
    std::cout << "Unpacked msgpack object." << std::endl;
    std::cout << obj << std::endl;
    msgpack::type::variant_ref v = obj.as<msgpack::type::variant_ref>();
    std::cout << "Applying proc..." << std::endl;
    boost::apply_visitor(proc(), v);
    msgpack::zone z;
    std::cout << "Applied msgpack object." << std::endl;
    std::cout << msgpack::object(v, z) << std::endl;
}
