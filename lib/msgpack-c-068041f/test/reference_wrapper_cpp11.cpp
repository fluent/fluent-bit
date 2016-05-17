#include <msgpack.hpp>
#include <sstream>
#include <gtest/gtest.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if !defined(MSGPACK_USE_CPP03)

TEST(MSGPACK_REFERENCE_WRAPPER, pack_convert)
{
    int i1 = 42;
    std::reference_wrapper<int> val1(i1);
    std::stringstream ss;
    msgpack::pack(ss, val1);
    msgpack::object_handle oh = msgpack::unpack(ss.str().data(), ss.str().size());
    int i2 = 0;
    std::reference_wrapper<int> val2(i2);
    oh.get().convert(val2);
    EXPECT_EQ(i1, i2);
}

TEST(MSGPACK_REFERENCE_WRAPPER, pack_convert_const)
{
    const int i1 = 42;
    std::reference_wrapper<const int> val1(i1);
    std::stringstream ss;
    msgpack::pack(ss, val1);
    msgpack::object_handle oh = msgpack::unpack(ss.str().data(), ss.str().size());
    int i2 = 0;
    std::reference_wrapper<int> val2(i2);
    oh.get().convert(val2);
    EXPECT_EQ(i1, i2);
}

TEST(MSGPACK_REFERENCE_WRAPPER, pack_vector)
{
    int i1 = 42;
    std::vector<std::reference_wrapper<int>> val1{i1};
    std::stringstream ss;
    msgpack::pack(ss, val1);
    msgpack::object_handle oh = msgpack::unpack(ss.str().data(), ss.str().size());
    std::vector<int> val2 = oh.get().as<std::vector<int>>();
    EXPECT_EQ(val2.size(), 1);
    EXPECT_EQ(val1[0], val2[0]);
}

TEST(MSGPACK_REFERENCE_WRAPPER, object)
{
    int i1 = 42;
    std::reference_wrapper<int> val1(i1);
    msgpack::object o(val1);
    int i2 = 0;
    std::reference_wrapper<int> val2(i2);
    o.convert(val2);
    EXPECT_EQ(i1, i2);
}

TEST(MSGPACK_REFERENCE_WRAPPER, object_const)
{
    const int i1 = 42;
    std::reference_wrapper<const int> val1(i1);
    msgpack::object o(val1);
    int i2 = 0;
    std::reference_wrapper<int> val2(i2);
    o.convert(val2);
    EXPECT_EQ(i1, i2);
}

TEST(MSGPACK_REFERENCE_WRAPPER, object_with_zone)
{
    std::string s1 = "ABC";
    std::reference_wrapper<std::string> val1(s1);
    msgpack::zone z;
    msgpack::object o(val1, z);
    std::string s2 = "DE";
    std::reference_wrapper<std::string> val2(s2);
    o.convert(val2);
    EXPECT_EQ(s1, s2);
}

TEST(MSGPACK_REFERENCE_WRAPPER, object_with_zone_const)
{
    const std::string s1 = "ABC";
    std::reference_wrapper<const std::string> val1(s1);
    msgpack::zone z;
    msgpack::object o(val1, z);
    std::string s2 = "DE";
    std::reference_wrapper<std::string> val2(s2);
    o.convert(val2);
    EXPECT_EQ(s1, s2);
}

#endif // !defined(MSGPACK_USE_CPP03)
