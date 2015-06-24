#include <msgpack.hpp>

#include <gtest/gtest.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if !defined(MSGPACK_USE_CPP03)

class TestEnumClassMemberClass
{
public:
    TestEnumClassMemberClass()
        : t1(TestEnumClassType::STATE_A), t2(TestEnumClassType::STATE_B), t3(TestEnumClassType::STATE_C) {}

    enum class TestEnumClassType:long {
        STATE_INVALID = 0,
            STATE_A = 1,
            STATE_B = 2,
            STATE_C = 3
        };
    TestEnumClassType t1;
    TestEnumClassType t2;
    TestEnumClassType t3;

    MSGPACK_DEFINE(t1, t2, t3);
};

MSGPACK_ADD_ENUM(TestEnumClassMemberClass::TestEnumClassType);

using namespace std;

const unsigned int kLoop = 10000;
const unsigned int kElements = 100;


// C++11

TEST(MSGPACK_CPP11, simple_tuple)
{
    msgpack::sbuffer sbuf;
    std::tuple<bool, std::string, double> val1(true, "kzk", 12.3);
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    std::tuple<bool, std::string, double> val2 = ret.get().as<std::tuple<bool, std::string, double> >();
    EXPECT_EQ(val1, val2);
}

TEST(MSGPACK_CPP11, simple_tuple_empty)
{
    msgpack::sbuffer sbuf;
    std::tuple<> val1;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    std::tuple<> val2 = ret.get().as<std::tuple<> >();
    EXPECT_EQ(val1, val2);
}

TEST(MSGPACK_CPP11, simple_array)
{
    for (unsigned int k = 0; k < kLoop; k++) {
        array<int, kElements> val1;
        for (unsigned int i = 0; i < kElements; i++)
            val1[i] = rand();
        msgpack::sbuffer sbuf;
        msgpack::pack(sbuf, val1);
        msgpack::unpacked ret;
        msgpack::unpack(ret, sbuf.data(), sbuf.size());
        EXPECT_EQ(ret.get().type, msgpack::type::ARRAY);
        array<int, kElements> val2 = ret.get().as<array<int, kElements> >();
        EXPECT_EQ(val1.size(), val2.size());
        EXPECT_TRUE(equal(val1.begin(), val1.end(), val2.begin()));
    }
}

TEST(MSGPACK_CPP11, simple_buffer_array_char)
{
    for (unsigned int k = 0; k < kLoop; k++) {
        array<char, kElements> val1;
        for (unsigned int i = 0; i < kElements; i++)
            val1[i] = rand();
        msgpack::sbuffer sbuf;
        msgpack::pack(sbuf, val1);
        msgpack::unpacked ret;
        msgpack::unpack(ret, sbuf.data(), sbuf.size());
        EXPECT_EQ(ret.get().type, msgpack::type::BIN);
        array<char, kElements> val2 = ret.get().as<array<char, kElements> >();
        EXPECT_EQ(val1.size(), val2.size());
        EXPECT_TRUE(equal(val1.begin(), val1.end(), val2.begin()));
    }
}

TEST(MSGPACK_STL, simple_buffer_forward_list)
{
    for (unsigned int k = 0; k < kLoop; k++) {
        forward_list<int> val1;
        for (unsigned int i = 0; i < kElements; i++)
            val1.push_front(rand());
        msgpack::sbuffer sbuf;
        msgpack::pack(sbuf, val1);
        msgpack::unpacked ret;
        msgpack::unpack(ret, sbuf.data(), sbuf.size());
        forward_list<int> val2 = ret.get().as<forward_list<int> >();
        EXPECT_EQ(val1, val2);
    }
}

TEST(MSGPACK_STL, simple_buffer_unordered_map)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    unordered_map<int, int> val1;
    for (unsigned int i = 0; i < kElements; i++)
      val1[rand()] = rand();
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    unordered_map<int, int> val2 = ret.get().as<unordered_map<int, int> >();
    EXPECT_EQ(val1, val2);
  }
}

TEST(MSGPACK_STL, simple_buffer_unordered_multimap)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    unordered_multimap<int, int> val1;
    for (unsigned int i = 0; i < kElements; i++) {
      int i1 = rand();
      val1.insert(make_pair(i1, rand()));
      val1.insert(make_pair(i1, rand()));
    }
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    unordered_multimap<int, int> val2 = ret.get().as<unordered_multimap<int, int> >();

    EXPECT_EQ(val1, val2);
  }
}

TEST(MSGPACK_STL, simple_buffer_unordered_set)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    unordered_set<int> val1;
    for (unsigned int i = 0; i < kElements; i++)
      val1.insert(rand());
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    unordered_set<int> val2 = ret.get().as<unordered_set<int> >();
    EXPECT_EQ(val1, val2);
  }
}

TEST(MSGPACK_STL, simple_buffer_unordered_multiset)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    unordered_multiset<int> val1;
    for (unsigned int i = 0; i < kElements; i++)
      val1.insert(rand());
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    unordered_multiset<int> val2 = ret.get().as<unordered_multiset<int> >();
    EXPECT_EQ(val1, val2);
  }
}

TEST(MSGPACK_USER_DEFINED, simple_buffer_enum_class_member)
{
    TestEnumClassMemberClass val1;
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    TestEnumClassMemberClass val2 = ret.get().as<TestEnumClassMemberClass>();
    EXPECT_EQ(val1.t1, val2.t1);
    EXPECT_EQ(val1.t2, val2.t2);
    EXPECT_EQ(val1.t3, val2.t3);
}

#endif // !defined(MSGPACK_USE_CPP03)
