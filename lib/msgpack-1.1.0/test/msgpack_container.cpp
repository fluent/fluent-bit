#include <msgpack.hpp>

#include <cmath>
#include <string>
#include <vector>
#include <map>
#include <deque>
#include <set>
#include <list>
#include <limits>

#include <gtest/gtest.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif



class TestEnumMemberClass
{
public:
  TestEnumMemberClass()
    : t1(STATE_A), t2(STATE_B), t3(STATE_C) {}

  enum TestEnumType {
    STATE_INVALID = 0,
    STATE_A = 1,
    STATE_B = 2,
    STATE_C = 3
  };
  TestEnumType t1;
  TestEnumType t2;
  TestEnumType t3;

  MSGPACK_DEFINE(t1, t2, t3);
};

MSGPACK_ADD_ENUM(TestEnumMemberClass::TestEnumType);

using namespace std;

const unsigned int kLoop = 1000;
const unsigned int kElements = 100;
const double kEPS = 1e-10;

TEST(MSGPACK_STL, simple_buffer_vector)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    vector<int> val1;
    for (unsigned int i = 0; i < kElements; i++)
      val1.push_back(rand());
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    EXPECT_EQ(ret.get().type, msgpack::type::ARRAY);
    vector<int> val2 = ret.get().as<vector<int> >();
    EXPECT_EQ(val1.size(), val2.size());
    EXPECT_TRUE(equal(val1.begin(), val1.end(), val2.begin()));
  }
}

TEST(MSGPACK_STL, simple_buffer_vector_char)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    vector<char> val1;
    for (unsigned int i = 0; i < kElements; i++)
      val1.push_back(rand());
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    EXPECT_EQ(ret.get().type, msgpack::type::BIN);
    vector<char> val2 = ret.get().as<vector<char> >();
    EXPECT_EQ(val1.size(), val2.size());
    EXPECT_TRUE(equal(val1.begin(), val1.end(), val2.begin()));
  }
}

TEST(MSGPACK_STL, simple_buffer_vector_bool)
{
  vector<bool> val1;
  for (unsigned int i = 0; i < kElements; i++)
    val1.push_back(i % 2 ? false : true);
  msgpack::sbuffer sbuf;
  msgpack::pack(sbuf, val1);
  msgpack::unpacked ret;
  msgpack::unpack(ret, sbuf.data(), sbuf.size());
  EXPECT_EQ(ret.get().type, msgpack::type::ARRAY);
  vector<bool> val2 = ret.get().as<vector<bool> >();
  EXPECT_EQ(val1.size(), val2.size());
  EXPECT_TRUE(equal(val1.begin(), val1.end(), val2.begin()));
}


TEST(MSGPACK_STL, simple_buffer_map)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    map<int, int> val1;
    for (unsigned int i = 0; i < kElements; i++)
      val1[rand()] = rand();
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    map<int, int> val2 = ret.get().as<map<int, int> >();
    EXPECT_EQ(val1.size(), val2.size());
    EXPECT_TRUE(equal(val1.begin(), val1.end(), val2.begin()));
  }
}

TEST(MSGPACK_STL, simple_buffer_deque)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    deque<int> val1;
    for (unsigned int i = 0; i < kElements; i++)
      val1.push_back(rand());
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    deque<int> val2 = ret.get().as<deque<int> >();
    EXPECT_EQ(val1.size(), val2.size());
    EXPECT_TRUE(equal(val1.begin(), val1.end(), val2.begin()));
  }
}

TEST(MSGPACK_STL, simple_buffer_list)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    list<int> val1;
    for (unsigned int i = 0; i < kElements; i++)
      val1.push_back(rand());
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    list<int> val2 = ret.get().as<list<int> >();
    EXPECT_EQ(val1.size(), val2.size());
    EXPECT_TRUE(equal(val1.begin(), val1.end(), val2.begin()));
  }
}

TEST(MSGPACK_STL, simple_buffer_set)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    set<int> val1;
    for (unsigned int i = 0; i < kElements; i++)
      val1.insert(rand());
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    set<int> val2 = ret.get().as<set<int> >();
    EXPECT_EQ(val1.size(), val2.size());
    EXPECT_TRUE(equal(val1.begin(), val1.end(), val2.begin()));
  }
}

TEST(MSGPACK_STL, simple_buffer_pair)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    pair<int, int> val1 = make_pair(rand(), rand());
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    pair<int, int> val2 = ret.get().as<pair<int, int> >();
    EXPECT_EQ(val1.first, val2.first);
    EXPECT_EQ(val1.second, val2.second);
  }
}

TEST(MSGPACK_STL, simple_buffer_multimap)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    multimap<int, int> val1;
    for (unsigned int i = 0; i < kElements; i++) {
      int i1 = rand();
      val1.insert(make_pair(i1, rand()));
      val1.insert(make_pair(i1, rand()));
    }
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    multimap<int, int> val2 = ret.get().as<multimap<int, int> >();

    vector<pair<int, int> > v1, v2;
    multimap<int, int>::const_iterator it;
    for (it = val1.begin(); it != val1.end(); ++it)
      v1.push_back(make_pair(it->first, it->second));
    for (it = val2.begin(); it != val2.end(); ++it)
      v2.push_back(make_pair(it->first, it->second));
    EXPECT_EQ(val1.size(), val2.size());
    EXPECT_EQ(v1.size(), v2.size());
    sort(v1.begin(), v1.end());
    sort(v2.begin(), v2.end());
    EXPECT_TRUE(v1 == v2);
  }
}

TEST(MSGPACK_STL, simple_buffer_multiset)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    multiset<int> val1;
    for (unsigned int i = 0; i < kElements; i++)
      val1.insert(rand());
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    multiset<int> val2 = ret.get().as<multiset<int> >();

    vector<int> v1, v2;
    multiset<int>::const_iterator it;
    for (it = val1.begin(); it != val1.end(); ++it)
      v1.push_back(*it);
    for (it = val2.begin(); it != val2.end(); ++it)
      v2.push_back(*it);
    EXPECT_EQ(val1.size(), val2.size());
    EXPECT_EQ(v1.size(), v2.size());
    sort(v1.begin(), v1.end());
    sort(v2.begin(), v2.end());
    EXPECT_TRUE(v1 == v2);
  }
}

TEST(MSGPACK_TUPLE, simple_tuple)
{
    msgpack::sbuffer sbuf;
    msgpack::type::tuple<bool, std::string, double> val1(true, "kzk", 12.3);
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    msgpack::type::tuple<bool, std::string, double> val2
        = ret.get().as<msgpack::type::tuple<bool, std::string, double> >();
    EXPECT_EQ(ret.get().via.array.size, 3);
    EXPECT_EQ(val1.get<0>(), val2.get<0>());
    EXPECT_EQ(val1.get<1>(), val2.get<1>());
    EXPECT_EQ(val1.get<2>(), val2.get<2>());
}

TEST(MSGPACK_TUPLE, simple_tuple_empty)
{
    msgpack::sbuffer sbuf;
    msgpack::type::tuple<> val1;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    ret.get().as<msgpack::type::tuple<> >();
    EXPECT_EQ(ret.get().via.array.size, 0);
}


// TR1

#ifdef MSGPACK_HAS_STD_TR1_UNORDERED_MAP
#include <tr1/unordered_map>
#include "msgpack/adaptor/tr1/unordered_map.hpp"
TEST(MSGPACK_TR1, simple_buffer_tr1_unordered_map)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    tr1::unordered_map<int, int> val1;
    for (unsigned int i = 0; i < kElements; i++)
      val1[rand()] = rand();
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    tr1::unordered_map<int, int> val2 = ret.get().as<tr1::unordered_map<int, int> >();
    EXPECT_EQ(val1.size(), val2.size());
    tr1::unordered_map<int, int>::const_iterator it;
    for (it = val1.begin(); it != val1.end(); ++it) {
      EXPECT_TRUE(val2.find(it->first) != val2.end());
      EXPECT_EQ(it->second, val2.find(it->first)->second);
    }
  }
}

TEST(MSGPACK_TR1, simple_buffer_tr1_unordered_multimap)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    tr1::unordered_multimap<int, int> val1;
    for (unsigned int i = 0; i < kElements; i++) {
      int i1 = rand();
      val1.insert(make_pair(i1, rand()));
      val1.insert(make_pair(i1, rand()));
    }
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    tr1::unordered_multimap<int, int> val2 = ret.get().as<tr1::unordered_multimap<int, int> >();

    vector<pair<int, int> > v1, v2;
    tr1::unordered_multimap<int, int>::const_iterator it;
    for (it = val1.begin(); it != val1.end(); ++it)
      v1.push_back(make_pair(it->first, it->second));
    for (it = val2.begin(); it != val2.end(); ++it)
      v2.push_back(make_pair(it->first, it->second));
    EXPECT_EQ(val1.size(), val2.size());
    EXPECT_EQ(v1.size(), v2.size());
    sort(v1.begin(), v1.end());
    sort(v2.begin(), v2.end());
    EXPECT_TRUE(v1 == v2);
  }
}
#endif

#ifdef MSGPACK_HAS_STD_TR1_UNORDERED_SET
#include <tr1/unordered_set>
#include "msgpack/adaptor/tr1/unordered_set.hpp"
TEST(MSGPACK_TR1, simple_buffer_tr1_unordered_set)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    tr1::unordered_set<int> val1;
    for (unsigned int i = 0; i < kElements; i++)
      val1.insert(rand());
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    tr1::unordered_set<int> val2 = ret.get().as<tr1::unordered_set<int> >();
    EXPECT_EQ(val1.size(), val2.size());
    tr1::unordered_set<int>::const_iterator it;
    for (it = val1.begin(); it != val1.end(); ++it)
      EXPECT_TRUE(val2.find(*it) != val2.end());
  }
}

TEST(MSGPACK_TR1, simple_buffer_tr1_unordered_multiset)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    tr1::unordered_multiset<int> val1;
    for (unsigned int i = 0; i < kElements; i++)
      val1.insert(rand());
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    tr1::unordered_multiset<int> val2 = ret.get().as<tr1::unordered_multiset<int> >();

    vector<int> v1, v2;
    tr1::unordered_multiset<int>::const_iterator it;
    for (it = val1.begin(); it != val1.end(); ++it)
      v1.push_back(*it);
    for (it = val2.begin(); it != val2.end(); ++it)
      v2.push_back(*it);
    EXPECT_EQ(val1.size(), val2.size());
    EXPECT_EQ(v1.size(), v2.size());
    sort(v1.begin(), v1.end());
    sort(v2.begin(), v2.end());
    EXPECT_TRUE(v1 == v2);
  }
}
#endif

#ifdef MSGPACK_HAS_STD_UNORDERED_MAP
#include <unordered_map>
#include "msgpack/adaptor/tr1/unordered_map.hpp"
TEST(MSGPACK_TR1, simple_buffer_unordered_map)
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
    EXPECT_EQ(val1.size(), val2.size());
    unordered_map<int, int>::const_iterator it;
    for (it = val1.begin(); it != val1.end(); ++it) {
      EXPECT_TRUE(val2.find(it->first) != val2.end());
      EXPECT_EQ(it->second, val2.find(it->first)->second);
    }
  }
}

TEST(MSGPACK_TR1, simple_buffer_unordered_multimap)
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

    vector<pair<int, int> > v1, v2;
    unordered_multimap<int, int>::const_iterator it;
    for (it = val1.begin(); it != val1.end(); ++it)
      v1.push_back(make_pair(it->first, it->second));
    for (it = val2.begin(); it != val2.end(); ++it)
      v2.push_back(make_pair(it->first, it->second));
    EXPECT_EQ(val1.size(), val2.size());
    EXPECT_EQ(v1.size(), v2.size());
    sort(v1.begin(), v1.end());
    sort(v2.begin(), v2.end());
    EXPECT_TRUE(v1 == v2);
  }
}
#endif

#ifdef MSGPACK_HAS_STD_UNORDERED_SET
#include <unordered_set>
#include "msgpack/adaptor/tr1/unordered_set.hpp"
TEST(MSGPACK_TR1, simple_buffer_unordered_set)
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
    EXPECT_EQ(val1.size(), val2.size());
    unordered_set<int>::const_iterator it;
    for (it = val1.begin(); it != val1.end(); ++it)
      EXPECT_TRUE(val2.find(*it) != val2.end());
  }
}

TEST(MSGPACK_TR1, simple_buffer_unordered_multiset)
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

    vector<int> v1, v2;
    unordered_multiset<int>::const_iterator it;
    for (it = val1.begin(); it != val1.end(); ++it)
      v1.push_back(*it);
    for (it = val2.begin(); it != val2.end(); ++it)
      v2.push_back(*it);
    EXPECT_EQ(val1.size(), val2.size());
    EXPECT_EQ(v1.size(), v2.size());
    sort(v1.begin(), v1.end());
    sort(v2.begin(), v2.end());
    EXPECT_TRUE(v1 == v2);
  }
}
#endif


// User-Defined Structures

class TestClass
{
public:
  TestClass() : i(0), s("kzk") {}
  int i;
  string s;
  MSGPACK_DEFINE(i, s);
};

TEST(MSGPACK_USER_DEFINED, simple_buffer_class)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    TestClass val1;
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    TestClass val2 = ret.get().as<TestClass>();
    EXPECT_EQ(val1.i, val2.i);
    EXPECT_EQ(val1.s, val2.s);
  }
}

class TestClass2
{
public:
  TestClass2() : i(0), s("kzk") {
    for (unsigned int i = 0; i < kElements; i++)
      v.push_back(rand());
  }
  int i;
  string s;
  vector<int> v;
  MSGPACK_DEFINE(i, s, v);
};

TEST(MSGPACK_USER_DEFINED, simple_buffer_class_old_to_new)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    TestClass val1;
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    TestClass2 val2 = ret.get().as<TestClass2>();
    EXPECT_EQ(val1.i, val2.i);
    EXPECT_EQ(val1.s, val2.s);
    EXPECT_FALSE(val2.s.empty());
  }
}

TEST(MSGPACK_USER_DEFINED, simple_buffer_class_new_to_old)
{
  for (unsigned int k = 0; k < kLoop; k++) {
    TestClass2 val1;
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    TestClass val2 = ret.get().as<TestClass>();
    EXPECT_EQ(val1.i, val2.i);
    EXPECT_EQ(val1.s, val2.s);
    EXPECT_FALSE(val2.s.empty());
  }
}

TEST(MSGPACK_USER_DEFINED, simple_buffer_enum_member)
{
  TestEnumMemberClass val1;
  msgpack::sbuffer sbuf;
  msgpack::pack(sbuf, val1);
  msgpack::unpacked ret;
  msgpack::unpack(ret, sbuf.data(), sbuf.size());
  TestEnumMemberClass val2 = ret.get().as<TestEnumMemberClass>();
  EXPECT_EQ(val1.t1, val2.t1);
  EXPECT_EQ(val1.t2, val2.t2);
  EXPECT_EQ(val1.t3, val2.t3);
}

class TestUnionMemberClass
{
public:
  TestUnionMemberClass() {}
  TestUnionMemberClass(double f) {
    is_double = true;
    value.f = f;
  }
  TestUnionMemberClass(int i) {
    is_double = false;
    value.i = i;
  }

  union {
    double f;
    int i;
  } value;
  bool is_double;

  template <typename Packer>
  void msgpack_pack(Packer& pk) const
  {
    if (is_double)
      pk.pack(msgpack::type::tuple<bool, double>(true, value.f));
    else
      pk.pack(msgpack::type::tuple<bool, int>(false, value.i));
  }

  void msgpack_unpack(msgpack::object o)
  {
    msgpack::type::tuple<bool, msgpack::object> tuple;
    o.convert(&tuple);

    is_double = tuple.get<0>();
    if (is_double)
      tuple.get<1>().convert(&value.f);
    else
      tuple.get<1>().convert(&value.i);
  }
};

TEST(MSGPACK_USER_DEFINED, simple_buffer_union_member)
{
  {
    // double
    TestUnionMemberClass val1(1.0);
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    TestUnionMemberClass val2 = ret.get().as<TestUnionMemberClass>();
    EXPECT_EQ(val1.is_double, val2.is_double);
    EXPECT_TRUE(fabs(val1.value.f - val2.value.f) < kEPS);
  }
  {
    // int
    TestUnionMemberClass val1(1);
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, val1);
    msgpack::unpacked ret;
    msgpack::unpack(ret, sbuf.data(), sbuf.size());
    TestUnionMemberClass val2 = ret.get().as<TestUnionMemberClass>();
    EXPECT_EQ(val1.is_double, val2.is_double);
    EXPECT_EQ(val1.value.i, 1);
    EXPECT_EQ(val1.value.i, val2.value.i);
  }
}
