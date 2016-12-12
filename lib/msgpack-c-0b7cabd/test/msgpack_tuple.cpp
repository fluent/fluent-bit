#include <msgpack.hpp>
#include <gtest/gtest.h>


TEST(msgpack_tuple, member_get)
{
    msgpack::type::tuple<int, bool, std::string> t1(42, true, "ABC");
    EXPECT_EQ(42, t1.get<0>());
    EXPECT_EQ(true, t1.get<1>());
    EXPECT_EQ("ABC", t1.get<2>());
    t1.get<0>() = 40;
    t1.get<1>() = false;
    t1.get<2>() = "DEFG";
    EXPECT_EQ(40, t1.get<0>());
    EXPECT_FALSE(t1.get<1>());
    EXPECT_EQ("DEFG", t1.get<2>());
}

TEST(msgpack_tuple, non_member_get)
{
    msgpack::type::tuple<int, bool, std::string> t1(42, true, "ABC");
    EXPECT_EQ(42, msgpack::type::get<0>(t1));
    EXPECT_EQ(true, msgpack::type::get<1>(t1));
    EXPECT_EQ("ABC", msgpack::type::get<2>(t1));
    msgpack::type::get<0>(t1) = 40;
    msgpack::type::get<1>(t1) = false;
    msgpack::type::get<2>(t1) = "DEFG";
    EXPECT_EQ(40, msgpack::type::get<0>(t1));
    EXPECT_FALSE(msgpack::type::get<1>(t1));
    EXPECT_EQ("DEFG", msgpack::type::get<2>(t1));
}

#if __cplusplus >= 201103L
TEST(msgpack_tuple, std_non_member_get)
{
    msgpack::type::tuple<int, bool, std::string> t1(42, true, "ABC");
    EXPECT_EQ(42, std::get<0>(t1));
    EXPECT_EQ(true, std::get<1>(t1));
    EXPECT_EQ("ABC", std::get<2>(t1));
    std::get<0>(t1) = 40;
    std::get<1>(t1) = false;
    std::get<2>(t1) = "DEFG";
    EXPECT_EQ(40, std::get<0>(t1));
    EXPECT_FALSE(std::get<1>(t1));
    EXPECT_EQ("DEFG", std::get<2>(t1));
}

TEST(msgpack_tuple, make_tuple)
{
    msgpack::type::tuple<int, bool, std::string> t1 = msgpack::type::make_tuple(42, true, "ABC");
    EXPECT_EQ(42, t1.get<0>());
    EXPECT_EQ(true, t1.get<1>());
    EXPECT_EQ("ABC", t1.get<2>());
    t1.get<0>() = 40;
    t1.get<1>() = false;
    t1.get<2>() = "DEFG";
    EXPECT_EQ(40, t1.get<0>());
    EXPECT_FALSE(t1.get<1>());
    EXPECT_EQ("DEFG", t1.get<2>());
}

TEST(msgpack_tuple, std_make_tuple)
{
    msgpack::type::tuple<int, bool, std::string> t1 = std::make_tuple(42, true, "ABC");
    EXPECT_EQ(42, t1.get<0>());
    EXPECT_EQ(true, t1.get<1>());
    EXPECT_EQ("ABC", t1.get<2>());
}

TEST(msgpack_tuple, tie)
{
    int i(43);
    bool b(false);
    std::string s("DEFG");
    msgpack::type::tie(i, b, s) = msgpack::type::make_tuple(42, true, "ABC");
    EXPECT_EQ(42, i);
    EXPECT_EQ(true, b);
    EXPECT_EQ("ABC", s);
}

TEST(msgpack_tuple, tuple_cat)
{
    msgpack::type::tuple<int> t1 = msgpack::type::make_tuple(42);
    msgpack::type::tuple<bool, std::string> t2 = msgpack::type::make_tuple(true, "ABC");
    msgpack::type::tuple<int, bool, std::string> t3 = msgpack::type::tuple_cat(t1, std::move(t2));
    EXPECT_EQ(42, t3.get<0>());
    EXPECT_EQ(true, t3.get<1>());
    EXPECT_EQ("ABC", t3.get<2>());
}

TEST(msgpack_tuple, swap)
{
    msgpack::type::tuple<int, bool, std::string>  t1 = msgpack::type::make_tuple(42, true, "ABC");
    msgpack::type::tuple<int, bool, std::string>  t2 = msgpack::type::make_tuple(40, false, "DEFG");
    msgpack::type::swap(t1, t2);
    EXPECT_EQ(42, t2.get<0>());
    EXPECT_EQ(true, t2.get<1>());
    EXPECT_EQ("ABC", t2.get<2>());
    EXPECT_EQ(40, t1.get<0>());
    EXPECT_FALSE(t1.get<1>());
    EXPECT_EQ("DEFG", t1.get<2>());
}
#endif
