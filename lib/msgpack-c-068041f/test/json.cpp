#include <msgpack.hpp>
#include <fstream>
#include <sstream>
#include <gtest/gtest.h>

TEST(json, basic_elements)
{
    typedef std::map<std::string, int> map_s_i;
    map_s_i msi;
    msi.insert(map_s_i::value_type("Hello", 789));
    msi.insert(map_s_i::value_type("World", -789));

    msgpack::type::tuple<int, int, double, double, bool, bool, std::string, map_s_i>
        t1(12, -34, 1.23, -4.56, true, false, "ABC", msi);

    msgpack::zone z;
    msgpack::object o(t1, z);
    std::stringstream ss;
    ss << o;
    EXPECT_EQ(ss.str(), "[12, -34, 1.23, -4.56, true, false, \"ABC\", {\"Hello\":789, \"World\":-789}]");
}

TEST(json, escape)
{
    std::string s = "\"\\/\b\f\n\r\tabc";

    msgpack::zone z;
    msgpack::object o(s, z);
    std::stringstream ss;
    ss << o;
    EXPECT_EQ(ss.str(), "\"\\\"\\\\\\/\\b\\f\\n\\r\\tabc\"");
}

TEST(json, escape_cc)
{
    std::string s;
    for (int i = 0; i < 0x20; ++i)
        s.push_back(static_cast<char>(i));
    s.push_back(0x7f);
    s.push_back(0x20);
    msgpack::zone z;
    msgpack::object o(s, z);
    std::stringstream ss;
    ss << o;
    EXPECT_EQ(ss.str(), "\"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\b\\t\\n\\u000b\\f\\r\\u000e\\u000f\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f\\u007f \"");
}
