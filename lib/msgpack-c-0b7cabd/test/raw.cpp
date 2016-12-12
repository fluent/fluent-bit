#include <msgpack.hpp>

#include <string>
#include <sstream>

#include <gtest/gtest.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

TEST(MSGPACK_RAW_REF, pack_unpack)
{
    std::string s = "ABC";

    msgpack::type::raw_ref rr1(s.data(), s.size());
    std::stringstream ss;
    msgpack::pack(ss, rr1);
    std::string packed_str = ss.str();
    EXPECT_EQ(packed_str[0], static_cast<char>(0xc4u));
    EXPECT_EQ(packed_str[1], static_cast<char>(0x03u));
    EXPECT_EQ(packed_str[2], 'A');
    EXPECT_EQ(packed_str[3], 'B');
    EXPECT_EQ(packed_str[4], 'C');

    msgpack::object_handle oh =
        msgpack::unpack(ss.str().data(), ss.str().size());
    msgpack::type::raw_ref rr2 = oh.get().as<msgpack::type::raw_ref>();
    EXPECT_TRUE(rr1 == rr2);
}

TEST(MSGPACK_RAW_REF, pack_unpack_8_l)
{
    std::string s;

    msgpack::type::raw_ref rr1(s.data(), s.size());
    std::stringstream ss;
    msgpack::pack(ss, rr1);
    std::string packed_str = ss.str();
    EXPECT_EQ(packed_str[0], static_cast<char>(0xc4u));
    EXPECT_EQ(packed_str[1], static_cast<char>(0x00u));

    msgpack::object_handle oh =
        msgpack::unpack(ss.str().data(), ss.str().size());
    msgpack::type::raw_ref rr2 = oh.get().as<msgpack::type::raw_ref>();
    EXPECT_TRUE(rr1 == rr2);
}

TEST(MSGPACK_RAW_REF, pack_unpack_8_h)
{
    std::string s(0xff, 'A');

    msgpack::type::raw_ref rr1(s.data(), s.size());
    std::stringstream ss;
    msgpack::pack(ss, rr1);
    std::string packed_str = ss.str();
    EXPECT_EQ(packed_str[0], static_cast<char>(0xc4u));
    EXPECT_EQ(packed_str[1], static_cast<char>(0xffu));
    EXPECT_EQ(packed_str[2], 'A');

    msgpack::object_handle oh =
        msgpack::unpack(ss.str().data(), ss.str().size());
    msgpack::type::raw_ref rr2 = oh.get().as<msgpack::type::raw_ref>();
    EXPECT_TRUE(rr1 == rr2);
}

TEST(MSGPACK_RAW_REF, pack_unpack_16_l)
{
    std::string s(0xff+1, 'A');

    msgpack::type::raw_ref rr1(s.data(), s.size());
    std::stringstream ss;
    msgpack::pack(ss, rr1);
    std::string packed_str = ss.str();
    EXPECT_EQ(packed_str[0], static_cast<char>(0xc5u));
    EXPECT_EQ(packed_str[1], static_cast<char>(0x01));
    EXPECT_EQ(packed_str[2], static_cast<char>(0x00));
    EXPECT_EQ(packed_str[3], 'A');

    msgpack::object_handle oh =
        msgpack::unpack(ss.str().data(), ss.str().size());
    msgpack::type::raw_ref rr2 = oh.get().as<msgpack::type::raw_ref>();
    EXPECT_TRUE(rr1 == rr2);
}

TEST(MSGPACK_RAW_REF, pack_unpack_16_h)
{
    std::string s(0xffff, 'A');

    msgpack::type::raw_ref rr1(s.data(), s.size());
    std::stringstream ss;
    msgpack::pack(ss, rr1);
    std::string packed_str = ss.str();
    EXPECT_EQ(packed_str[0], static_cast<char>(0xc5u));
    EXPECT_EQ(packed_str[1], static_cast<char>(0xffu));
    EXPECT_EQ(packed_str[2], static_cast<char>(0xffu));
    EXPECT_EQ(packed_str[3], 'A');

    msgpack::object_handle oh =
        msgpack::unpack(ss.str().data(), ss.str().size());
    msgpack::type::raw_ref rr2 = oh.get().as<msgpack::type::raw_ref>();
    EXPECT_TRUE(rr1 == rr2);
}

TEST(MSGPACK_RAW_REF, pack_unpack_32_l)
{
    std::string s(0xffff+1, 'A');

    msgpack::type::raw_ref rr1(s.data(), s.size());
    std::stringstream ss;
    msgpack::pack(ss, rr1);
    std::string packed_str = ss.str();
    EXPECT_EQ(packed_str[0], static_cast<char>(0xc6u));
    EXPECT_EQ(packed_str[1], static_cast<char>(0x00));
    EXPECT_EQ(packed_str[2], static_cast<char>(0x01));
    EXPECT_EQ(packed_str[3], static_cast<char>(0x00));
    EXPECT_EQ(packed_str[4], static_cast<char>(0x00));
    EXPECT_EQ(packed_str[5], 'A');

    msgpack::object_handle oh =
        msgpack::unpack(ss.str().data(), ss.str().size());
    msgpack::type::raw_ref rr2 = oh.get().as<msgpack::type::raw_ref>();
    EXPECT_TRUE(rr1 == rr2);
}

TEST(MSGPACK_V4RAW_REF, pack_unpack)
{
    std::string s = "ABC";

    msgpack::type::v4raw_ref rr1(s.data(), s.size());
    std::stringstream ss;
    msgpack::pack(ss, rr1);
    std::string packed_str = ss.str();
    EXPECT_EQ(packed_str[0], static_cast<char>(0xa3u));
    EXPECT_EQ(packed_str[1], 'A');
    EXPECT_EQ(packed_str[2], 'B');
    EXPECT_EQ(packed_str[3], 'C');

    msgpack::object_handle oh =
        msgpack::unpack(ss.str().data(), ss.str().size());
    msgpack::type::v4raw_ref rr2 = oh.get().as<msgpack::type::v4raw_ref>();
    EXPECT_TRUE(rr1 == rr2);
}

TEST(MSGPACK_V4RAW_REF, pack_unpack_fix_l)
{
    std::string s;

    msgpack::type::v4raw_ref rr1(s.data(), s.size());
    std::stringstream ss;
    msgpack::pack(ss, rr1);
    std::string packed_str = ss.str();
    EXPECT_EQ(packed_str[0], static_cast<char>(0xa0u));

    msgpack::object_handle oh =
        msgpack::unpack(ss.str().data(), ss.str().size());
    msgpack::type::v4raw_ref rr2 = oh.get().as<msgpack::type::v4raw_ref>();
    EXPECT_TRUE(rr1 == rr2);
}

TEST(MSGPACK_V4RAW_REF, pack_unpack_fix_h)
{
    std::string s(0x1f, 'A');

    msgpack::type::v4raw_ref rr1(s.data(), s.size());
    std::stringstream ss;
    msgpack::pack(ss, rr1);
    std::string packed_str = ss.str();
    EXPECT_EQ(packed_str[0], static_cast<char>(0xbfu));
    EXPECT_EQ(packed_str[1], 'A');

    msgpack::object_handle oh =
        msgpack::unpack(ss.str().data(), ss.str().size());
    msgpack::type::v4raw_ref rr2 = oh.get().as<msgpack::type::v4raw_ref>();
    EXPECT_TRUE(rr1 == rr2);
}

TEST(MSGPACK_V4RAW_REF, pack_unpack_16_l)
{
    std::string s(0x1f+1, 'A');

    msgpack::type::v4raw_ref rr1(s.data(), s.size());
    std::stringstream ss;
    msgpack::pack(ss, rr1);
    std::string packed_str = ss.str();
    EXPECT_EQ(packed_str[0], static_cast<char>(0xdau));
    EXPECT_EQ(packed_str[1], static_cast<char>(0x00u));
    EXPECT_EQ(packed_str[2], static_cast<char>(0x20u));
    EXPECT_EQ(packed_str[3], 'A');

    msgpack::object_handle oh =
        msgpack::unpack(ss.str().data(), ss.str().size());
    msgpack::type::v4raw_ref rr2 = oh.get().as<msgpack::type::v4raw_ref>();
    EXPECT_TRUE(rr1 == rr2);
}

TEST(MSGPACK_V4RAW_REF, pack_unpack_16_h)
{
    std::string s(0xffff, 'A');

    msgpack::type::v4raw_ref rr1(s.data(), s.size());
    std::stringstream ss;
    msgpack::pack(ss, rr1);
    std::string packed_str = ss.str();
    EXPECT_EQ(packed_str[0], static_cast<char>(0xdau));
    EXPECT_EQ(packed_str[1], static_cast<char>(0xffu));
    EXPECT_EQ(packed_str[2], static_cast<char>(0xffu));
    EXPECT_EQ(packed_str[3], 'A');

    msgpack::object_handle oh =
        msgpack::unpack(ss.str().data(), ss.str().size());
    msgpack::type::v4raw_ref rr2 = oh.get().as<msgpack::type::v4raw_ref>();
    EXPECT_TRUE(rr1 == rr2);
}

TEST(MSGPACK_V4RAW_REF, pack_unpack_32_l)
{
    std::string s(0xffff+1, 'A');

    msgpack::type::v4raw_ref rr1(s.data(), s.size());
    std::stringstream ss;
    msgpack::pack(ss, rr1);
    std::string packed_str = ss.str();
    EXPECT_EQ(packed_str[0], static_cast<char>(0xdbu));
    EXPECT_EQ(packed_str[1], static_cast<char>(0x00));
    EXPECT_EQ(packed_str[2], static_cast<char>(0x01));
    EXPECT_EQ(packed_str[3], static_cast<char>(0x00));
    EXPECT_EQ(packed_str[4], static_cast<char>(0x00));
    EXPECT_EQ(packed_str[5], 'A');

    msgpack::object_handle oh =
        msgpack::unpack(ss.str().data(), ss.str().size());
    msgpack::type::v4raw_ref rr2 = oh.get().as<msgpack::type::v4raw_ref>();
    EXPECT_TRUE(rr1 == rr2);
}
