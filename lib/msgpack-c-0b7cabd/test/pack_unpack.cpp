#include <msgpack.hpp>
#include <gtest/gtest.h>
#include <sstream>

TEST(pack, num)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
}


TEST(pack, vector)
{
    msgpack::sbuffer sbuf;
    std::vector<int> vec;
    vec.push_back(1);
    vec.push_back(2);
    vec.push_back(3);
    msgpack::pack(sbuf, vec);
}


TEST(pack, to_ostream)
{
    std::ostringstream stream;
    msgpack::pack(stream, 1);
}


struct myclass {
    myclass() : num(0), str("default") { }

    myclass(int num, const std::string& str) :
        num(num), str(str) { }

    ~myclass() { }

    int num;
    std::string str;

    MSGPACK_DEFINE(num, str);
};


TEST(pack, myclass)
{
    msgpack::sbuffer sbuf;
    myclass m(1, "msgpack");
    msgpack::pack(sbuf, m);
}


TEST(unpack, int_ret_no_offset_no_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);

    msgpack::object_handle oh = msgpack::unpack(sbuf.data(), sbuf.size());
    EXPECT_EQ(1, oh.get().as<int>());
}

TEST(unpack, int_ret_offset_no_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);

    std::size_t off = 0;

    msgpack::object_handle oh = msgpack::unpack(sbuf.data(), sbuf.size(), off);
    EXPECT_EQ(1, oh.get().as<int>());
    EXPECT_EQ(off, sbuf.size());
}

TEST(unpack, int_ret_no_offset_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    bool referenced;

    msgpack::object_handle oh = msgpack::unpack(sbuf.data(), sbuf.size(), referenced);
    EXPECT_EQ(1, oh.get().as<int>());
    EXPECT_FALSE(referenced);
}

TEST(unpack, int_ret_offset_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    std::size_t off = 0;
    bool referenced;

    msgpack::object_handle oh = msgpack::unpack(sbuf.data(), sbuf.size(), off, referenced);
    EXPECT_EQ(1, oh.get().as<int>());
    EXPECT_FALSE(referenced);
    EXPECT_EQ(off, sbuf.size());
}


TEST(unpack, int_no_offset_no_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::object_handle oh;

    msgpack::unpack(oh, sbuf.data(), sbuf.size());
    EXPECT_EQ(1, oh.get().as<int>());
}

TEST(unpack, int_offset_no_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::object_handle oh;

    std::size_t off = 0;

    msgpack::unpack(oh, sbuf.data(), sbuf.size(), off);
    EXPECT_EQ(1, oh.get().as<int>());
    EXPECT_EQ(off, sbuf.size());
}

TEST(unpack, int_no_offset_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::object_handle oh;
    bool referenced;

    msgpack::unpack(oh, sbuf.data(), sbuf.size(), referenced);
    EXPECT_EQ(1, oh.get().as<int>());
    EXPECT_FALSE(referenced);
}

TEST(unpack, int_offset_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::object_handle oh;
    std::size_t off = 0;
    bool referenced;

    msgpack::unpack(oh, sbuf.data(), sbuf.size(), off, referenced);
    EXPECT_EQ(1, oh.get().as<int>());
    EXPECT_FALSE(referenced);
    EXPECT_EQ(off, sbuf.size());
}

#if MSGPACK_DEFAULT_API_VERSION == 1

TEST(unpack, int_pointer_off_no_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::object_handle oh;

    std::size_t off = 0;

    // obsolete
    msgpack::unpack(&oh, sbuf.data(), sbuf.size(), &off);
    EXPECT_EQ(1, oh.get().as<int>());
    EXPECT_EQ(off, sbuf.size());
}

TEST(unpack, int_pointer_off_no_ref_explicit)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::object_handle oh;

    std::size_t off = 0;

    // obsolete
    msgpack::unpack(&oh, sbuf.data(), sbuf.size(), &off, MSGPACK_NULLPTR);
    EXPECT_EQ(1, oh.get().as<int>());
    EXPECT_EQ(off, sbuf.size());
}

TEST(unpack, int_pointer_no_off_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::object_handle oh;
    bool referenced;

    // obsolete
    msgpack::unpack(&oh, sbuf.data(), sbuf.size(), MSGPACK_NULLPTR, &referenced);
    EXPECT_EQ(1, oh.get().as<int>());
    EXPECT_FALSE(referenced);
}

TEST(unpack, int_pointer_off_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::object_handle oh;
    bool referenced;
    std::size_t off = 0;

    // obsolete
    msgpack::unpack(&oh, sbuf.data(), sbuf.size(), &off, &referenced);
    EXPECT_EQ(1, oh.get().as<int>());
    EXPECT_EQ(off, sbuf.size());
    EXPECT_FALSE(referenced);
}


TEST(unpack, int_default_null_pointer)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::object_handle oh;

    // obsolete
    msgpack::unpack(&oh, sbuf.data(), sbuf.size());
    EXPECT_EQ(1, oh.get().as<int>());
}

#endif // MSGPACK_DEFAULT_API_VERSION == 1

TEST(unpack, int_zone_no_offset_no_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);

    msgpack::zone z;
    msgpack::object obj = msgpack::unpack(z, sbuf.data(), sbuf.size());
    EXPECT_EQ(1, obj.as<int>());
}

TEST(unpack, int_zone_offset_no_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);

    std::size_t off = 0;

    msgpack::zone z;
    msgpack::object obj = msgpack::unpack(z, sbuf.data(), sbuf.size(), off);
    EXPECT_EQ(1, obj.as<int>());
    EXPECT_EQ(off, sbuf.size());
}

TEST(unpack, int_zone_no_offset_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    bool referenced;

    msgpack::zone z;
    msgpack::object obj = msgpack::unpack(z, sbuf.data(), sbuf.size(), referenced);
    EXPECT_EQ(1, obj.as<int>());
    EXPECT_FALSE(referenced);
}

TEST(unpack, int_zone_offset_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    std::size_t off = 0;
    bool referenced;

    msgpack::zone z;
    msgpack::object obj = msgpack::unpack(z, sbuf.data(), sbuf.size(), off, referenced);
    EXPECT_EQ(1, obj.as<int>());
    EXPECT_FALSE(referenced);
    EXPECT_EQ(off, sbuf.size());
}


TEST(unpack, sequence)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::pack(sbuf, 2);
    msgpack::pack(sbuf, 3);

    std::size_t off = 0;

    msgpack::object_handle oh;

    msgpack::unpack(oh, sbuf.data(), sbuf.size(), off);
    EXPECT_EQ(1, oh.get().as<int>());

    msgpack::unpack(oh, sbuf.data(), sbuf.size(), off);
    EXPECT_EQ(2, oh.get().as<int>());

    msgpack::unpack(oh, sbuf.data(), sbuf.size(), off);
    EXPECT_EQ(3, oh.get().as<int>());

    EXPECT_EQ(off, sbuf.size());
}


TEST(unpack, convert_to_object_handle)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::unpacked msg;

    msgpack::unpack(msg, sbuf.data(), sbuf.size());
    msgpack::object_handle oh(msgpack::move(msg));
    EXPECT_EQ(1, oh.get().as<int>());

}

TEST(unpack, convert_to_object_handle_direct)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::object_handle oh(msgpack::unpack(sbuf.data(), sbuf.size()));
    EXPECT_EQ(1, oh.get().as<int>());

}

TEST(unpack, convert_to_object_handle_direct_implicit)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::object_handle oh = msgpack::unpack(sbuf.data(), sbuf.size());
    EXPECT_EQ(1, oh.get().as<int>());

}

TEST(unpack, insufficient_bytes_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 255); // uint8 (2bytes)

    std::size_t off = 0;

    msgpack::object_handle oh;
    try {
        msgpack::unpack(oh, sbuf.data(), 1, off);
        EXPECT_TRUE(false);
    }
    catch (msgpack::insufficient_bytes const&) {
        EXPECT_TRUE(true);
        EXPECT_EQ(off, 0u);
    }
}

TEST(unpack, insufficient_bytes_object_handle)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 255); // uint8 (2bytes)

    std::size_t off = 0;

    try {
        msgpack::object_handle oh(msgpack::unpack(sbuf.data(), 1, off));
        EXPECT_TRUE(false);
    }
    catch (msgpack::insufficient_bytes const&) {
        EXPECT_TRUE(true);
        EXPECT_EQ(off, 0u);
    }
}

TEST(unpack, insufficient_bytes_zone)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 255); // uint8 (2bytes)

    std::size_t off = 0;

    try {
        msgpack::zone z;
        msgpack::unpack(z, sbuf.data(), 1, off);
        EXPECT_TRUE(false);
    }
    catch (msgpack::insufficient_bytes const&) {
        EXPECT_TRUE(true);
        EXPECT_EQ(off, 0u);
    }
}

TEST(unpack, parse_error)
{
    msgpack::sbuffer sbuf;

    char c = '\xc1';
    sbuf.write(&c, 1);

    bool thrown = false;
    msgpack::object_handle oh;
    try {
        msgpack::unpack(oh, sbuf.data(), sbuf.size());
        EXPECT_TRUE(false);
    }
    catch (msgpack::parse_error const&) {
        thrown = true;
    }
    EXPECT_TRUE(thrown);
}

TEST(unpack, returned_parse_error)
{
    msgpack::sbuffer sbuf;

    char c = '\xc1';
    sbuf.write(&c, 1);

    bool thrown = false;
    try {
        msgpack::unpack(sbuf.data(), sbuf.size());
        EXPECT_TRUE(false);
    }
    catch (msgpack::parse_error const&) {
        thrown = true;
    }
    EXPECT_TRUE(thrown);
}

TEST(unpack, zone_parse_error)
{
    msgpack::sbuffer sbuf;

    char c = '\xc1';
    sbuf.write(&c, 1);

    bool thrown = false;
    msgpack::zone z;
    try {
        msgpack::unpack(z, sbuf.data(), sbuf.size());
        EXPECT_TRUE(false);
    }
    catch (msgpack::parse_error const&) {
        thrown = true;
    }
    EXPECT_TRUE(thrown);
}

TEST(unpack, extra_bytes)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);

    msgpack::object_handle oh = msgpack::unpack(sbuf.data(), sbuf.size() + 1);
    EXPECT_EQ(1, oh.get().as<int>());
}

TEST(unpack, zone_extra_bytes)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);

    msgpack::zone z;
    msgpack::object obj = msgpack::unpack(z, sbuf.data(), sbuf.size() + 1);
    EXPECT_EQ(1, obj.as<int>());
}

TEST(unpack, int_off_larger_than_length)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);

    std::size_t off = 2;

    bool thrown = false;
    try {
        msgpack::object_handle oh = msgpack::unpack(sbuf.data(), sbuf.size(), off);
    }
    catch (msgpack::insufficient_bytes const&) {
        thrown = true;
    }
    EXPECT_TRUE(thrown);
    EXPECT_EQ(off, 2u);
}
