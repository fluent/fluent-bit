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


#if !defined(MSGPACK_USE_CPP03)

TEST(unpack, int_ret_no_offset_no_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);

    msgpack::unpacked msg = msgpack::unpack(sbuf.data(), sbuf.size());
    EXPECT_EQ(1, msg.get().as<int>());
}

TEST(unpack, int_ret_offset_no_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);

    std::size_t off = 0;

    msgpack::unpacked msg = msgpack::unpack(sbuf.data(), sbuf.size(), off);
    EXPECT_EQ(1, msg.get().as<int>());
    EXPECT_EQ(off, sbuf.size());
}

TEST(unpack, int_ret_no_offset_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    bool referenced;

    msgpack::unpacked msg = msgpack::unpack(sbuf.data(), sbuf.size(), referenced);
    EXPECT_EQ(1, msg.get().as<int>());
    EXPECT_EQ(false, referenced);
}

TEST(unpack, int_ret_offset_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    std::size_t off = 0;
    bool referenced;

    msgpack::unpacked msg = msgpack::unpack(sbuf.data(), sbuf.size(), off, referenced);
    EXPECT_EQ(1, msg.get().as<int>());
    EXPECT_EQ(false, referenced);
    EXPECT_EQ(off, sbuf.size());
}

#endif // !defined(MSGPACK_USE_CPP03)


TEST(unpack, int_no_offset_no_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::unpacked msg;

    msgpack::unpack(msg, sbuf.data(), sbuf.size());
    EXPECT_EQ(1, msg.get().as<int>());
}

TEST(unpack, int_offset_no_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::unpacked msg;

    std::size_t off = 0;

    msgpack::unpack(msg, sbuf.data(), sbuf.size(), off);
    EXPECT_EQ(1, msg.get().as<int>());
    EXPECT_EQ(off, sbuf.size());
}

TEST(unpack, int_no_offset_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::unpacked msg;
    bool referenced;

    msgpack::unpack(msg, sbuf.data(), sbuf.size(), referenced);
    EXPECT_EQ(1, msg.get().as<int>());
    EXPECT_EQ(false, referenced);
}

TEST(unpack, int_offset_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::unpacked msg;
    std::size_t off = 0;
    bool referenced;

    msgpack::unpack(msg, sbuf.data(), sbuf.size(), off, referenced);
    EXPECT_EQ(1, msg.get().as<int>());
    EXPECT_EQ(false, referenced);
    EXPECT_EQ(off, sbuf.size());
}


TEST(unpack, int_pointer_off_no_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::unpacked msg;

    std::size_t off = 0;

    // obsolete
    msgpack::unpack(&msg, sbuf.data(), sbuf.size(), &off);
    EXPECT_EQ(1, msg.get().as<int>());
    EXPECT_EQ(off, sbuf.size());
}

TEST(unpack, int_pointer_off_no_ref_explicit)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::unpacked msg;

    std::size_t off = 0;

    // obsolete
    msgpack::unpack(&msg, sbuf.data(), sbuf.size(), &off, nullptr);
    EXPECT_EQ(1, msg.get().as<int>());
    EXPECT_EQ(off, sbuf.size());
}

TEST(unpack, int_pointer_no_off_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::unpacked msg;
    bool referenced;

    // obsolete
    msgpack::unpack(&msg, sbuf.data(), sbuf.size(), nullptr, &referenced);
    EXPECT_EQ(1, msg.get().as<int>());
    EXPECT_EQ(false, referenced);
}

TEST(unpack, int_pointer_off_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::unpacked msg;
    bool referenced;
    std::size_t off = 0;

    // obsolete
    msgpack::unpack(&msg, sbuf.data(), sbuf.size(), &off, &referenced);
    EXPECT_EQ(1, msg.get().as<int>());
    EXPECT_EQ(off, sbuf.size());
    EXPECT_EQ(false, referenced);
}


TEST(unpack, int_default_null_pointer)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::unpacked msg;

    // obsolete
    msgpack::unpack(&msg, sbuf.data(), sbuf.size());
    EXPECT_EQ(1, msg.get().as<int>());
}

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
    EXPECT_EQ(false, referenced);
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
    EXPECT_EQ(false, referenced);
    EXPECT_EQ(off, sbuf.size());
}


TEST(unpack, sequence)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::pack(sbuf, 2);
    msgpack::pack(sbuf, 3);

    std::size_t off = 0;

    msgpack::unpacked msg;

    msgpack::unpack(msg, sbuf.data(), sbuf.size(), off);
    EXPECT_EQ(1, msg.get().as<int>());

    msgpack::unpack(msg, sbuf.data(), sbuf.size(), off);
    EXPECT_EQ(2, msg.get().as<int>());

    msgpack::unpack(msg, sbuf.data(), sbuf.size(), off);
    EXPECT_EQ(3, msg.get().as<int>());

    EXPECT_EQ(off, sbuf.size());
}
