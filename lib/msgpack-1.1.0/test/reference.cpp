#include <msgpack.hpp>
#include <gtest/gtest.h>

TEST(reference, unpack_int)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::unpacked ret;
    bool referenced;

    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced);
    EXPECT_FALSE(referenced);
}

TEST(reference, unpack_string)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, std::string("abcdefg"));
    msgpack::unpacked ret;
    bool referenced;

    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced);
    EXPECT_FALSE(referenced);
}

TEST(reference, unpack_bin)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char c[] = { 1, 2, 3, 4, 5, 6 };
    packer.pack_bin(sizeof(c));
    packer.pack_bin_body(c, sizeof(c));

    msgpack::unpacked ret;
    bool referenced;
    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced);
    EXPECT_FALSE(referenced);
}

TEST(reference, unpack_ext)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char const buf [] = { 2 };

    packer.pack_ext(sizeof(buf), 1);
    packer.pack_ext_body(buf, sizeof(buf));
    msgpack::unpacked ret;
    bool referenced;
    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced);
    EXPECT_FALSE(referenced);
}

bool never_called(msgpack::type::object_type, std::size_t, void*)
{
    EXPECT_TRUE(false);
    return false;
}

bool always_reference(msgpack::type::object_type, std::size_t, void*)
{
    return true;
}

TEST(reference, unpack_int_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);
    msgpack::unpacked ret;
    bool referenced;

    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced, never_called);
    EXPECT_FALSE(referenced);
}

TEST(reference, unpack_string_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, std::string("abcdefg"));
    msgpack::unpacked ret;
    bool referenced;


    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced, always_reference);
    EXPECT_TRUE(referenced);
}

TEST(reference, unpack_bin_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char c[] = { 1, 2, 3, 4, 5, 6 };
    packer.pack_bin(sizeof(c));
    packer.pack_bin_body(c, sizeof(c));

    msgpack::unpacked ret;
    bool referenced;
    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced, always_reference);
    EXPECT_TRUE(referenced);
}

TEST(reference, unpack_ext_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char const buf [] = { 2 };

    packer.pack_ext(sizeof(buf), 1);
    packer.pack_ext_body(buf, sizeof(buf));
    msgpack::unpacked ret;
    bool referenced;
    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced, always_reference);
    EXPECT_TRUE(referenced);
}

static void* s_p;

bool sized_reference(msgpack::type::object_type t, std::size_t s, void* p)
{
    s_p = p;
    switch (t) {
    case msgpack::type::STR:
        if (s >= 5) return true;
        break;
    case msgpack::type::BIN:
        if (s >= 6) return true;
        break;
    case msgpack::type::EXT:
        if (s >= 7) return true;
        break;
    default:
        EXPECT_TRUE(false);
    }
    return false;
}

TEST(reference, unpack_int_sized_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);

    msgpack::unpacked ret;
    bool referenced;
    s_p = nullptr;
    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced, never_called, &sbuf);
    EXPECT_FALSE(referenced);
    EXPECT_EQ(nullptr, s_p);
}

TEST(reference, unpack_string_sized_ref_4)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, std::string("1234"));

    msgpack::unpacked ret;
    bool referenced;
    s_p = nullptr;
    // the last argument sbuf is any pointer as a user data.
    // That is stored to s_p in sized_reference
    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced, sized_reference, &sbuf);
    EXPECT_FALSE(referenced);
    // compare the passed argument with stored s_p.
    EXPECT_EQ(&sbuf, s_p);
}

TEST(reference, unpack_string_sized_ref_5)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, std::string("12345"));

    msgpack::unpacked ret;
    bool referenced;
    s_p = nullptr;
    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced, sized_reference, &sbuf);
    EXPECT_TRUE(referenced);
    EXPECT_EQ(&sbuf, s_p);
}


TEST(reference, unpack_bin_sized_ref_5)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char c[] = { 1, 2, 3, 4, 5 };
    packer.pack_bin(sizeof(c));
    packer.pack_bin_body(c, sizeof(c));

    msgpack::unpacked ret;
    bool referenced;
    s_p = nullptr;
    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced, sized_reference, &sbuf);
    EXPECT_FALSE(referenced);
    EXPECT_EQ(&sbuf, s_p);
}

TEST(reference, unpack_bin_sized_ref_6)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char c[] = { 1, 2, 3, 4, 5, 6 };
    packer.pack_bin(sizeof(c));
    packer.pack_bin_body(c, sizeof(c));

    msgpack::unpacked ret;
    bool referenced;
    s_p = nullptr;
    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced, sized_reference, &sbuf);
    EXPECT_TRUE(referenced);
    EXPECT_EQ(&sbuf, s_p);
}

TEST(reference, unpack_ext_sized_ref_6)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char const buf [] = { 1, 2, 3, 4, 5 };

    packer.pack_ext(sizeof(buf), 1); // 5 + 1(type) = 6
    packer.pack_ext_body(buf, sizeof(buf));

    msgpack::unpacked ret;
    bool referenced;
    s_p = nullptr;
    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced, sized_reference, &sbuf);
    EXPECT_FALSE(referenced);
    EXPECT_EQ(&sbuf, s_p);
}

TEST(reference, unpack_ext_sized_ref_7)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char const buf [] = { 1, 2, 3, 4, 5, 6 };

    packer.pack_ext(sizeof(buf), 1); // 6 + 1(type) = 7
    packer.pack_ext_body(buf, sizeof(buf));

    msgpack::unpacked ret;
    bool referenced;
    s_p = nullptr;
    msgpack::unpack(ret, sbuf.data(), sbuf.size(), referenced, sized_reference, &sbuf);
    EXPECT_TRUE(referenced);
    EXPECT_EQ(&sbuf, s_p);
}

// default reference function
// STR, BIN, and EXT are always referenced, otherwise copied (converted).

TEST(reference, unpacker_int)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);

    msgpack::unpacker unp;
    msgpack::unpacked ret;
    bool referenced;
    unp.reserve_buffer(sbuf.size());
    std::memcpy(unp.buffer(), sbuf.data(), sbuf.size());
    unp.buffer_consumed(sbuf.size());
    bool b = unp.next(ret, referenced);
    EXPECT_TRUE(b);
    EXPECT_FALSE(referenced);
}

TEST(reference, unpacker_string)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, std::string("a"));

    msgpack::unpacker unp;
    msgpack::unpacked ret;
    bool referenced;
    unp.reserve_buffer(sbuf.size());
    std::memcpy(unp.buffer(), sbuf.data(), sbuf.size());
    unp.buffer_consumed(sbuf.size());
    bool b = unp.next(ret, referenced);
    EXPECT_TRUE(b);
    EXPECT_TRUE(referenced);
}

TEST(reference, unpacker_bin)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char c[] = { 1 };
    packer.pack_bin(sizeof(c));
    packer.pack_bin_body(c, sizeof(c));

    msgpack::unpacker unp;
    msgpack::unpacked ret;
    bool referenced;
    unp.reserve_buffer(sbuf.size());
    std::memcpy(unp.buffer(), sbuf.data(), sbuf.size());
    unp.buffer_consumed(sbuf.size());
    bool b = unp.next(ret, referenced);
    EXPECT_TRUE(b);
    EXPECT_TRUE(referenced);
}

TEST(reference, unpacker_ext)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char const buf [] = { 2 };

    packer.pack_ext(sizeof(buf), 1);
    packer.pack_ext_body(buf, sizeof(buf));

    msgpack::unpacker unp;
    msgpack::unpacked ret;
    bool referenced;
    unp.reserve_buffer(sbuf.size());
    std::memcpy(unp.buffer(), sbuf.data(), sbuf.size());
    unp.buffer_consumed(sbuf.size());
    bool b = unp.next(ret, referenced);
    EXPECT_TRUE(b);
    EXPECT_TRUE(referenced);
}

// pass user custom reference function

TEST(reference, unpacker_int_sized_ref)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, 1);

    msgpack::unpacker unp(never_called, &sbuf);
    msgpack::unpacked ret;
    bool referenced;
    unp.reserve_buffer(sbuf.size());
    std::memcpy(unp.buffer(), sbuf.data(), sbuf.size());
    unp.buffer_consumed(sbuf.size());
    s_p = nullptr;
    bool b = unp.next(ret, referenced);
    EXPECT_TRUE(b);
    EXPECT_FALSE(referenced);
    EXPECT_EQ(nullptr, s_p);
}

TEST(reference, unpacker_string_sized_ref_4)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, std::string("1234"));

    msgpack::unpacker unp(sized_reference, &sbuf);
    msgpack::unpacked ret;
    bool referenced;
    unp.reserve_buffer(sbuf.size());
    std::memcpy(unp.buffer(), sbuf.data(), sbuf.size());
    unp.buffer_consumed(sbuf.size());
    s_p = nullptr;
    bool b = unp.next(ret, referenced);
    EXPECT_TRUE(b);
    EXPECT_FALSE(referenced);
    EXPECT_EQ(&sbuf, s_p);
}

TEST(reference, unpacker_string_sized_ref_5)
{
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, std::string("12345"));

    msgpack::unpacker unp(sized_reference, &sbuf);
    msgpack::unpacked ret;
    bool referenced;
    unp.reserve_buffer(sbuf.size());
    std::memcpy(unp.buffer(), sbuf.data(), sbuf.size());
    unp.buffer_consumed(sbuf.size());
    s_p = nullptr;
    bool b = unp.next(ret, referenced);
    EXPECT_TRUE(b);
    EXPECT_TRUE(referenced);
    EXPECT_EQ(&sbuf, s_p);
}


TEST(reference, unpacker_bin_sized_ref_5)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char c[] = { 1, 2, 3, 4, 5 };
    packer.pack_bin(sizeof(c));
    packer.pack_bin_body(c, sizeof(c));

    msgpack::unpacker unp(sized_reference, &sbuf);
    msgpack::unpacked ret;
    bool referenced;
    unp.reserve_buffer(sbuf.size());
    std::memcpy(unp.buffer(), sbuf.data(), sbuf.size());
    unp.buffer_consumed(sbuf.size());
    s_p = nullptr;
    bool b = unp.next(ret, referenced);
    EXPECT_TRUE(b);
    EXPECT_FALSE(referenced);
    EXPECT_EQ(&sbuf, s_p);
}

TEST(reference, unpacker_bin_sized_ref_6)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char c[] = { 1, 2, 3, 4, 5, 6 };
    packer.pack_bin(sizeof(c));
    packer.pack_bin_body(c, sizeof(c));

    msgpack::unpacker unp(sized_reference, &sbuf);
    msgpack::unpacked ret;
    bool referenced;
    unp.reserve_buffer(sbuf.size());
    std::memcpy(unp.buffer(), sbuf.data(), sbuf.size());
    unp.buffer_consumed(sbuf.size());
    s_p = nullptr;
    bool b = unp.next(ret, referenced);
    EXPECT_TRUE(b);
    EXPECT_TRUE(referenced);
    EXPECT_EQ(&sbuf, s_p);
}

TEST(reference, unpacker_ext_sized_ref_6)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char const buf [] = { 1, 2, 3, 4, 5 };

    packer.pack_ext(sizeof(buf), 1); // 5 + 1(type) = 6
    packer.pack_ext_body(buf, sizeof(buf));

    msgpack::unpacker unp(sized_reference, &sbuf);
    msgpack::unpacked ret;
    bool referenced;
    unp.reserve_buffer(sbuf.size());
    std::memcpy(unp.buffer(), sbuf.data(), sbuf.size());
    unp.buffer_consumed(sbuf.size());
    s_p = nullptr;
    bool b = unp.next(ret, referenced);
    EXPECT_TRUE(b);
    EXPECT_FALSE(referenced);
    EXPECT_EQ(&sbuf, s_p);
}

TEST(reference, unpacker_ext_sized_ref_7)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char const buf [] = { 1, 2, 3, 4, 5, 6 };

    packer.pack_ext(sizeof(buf), 1); // 6 + 1(type) = 7
    packer.pack_ext_body(buf, sizeof(buf));

    msgpack::unpacker unp(sized_reference, &sbuf);
    msgpack::unpacked ret;
    bool referenced;
    unp.reserve_buffer(sbuf.size());
    std::memcpy(unp.buffer(), sbuf.data(), sbuf.size());
    unp.buffer_consumed(sbuf.size());
    s_p = nullptr;
    bool b = unp.next(ret, referenced);
    EXPECT_TRUE(b);
    EXPECT_TRUE(referenced);
    EXPECT_EQ(&sbuf, s_p);
}
