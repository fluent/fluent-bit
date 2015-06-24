#include <msgpack.hpp>
#include <gtest/gtest.h>

template <typename T>
void check_size(size_t size) {
    T v(0);
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, v);
    EXPECT_EQ(size, sbuf.size());
}

TEST(fixint, size)
{
    check_size<msgpack::type::fix_int8>(2);
    check_size<msgpack::type::fix_int16>(3);
    check_size<msgpack::type::fix_int32>(5);
    check_size<msgpack::type::fix_int64>(9);

    check_size<msgpack::type::fix_uint8>(2);
    check_size<msgpack::type::fix_uint16>(3);
    check_size<msgpack::type::fix_uint32>(5);
    check_size<msgpack::type::fix_uint64>(9);
}


template <typename T>
void check_convert() {
    T v1(-11);
    msgpack::sbuffer sbuf;
    msgpack::pack(sbuf, v1);

    msgpack::unpacked msg;
    msgpack::unpack(&msg, sbuf.data(), sbuf.size());

    T v2;
    msg.get().convert(&v2);

    EXPECT_EQ(v1.get(), v2.get());

    EXPECT_EQ(msg.get(), msgpack::object(T(v1.get())));
}

TEST(fixint, convert)
{
    check_convert<msgpack::type::fix_int8>();
    check_convert<msgpack::type::fix_int16>();
    check_convert<msgpack::type::fix_int32>();
    check_convert<msgpack::type::fix_int64>();

    check_convert<msgpack::type::fix_uint8>();
    check_convert<msgpack::type::fix_uint16>();
    check_convert<msgpack::type::fix_uint32>();
    check_convert<msgpack::type::fix_uint64>();
}

