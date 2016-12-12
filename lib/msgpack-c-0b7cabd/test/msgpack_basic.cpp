#include "msgpack.hpp"

#include <cmath>
#include <string>
#include <vector>
#include <map>
#include <deque>
#include <set>
#include <list>
#include <limits>

#include <gtest/gtest.h>

#if defined(_MSC_VER) || defined(__MINGW32__)
#define msgpack_rand() ((double)rand() / RAND_MAX)
#else  // _MSC_VER || __MINGW32__
#define msgpack_rand() drand48()
#endif // _MSC_VER || __MINGW32__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

using namespace std;

const unsigned int kLoop = 10000;
const unsigned int kElements = 100;
const double kEPS = 1e-10;

#define GEN_TEST(test_type)                                 \
    do {                                                    \
        vector<test_type> v;                                \
        v.push_back(0);                                     \
        v.push_back(1);                                     \
        v.push_back(2);                                     \
        v.push_back(numeric_limits<test_type>::min());      \
        v.push_back(numeric_limits<test_type>::max());      \
        for (unsigned int i = 0; i < kLoop; i++)            \
            v.push_back(rand());                            \
        for (unsigned int i = 0; i < v.size() ; i++) {      \
            msgpack::sbuffer sbuf;                          \
            test_type val1 = v[i];                          \
            msgpack::pack(sbuf, val1);                      \
            msgpack::object_handle oh =                     \
                msgpack::unpack(sbuf.data(), sbuf.size());  \
            EXPECT_EQ(val1, oh.get().as<test_type>());      \
        }                                                   \
    } while(0)

TEST(MSGPACK, simple_buffer_char)
{
    GEN_TEST(char);
}

TEST(MSGPACK, simple_buffer_signed_char)
{
    GEN_TEST(signed char);
}

TEST(MSGPACK, simple_buffer_unsigned_char)
{
    GEN_TEST(unsigned char);
}


TEST(MSGPACK, simple_buffer_short)
{
    GEN_TEST(short);
}

TEST(MSGPACK, simple_buffer_int)
{
    GEN_TEST(int);
}

TEST(MSGPACK, simple_buffer_long)
{
    GEN_TEST(long);
}

TEST(MSGPACK, simple_buffer_long_long)
{
    GEN_TEST(long long);
}

TEST(MSGPACK, simple_buffer_unsigned_short)
{
    GEN_TEST(unsigned short);
}

TEST(MSGPACK, simple_buffer_unsigned_int)
{
    GEN_TEST(unsigned int);
}

TEST(MSGPACK, simple_buffer_unsigned_long)
{
    GEN_TEST(unsigned long);
}

TEST(MSGPACK, simple_buffer_unsigned_long_long)
{
    GEN_TEST(unsigned long long);
}

TEST(MSGPACK, simple_buffer_uint8)
{
    GEN_TEST(uint8_t);
}

TEST(MSGPACK, simple_buffer_uint16)
{
    GEN_TEST(uint16_t);
}

TEST(MSGPACK, simple_buffer_uint32)
{
    GEN_TEST(uint32_t);
}

TEST(MSGPACK, simple_buffer_uint64)
{
    GEN_TEST(uint64_t);
}

TEST(MSGPACK, simple_buffer_int8)
{
    GEN_TEST(int8_t);
}

TEST(MSGPACK, simple_buffer_int16)
{
    GEN_TEST(int16_t);
}

TEST(MSGPACK, simple_buffer_int32)
{
    GEN_TEST(int32_t);
}

TEST(MSGPACK, simple_buffer_int64)
{
    GEN_TEST(int64_t);
}

#if !defined(_MSC_VER) || _MSC_VER >=1800

TEST(MSGPACK, simple_buffer_float)
{
    vector<float> v;
    v.push_back(0.0);
    v.push_back(-0.0);
    v.push_back(1.0);
    v.push_back(-1.0);
    v.push_back(numeric_limits<float>::min());
    v.push_back(numeric_limits<float>::max());
    v.push_back(nanf("tag"));
    if (numeric_limits<float>::has_infinity) {
        v.push_back(numeric_limits<float>::infinity());
        v.push_back(-numeric_limits<float>::infinity());
    }
    if (numeric_limits<float>::has_quiet_NaN) {
        v.push_back(numeric_limits<float>::quiet_NaN());
    }
    if (numeric_limits<float>::has_signaling_NaN) {
        v.push_back(numeric_limits<float>::signaling_NaN());
    }

    for (unsigned int i = 0; i < kLoop; i++) {
        v.push_back(static_cast<float>(msgpack_rand()));
        v.push_back(static_cast<float>(-msgpack_rand()));
    }
    for (unsigned int i = 0; i < v.size() ; i++) {
        msgpack::sbuffer sbuf;
        float val1 = v[i];
        msgpack::pack(sbuf, val1);
        msgpack::object_handle oh =
            msgpack::unpack(sbuf.data(), sbuf.size());
        float val2 = oh.get().as<float>();

        if (std::isnan(val1))
            EXPECT_TRUE(std::isnan(val2));
        else if (std::isinf(val1))
            EXPECT_TRUE(std::isinf(val2));
        else
            EXPECT_TRUE(fabs(val2 - val1) <= kEPS);
    }
}

#endif // !defined(_MSC_VER) || _MSC_VER >=1800

namespace {
template<typename F, typename I>
struct TypePair {
    typedef F float_type;
    typedef I integer_type;
};
} // namespace

template <typename T>
class IntegerToFloatingPointTest : public testing::Test {
};
TYPED_TEST_CASE_P(IntegerToFloatingPointTest);

TYPED_TEST_P(IntegerToFloatingPointTest, simple_buffer)
{
    typedef typename TypeParam::float_type float_type;
    typedef typename TypeParam::integer_type integer_type;
    vector<integer_type> v;
    v.push_back(0);
    v.push_back(1);
    if (numeric_limits<integer_type>::is_signed) v.push_back(-1);
    else v.push_back(2);
    for (unsigned int i = 0; i < kLoop; i++) {
        v.push_back(rand() % 0x7FFFFF);
    }
    for (unsigned int i = 0; i < v.size() ; i++) {
        msgpack::sbuffer sbuf;
        integer_type val1 = v[i];
        msgpack::pack(sbuf, val1);
        msgpack::object_handle oh =
            msgpack::unpack(sbuf.data(), sbuf.size());
        float_type val2 = oh.get().as<float_type>();
        EXPECT_TRUE(fabs(val2 - val1) <= kEPS);
    }
}

REGISTER_TYPED_TEST_CASE_P(IntegerToFloatingPointTest,
                           simple_buffer);

typedef testing::Types<TypePair<float, signed long long>,
                       TypePair<float, unsigned long long>,
                       TypePair<double, signed long long>,
                       TypePair<double, unsigned long long> > IntegerToFloatingPointTestTypes;
INSTANTIATE_TYPED_TEST_CASE_P(IntegerToFloatingPointTestInstance,
                              IntegerToFloatingPointTest,
                              IntegerToFloatingPointTestTypes);

#if !defined(_MSC_VER) || _MSC_VER >=1800

TEST(MSGPACK, simple_buffer_double)
{
    vector<double> v;
    v.push_back(0.0);
    v.push_back(-0.0);
    v.push_back(1.0);
    v.push_back(-1.0);
    v.push_back(numeric_limits<double>::min());
    v.push_back(numeric_limits<double>::max());
    v.push_back(nanf("tag"));
    if (numeric_limits<double>::has_infinity) {
        v.push_back(numeric_limits<double>::infinity());
        v.push_back(-numeric_limits<double>::infinity());
    }
    if (numeric_limits<double>::has_quiet_NaN) {
        v.push_back(numeric_limits<double>::quiet_NaN());
    }
    if (numeric_limits<double>::has_signaling_NaN) {
        v.push_back(numeric_limits<double>::signaling_NaN());
    }
    for (unsigned int i = 0; i < kLoop; i++) {
        v.push_back(msgpack_rand());
        v.push_back(-msgpack_rand());
    }

    for (unsigned int i = 0; i < kLoop; i++) {
        v.push_back(msgpack_rand());
        v.push_back(-msgpack_rand());
    }
    for (unsigned int i = 0; i < v.size() ; i++) {
        msgpack::sbuffer sbuf;
        double val1 = v[i];
        msgpack::pack(sbuf, val1);
        msgpack::object_handle oh =
            msgpack::unpack(sbuf.data(), sbuf.size());
        double val2 = oh.get().as<double>();

        if (std::isnan(val1))
            EXPECT_TRUE(std::isnan(val2));
        else if (std::isinf(val1))
            EXPECT_TRUE(std::isinf(val2));
        else
            EXPECT_TRUE(fabs(val2 - val1) <= kEPS);
    }
}

#endif // !defined(_MSC_VER) || _MSC_VER >=1800

TEST(MSGPACK, simple_buffer_nil)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    packer.pack_nil();
    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    EXPECT_EQ(oh.get().type, msgpack::type::NIL);
}

TEST(MSGPACK, simple_buffer_true)
{
    msgpack::sbuffer sbuf;
    bool val1 = true;
    msgpack::pack(sbuf, val1);
    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    bool val2 = oh.get().as<bool>();
    EXPECT_EQ(val1, val2);
}

TEST(MSGPACK, simple_buffer_false)
{
    msgpack::sbuffer sbuf;
    bool val1 = false;
    msgpack::pack(sbuf, val1);
    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    bool val2 = oh.get().as<bool>();
    EXPECT_EQ(val1, val2);
}

TEST(MSGPACK, simple_buffer_fixext1)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char const buf [] = { 2 };

    packer.pack_ext(sizeof(buf), 1);
    packer.pack_ext_body(buf, sizeof(buf));
    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    EXPECT_EQ(1ul, oh.get().via.ext.size);
    EXPECT_EQ(1, oh.get().via.ext.type());
    EXPECT_EQ(2, oh.get().via.ext.data()[0]);
}

TEST(MSGPACK, simple_buffer_fixext2)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char const buf [] = { 2, 3 };

    packer.pack_ext(sizeof(buf), 0);
    packer.pack_ext_body(buf, sizeof(buf));
    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    EXPECT_EQ(2ul, oh.get().via.ext.size);
    EXPECT_EQ(0, oh.get().via.ext.type());
    EXPECT_TRUE(
        std::equal(buf, buf + sizeof(buf), oh.get().via.ext.data()));
}

TEST(MSGPACK, simple_buffer_fixext4)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char const buf [] = { 2, 3, 4, 5 };

    packer.pack_ext(sizeof(buf), 1);
    packer.pack_ext_body(buf, sizeof(buf));
    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    EXPECT_EQ(4ul, oh.get().via.ext.size);
    EXPECT_EQ(1, oh.get().via.ext.type());
    EXPECT_TRUE(
        std::equal(buf, buf + sizeof(buf), oh.get().via.ext.data()));
}

TEST(MSGPACK, simple_buffer_fixext8)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char const buf [] = { 2, 3, 4, 5, 6, 7, 8, 9 };

    packer.pack_ext(sizeof(buf), 1);
    packer.pack_ext_body(buf, sizeof(buf));
    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    EXPECT_EQ(8ul, oh.get().via.ext.size);
    EXPECT_EQ(1, oh.get().via.ext.type());
    EXPECT_TRUE(
        std::equal(buf, buf + sizeof(buf), oh.get().via.ext.data()));
}

TEST(MSGPACK, simple_buffer_fixext16)
{
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char const buf [] = { 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };

    packer.pack_ext(sizeof(buf), 1);
    packer.pack_ext_body(buf, sizeof(buf));
    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    EXPECT_EQ(16ul, oh.get().via.ext.size);
    EXPECT_EQ(1, oh.get().via.ext.type());
    EXPECT_TRUE(
        std::equal(buf, buf + sizeof(buf), oh.get().via.ext.data()));
}

TEST(MSGPACK, simple_buffer_fixext_1byte_0)
{
    std::size_t const size = 0;
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);

    packer.pack_ext(size, 77);
    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    EXPECT_EQ(size, oh.get().via.ext.size);
    EXPECT_EQ(77, oh.get().via.ext.type());
}

TEST(MSGPACK, simple_buffer_fixext_1byte_255)
{
    std::size_t const size = 255;
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char buf[size];
    for (std::size_t i = 0; i != size; ++i) buf[i] = static_cast<char>(i);
    packer.pack_ext(sizeof(buf), 77);
    packer.pack_ext_body(buf, sizeof(buf));

    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    EXPECT_EQ(size, oh.get().via.ext.size);
    EXPECT_EQ(77, oh.get().via.ext.type());
    EXPECT_TRUE(
        std::equal(buf, buf + sizeof(buf), oh.get().via.ext.data()));
}

TEST(MSGPACK, simple_buffer_fixext_2byte_256)
{
    std::size_t const size = 256;
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char buf[size];
    for (std::size_t i = 0; i != size; ++i) buf[i] = static_cast<char>(i);
    packer.pack_ext(sizeof(buf), 77);
    packer.pack_ext_body(buf, sizeof(buf));

    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    EXPECT_EQ(size, oh.get().via.ext.size);
    EXPECT_EQ(77, oh.get().via.ext.type());
    EXPECT_TRUE(
        std::equal(buf, buf + sizeof(buf), oh.get().via.ext.data()));
}

TEST(MSGPACK, simple_buffer_fixext_2byte_65535)
{
    std::size_t const size = 65535;
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char buf[size];
    for (std::size_t i = 0; i != size; ++i) buf[i] = static_cast<char>(i);
    packer.pack_ext(sizeof(buf), 77);
    packer.pack_ext_body(buf, sizeof(buf));

    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    EXPECT_EQ(size, oh.get().via.ext.size);
    EXPECT_EQ(77, oh.get().via.ext.type());
    EXPECT_TRUE(
        std::equal(buf, buf + sizeof(buf), oh.get().via.ext.data()));
}

TEST(MSGPACK, simple_buffer_fixext_4byte_65536)
{
    std::size_t const size = 65536;
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char buf[size];
    for (std::size_t i = 0; i != size; ++i) buf[i] = static_cast<char>(i);
    packer.pack_ext(sizeof(buf), 77);
    packer.pack_ext_body(buf, sizeof(buf));

    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    EXPECT_EQ(size, oh.get().via.ext.size);
    EXPECT_EQ(77, oh.get().via.ext.type());
    EXPECT_TRUE(
        std::equal(buf, buf + sizeof(buf), oh.get().via.ext.data()));
}

TEST(MSGPACK, simple_buffer_ext_convert)
{
    std::size_t const size = 65536;
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char buf[size];
    for (std::size_t i = 0; i != size; ++i) buf[i] = static_cast<char>(i);
    packer.pack_ext(sizeof(buf), 77);
    packer.pack_ext_body(buf, sizeof(buf));

    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    msgpack::type::ext e;
    oh.get().convert(e);
    EXPECT_EQ(size, e.size());
    EXPECT_EQ(77, e.type());
    EXPECT_TRUE(
        std::equal(buf, buf + sizeof(buf), e.data()));
}

TEST(MSGPACK, simple_buffer_ext_pack_convert)
{
    std::size_t const size = 65536;
    msgpack::sbuffer sbuf;
    msgpack::type::ext val1(77, size);
    char* buf = val1.data();
    for (std::size_t i = 0; i != size; ++i) buf[i] = static_cast<char>(i);
    msgpack::pack(sbuf, val1);

    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    msgpack::type::ext val2;
    oh.get().convert(val2);
    EXPECT_EQ(size, val2.size());
    EXPECT_EQ(77, val2.type());
    EXPECT_TRUE(
        std::equal(buf, buf + sizeof(buf), val2.data()));
}

TEST(MSGPACK, simple_buffer_ext_ref_convert)
{
    std::size_t const size = 65536;
    msgpack::sbuffer sbuf;
    msgpack::packer<msgpack::sbuffer> packer(sbuf);
    char buf[size];
    for (std::size_t i = 0; i != size; ++i) buf[i] = static_cast<char>(i);
    packer.pack_ext(sizeof(buf), 77);
    packer.pack_ext_body(buf, sizeof(buf));

    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    msgpack::type::ext_ref er;
    oh.get().convert(er);
    EXPECT_EQ(size, er.size());
    EXPECT_EQ(77, er.type());
    EXPECT_TRUE(
        std::equal(buf, buf + sizeof(buf), er.data()));
}

TEST(MSGPACK, simple_buffer_ext_ref_pack_convert)
{
    std::size_t const buf_size = 65536;
    std::size_t const data_size = buf_size - 1;
    msgpack::sbuffer sbuf;
    char buf[buf_size];
    buf[0] = static_cast<char>(77);
    for (std::size_t i = 0; i != data_size; ++i) buf[i + 1] = static_cast<char>(i);
    msgpack::pack(sbuf, msgpack::type::ext_ref(buf, buf_size));

    msgpack::object_handle oh =
        msgpack::unpack(sbuf.data(), sbuf.size());
    msgpack::type::ext_ref val2;
    oh.get().convert(val2);
    EXPECT_EQ(data_size, val2.size());
    EXPECT_EQ(77, val2.type());
    EXPECT_TRUE(
        std::equal(&buf[1], &buf[buf_size], val2.data()));
}

TEST(MSGPACK_STL, simple_buffer_string)
{
    for (unsigned int k = 0; k < kLoop; k++) {
        string val1;
        for (unsigned int i = 0; i < kElements; i++)
            val1 += 'a' + rand() % 26;
        msgpack::sbuffer sbuf;
        msgpack::pack(sbuf, val1);
        msgpack::object_handle oh =
            msgpack::unpack(sbuf.data(), sbuf.size());
        EXPECT_EQ(oh.get().type, msgpack::type::STR);
        string val2 = oh.get().as<string>();
        EXPECT_EQ(val1.size(), val2.size());
        EXPECT_EQ(val1, val2);
    }
}

TEST(MSGPACK_STL, simple_buffer_cstring)
{
    for (unsigned int k = 0; k < kLoop; k++) {
        string val1;
        for (unsigned int i = 0; i < kElements; i++)
            val1 += 'a' + rand() % 26;
        msgpack::sbuffer sbuf;
        msgpack::pack(sbuf, val1.c_str());
        msgpack::object_handle oh =
            msgpack::unpack(sbuf.data(), sbuf.size());
        EXPECT_EQ(oh.get().type, msgpack::type::STR);
        string val2 = oh.get().as<string>();
        EXPECT_EQ(val1.size(), val2.size());
        EXPECT_EQ(val1, val2);
    }
}

TEST(MSGPACK_STL, simple_buffer_non_const_cstring)
{
    for (unsigned int k = 0; k < kLoop; k++) {
        string val1;
        for (unsigned int i = 0; i < kElements; i++)
            val1 += 'a' + rand() % 26;
        msgpack::sbuffer sbuf;
        char* s = new char[val1.size() + 1];
        std::memcpy(s, val1.c_str(), val1.size() + 1);
        msgpack::pack(sbuf, s);
        delete [] s;
        msgpack::object_handle oh =
            msgpack::unpack(sbuf.data(), sbuf.size());
        EXPECT_EQ(oh.get().type, msgpack::type::STR);
        string val2 = oh.get().as<string>();
        EXPECT_EQ(val1.size(), val2.size());
        EXPECT_EQ(val1, val2);
    }
}
