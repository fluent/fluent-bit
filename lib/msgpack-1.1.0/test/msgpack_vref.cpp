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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

using namespace std;

#define GEN_TEST_VREF(test_type, vbuf)                                  \
  do {                                                                  \
    vector<test_type> v;                                                \
    v.push_back(0);                                                     \
    for (unsigned int i = 0; i < v.size(); i++) {                       \
      test_type val1 = v[i];                                            \
      msgpack::pack(vbuf, val1);                                        \
      msgpack::sbuffer sbuf;                                            \
      const struct iovec* cur = vbuf.vector();                          \
      const struct iovec* end = cur + vbuf.vector_size();               \
      for(; cur != end; ++cur)                                          \
        sbuf.write((const char*)cur->iov_base, cur->iov_len);           \
      msgpack::unpacked ret;                                            \
      msgpack::unpack(ret, sbuf.data(), sbuf.size());                   \
      test_type val2 = ret.get().as<test_type>();                       \
      EXPECT_EQ(val1, val2);                                            \
    }                                                                   \
  } while(0);

TEST(MSGPACK, vrefbuffer_char)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(char, vbuf);
}

TEST(MSGPACK, vrefbuffer_signed_char)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(signed char, vbuf);
}

TEST(MSGPACK, vrefbuffer_unsigned_char)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(unsigned char, vbuf);
}

TEST(MSGPACK, vrefbuffer_short)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(short, vbuf);
}

TEST(MSGPACK, vrefbuffer_int)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(int, vbuf);
}

TEST(MSGPACK, vrefbuffer_long)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(long, vbuf);
}

TEST(MSGPACK, vrefbuffer_long_long)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(long long, vbuf);
}

TEST(MSGPACK, vrefbuffer_unsigned_short)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(unsigned short, vbuf);
}

TEST(MSGPACK, vrefbuffer_unsigned_int)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(unsigned int, vbuf);
}

TEST(MSGPACK, vrefbuffer_unsigned_long)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(unsigned long, vbuf);
}

TEST(MSGPACK, vrefbuffer_unsigned_long_long)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(unsigned long long, vbuf);
}

TEST(MSGPACK, vrefbuffer_uint8)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(uint8_t, vbuf);
}

TEST(MSGPACK, vrefbuffer_uint16)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(uint16_t, vbuf);
}

TEST(MSGPACK, vrefbuffer_uint32)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(uint32_t, vbuf);
}

TEST(MSGPACK, vrefbuffer_uint64)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(uint64_t, vbuf);
}

TEST(MSGPACK, vrefbuffer_int8)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(int8_t, vbuf);
}

TEST(MSGPACK, vrefbuffer_int16)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(int16_t, vbuf);
}

TEST(MSGPACK, vrefbuffer_int32)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(int32_t, vbuf);
}

TEST(MSGPACK, vrefbuffer_int64)
{
  msgpack::vrefbuffer vbuf;
  GEN_TEST_VREF(int64_t, vbuf);
}

// small ref_size and chunk_size
TEST(MSGPACK, vrefbuffer_small_char)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(char, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_signed_char)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(signed char, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_unsigned_char)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(unsigned char, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_short)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(short, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_int)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(int, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_long)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(long, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_long_long)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(long long, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_unsigned_short)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(unsigned short, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_unsigned_int)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(unsigned int, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_unsigned_long)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(unsigned long, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_unsigned_long_long)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(unsigned long long, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_uint8)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(uint8_t, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_uint16)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(uint16_t, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_uint32)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(uint32_t, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_uint64)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(uint64_t, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_int8)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(int8_t, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_int16)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(int16_t, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_int32)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(int32_t, vbuf);
}

TEST(MSGPACK, vrefbuffer_small_int64)
{
  msgpack::vrefbuffer vbuf(0, 0);
  GEN_TEST_VREF(int64_t, vbuf);
}
