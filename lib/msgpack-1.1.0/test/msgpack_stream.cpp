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

const unsigned int kLoop = 1000;


#define GEN_TEST_STREAM(test_type)                                      \
  for (unsigned int k = 0; k < kLoop; k++) {                            \
    msgpack::sbuffer sbuf;                                              \
    msgpack::packer<msgpack::sbuffer> pk(sbuf);                         \
    typedef std::vector<test_type> vec_type;                            \
    vec_type vec;                                                       \
    for(unsigned int i = 0; i < rand() % kLoop; ++i) {                  \
      vec_type::value_type r = rand();                                  \
      vec.push_back(r);                                                 \
      pk.pack(r);                                                       \
    }                                                                   \
    msgpack::unpacker pac;                                              \
    vec_type::const_iterator it = vec.begin();                          \
    const char *p = sbuf.data();                                        \
    const char * const pend = p + sbuf.size();                          \
    while (p < pend) {                                                  \
      const size_t sz = std::min<size_t>(pend - p, rand() % 128);       \
      pac.reserve_buffer(sz);                                           \
      memcpy(pac.buffer(), p, sz);                                      \
      pac.buffer_consumed(sz);                                          \
      msgpack::unpacked result;                                         \
      while (pac.next(result)) {                                        \
        if (it == vec.end()) goto out;                                  \
        msgpack::object obj = result.get();                             \
        vec_type::value_type val;                                       \
        obj.convert(&val);                                              \
        EXPECT_EQ(*it, val);                                            \
        ++it;                                                           \
      }                                                                 \
      p += sz;                                                          \
    }                                                                   \
  out:                                                                  \
    ;                                                                   \
  }

TEST(MSGPACK, stream_char)
{
  GEN_TEST_STREAM(char);
}

TEST(MSGPACK, stream_signed_char)
{
  GEN_TEST_STREAM(signed char);
}

TEST(MSGPACK, stream_unsigned_char)
{
  GEN_TEST_STREAM(unsigned char);
}

TEST(MSGPACK, stream_short)
{
  GEN_TEST_STREAM(short);
}

TEST(MSGPACK, stream_int)
{
  GEN_TEST_STREAM(int);
}

TEST(MSGPACK, stream_long)
{
  GEN_TEST_STREAM(long);
}

TEST(MSGPACK, stream_long_long)
{
  GEN_TEST_STREAM(long long);
}

TEST(MSGPACK, stream_unsigned_short)
{
  GEN_TEST_STREAM(unsigned short);
}

TEST(MSGPACK, stream_unsigned_int)
{
  GEN_TEST_STREAM(unsigned int);
}

TEST(MSGPACK, stream_unsigned_long)
{
  GEN_TEST_STREAM(unsigned long);
}

TEST(MSGPACK, stream_unsigned_long_long)
{
  GEN_TEST_STREAM(unsigned long long);
}

TEST(MSGPACK, stream_uint8)
{
  GEN_TEST_STREAM(uint8_t);
}

TEST(MSGPACK, stream_uint16)
{
  GEN_TEST_STREAM(uint16_t);
}

TEST(MSGPACK, stream_uint32)
{
  GEN_TEST_STREAM(uint32_t);
}

TEST(MSGPACK, stream_uint64)
{
  GEN_TEST_STREAM(uint64_t);
}

TEST(MSGPACK, stream_int8)
{
  GEN_TEST_STREAM(int8_t);
}

TEST(MSGPACK, stream_int16)
{
  GEN_TEST_STREAM(int16_t);
}

TEST(MSGPACK, stream_int32)
{
  GEN_TEST_STREAM(int32_t);
}

TEST(MSGPACK, stream_int64)
{
  GEN_TEST_STREAM(int64_t);
}
