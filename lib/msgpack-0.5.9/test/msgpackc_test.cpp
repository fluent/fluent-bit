#include "msgpack.h"

#include <math.h>
#include <vector>
#include <limits>

#include <gtest/gtest.h>

using namespace std;

const unsigned int kLoop = 10000;
const double kEPS = 1e-10;

#define GEN_TEST_SIGNED(test_type, func_type)                   \
  do {                                                          \
    vector<test_type> v;                                        \
    v.push_back(0);                                             \
    v.push_back(1);                                             \
    v.push_back(-1);                                            \
    v.push_back(numeric_limits<test_type>::min());              \
    v.push_back(numeric_limits<test_type>::max());              \
    for (unsigned int i = 0; i < kLoop; i++)                    \
      v.push_back(rand());                                      \
    for (unsigned int i = 0; i < v.size() ; i++) {              \
      test_type val = v[i];                                     \
      msgpack_sbuffer sbuf;                                     \
      msgpack_sbuffer_init(&sbuf);                              \
      msgpack_packer pk;                                        \
      msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);   \
      msgpack_pack_##func_type(&pk, val);                       \
      msgpack_zone z;                                           \
      msgpack_zone_init(&z, 2048);                              \
      msgpack_object obj;                                       \
      msgpack_unpack_return ret =                               \
        msgpack_unpack(sbuf.data, sbuf.size, NULL, &z, &obj);   \
      EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);                   \
      if (val < 0) {                                            \
        EXPECT_EQ(MSGPACK_OBJECT_NEGATIVE_INTEGER, obj.type);   \
        EXPECT_EQ(val, obj.via.i64);                            \
      } else {                                                  \
        EXPECT_EQ(MSGPACK_OBJECT_POSITIVE_INTEGER, obj.type);   \
        EXPECT_EQ(val, obj.via.u64);                            \
      }                                                         \
      msgpack_zone_destroy(&z);                                 \
      msgpack_sbuffer_destroy(&sbuf);                           \
    }                                                           \
  } while(0)

#define GEN_TEST_UNSIGNED(test_type, func_type)                 \
  do {                                                          \
    vector<test_type> v;                                        \
    v.push_back(0);                                             \
    v.push_back(1);                                             \
    v.push_back(2);                                             \
    v.push_back(numeric_limits<test_type>::min());              \
    v.push_back(numeric_limits<test_type>::max());              \
    for (unsigned int i = 0; i < kLoop; i++)                    \
      v.push_back(rand());                                      \
    for (unsigned int i = 0; i < v.size() ; i++) {              \
      test_type val = v[i];                                     \
      msgpack_sbuffer sbuf;                                     \
      msgpack_sbuffer_init(&sbuf);                              \
      msgpack_packer pk;                                        \
      msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);   \
      msgpack_pack_##func_type(&pk, val);                       \
      msgpack_zone z;                                           \
      msgpack_zone_init(&z, 2048);                              \
      msgpack_object obj;                                       \
      msgpack_unpack_return ret =                               \
        msgpack_unpack(sbuf.data, sbuf.size, NULL, &z, &obj);   \
      EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);                   \
      EXPECT_EQ(MSGPACK_OBJECT_POSITIVE_INTEGER, obj.type);     \
      EXPECT_EQ(val, obj.via.u64);                              \
      msgpack_zone_destroy(&z);                                 \
      msgpack_sbuffer_destroy(&sbuf);                           \
    }                                                           \
  } while(0)

TEST(MSGPACKC, simple_buffer_char)
{
#if defined(CHAR_MIN)
#if CHAR_MIN < 0
	GEN_TEST_SIGNED(char, char);
#else
	GEN_TEST_UNSIGNED(char, char);
#endif
#else
#error CHAR_MIN is not defined
#endif
}

TEST(MSGPACKC, simple_buffer_singed_char)
{
  GEN_TEST_SIGNED(signed char, signed_char);
}

TEST(MSGPACKC, simple_buffer_short)
{
  GEN_TEST_SIGNED(short, short);
}

TEST(MSGPACKC, simple_buffer_int)
{
  GEN_TEST_SIGNED(int, int);
}

TEST(MSGPACKC, simple_buffer_long)
{
  GEN_TEST_SIGNED(long, long);
}

TEST(MSGPACKC, simple_buffer_long_long)
{
  GEN_TEST_SIGNED(long long, long_long);
}

TEST(MSGPACKC, simple_buffer_unsigned_char)
{
  GEN_TEST_UNSIGNED(unsigned char, unsigned_char);
}

TEST(MSGPACKC, simple_buffer_unsigned_short)
{
  GEN_TEST_UNSIGNED(unsigned short, unsigned_short);
}

TEST(MSGPACKC, simple_buffer_unsigned_int)
{
  GEN_TEST_UNSIGNED(unsigned int, unsigned_int);
}

TEST(MSGPACKC, simple_buffer_unsigned_long)
{
  GEN_TEST_UNSIGNED(unsigned long, unsigned_long);
}

TEST(MSGPACKC, simple_buffer_unsigned_long_long)
{
  GEN_TEST_UNSIGNED(unsigned long long, unsigned_long_long);
}

TEST(MSGPACKC, simple_buffer_uint8)
{
  GEN_TEST_UNSIGNED(uint8_t, uint8);
}

TEST(MSGPACKC, simple_buffer_uint16)
{
  GEN_TEST_UNSIGNED(uint16_t, uint16);
}

TEST(MSGPACKC, simple_buffer_uint32)
{
  GEN_TEST_UNSIGNED(uint32_t, uint32);
}

TEST(MSGPACKC, simple_buffer_uint64)
{
  GEN_TEST_UNSIGNED(uint64_t, uint64);
}

TEST(MSGPACKC, simple_buffer_int8)
{
  GEN_TEST_SIGNED(int8_t, int8);
}

TEST(MSGPACKC, simple_buffer_int16)
{
  GEN_TEST_SIGNED(int16_t, int16);
}

TEST(MSGPACKC, simple_buffer_int32)
{
  GEN_TEST_SIGNED(int32_t, int32);
}

TEST(MSGPACKC, simple_buffer_int64)
{
  GEN_TEST_SIGNED(int64_t, int64);
}

TEST(MSGPACKC, simple_buffer_float)
{
  vector<float> v;
  v.push_back(0.0);
  v.push_back(1.0);
  v.push_back(-1.0);
  v.push_back(numeric_limits<float>::min());
  v.push_back(numeric_limits<float>::max());
  v.push_back(nanf("tag"));
  v.push_back(1.0/0.0); // inf
  v.push_back(-(1.0/0.0)); // -inf
  for (unsigned int i = 0; i < kLoop; i++) {
    v.push_back(drand48());
    v.push_back(-drand48());
  }

  for (unsigned int i = 0; i < v.size() ; i++) {
    float val = v[i];
    msgpack_sbuffer sbuf;
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_float(&pk, val);
    msgpack_zone z;
    msgpack_zone_init(&z, 2048);
    msgpack_object obj;
    msgpack_unpack_return ret =
      msgpack_unpack(sbuf.data, sbuf.size, NULL, &z, &obj);
    EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);
    EXPECT_EQ(MSGPACK_OBJECT_DOUBLE, obj.type);
    if (isnan(val))
      EXPECT_TRUE(isnan(obj.via.dec));
    else if (isinf(val))
      EXPECT_TRUE(isinf(obj.via.dec));
    else
      EXPECT_TRUE(fabs(obj.via.dec - val) <= kEPS);
    msgpack_zone_destroy(&z);
    msgpack_sbuffer_destroy(&sbuf);
  }
}

TEST(MSGPACKC, simple_buffer_double)
{
  vector<double> v;
  v.push_back(0.0);
  v.push_back(-0.0);
  v.push_back(1.0);
  v.push_back(-1.0);
  v.push_back(numeric_limits<double>::min());
  v.push_back(numeric_limits<double>::max());
  v.push_back(nan("tag"));
  v.push_back(1.0/0.0); // inf
  v.push_back(-(1.0/0.0)); // -inf
  for (unsigned int i = 0; i < kLoop; i++) {
    v.push_back(drand48());
    v.push_back(-drand48());
  }

  for (unsigned int i = 0; i < v.size() ; i++) {
    double val = v[i];
    msgpack_sbuffer sbuf;
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer pk;
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_double(&pk, val);
    msgpack_zone z;
    msgpack_zone_init(&z, 2048);
    msgpack_object obj;
    msgpack_unpack_return ret =
      msgpack_unpack(sbuf.data, sbuf.size, NULL, &z, &obj);
    EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);
    EXPECT_EQ(MSGPACK_OBJECT_DOUBLE, obj.type);
    if (isnan(val))
      EXPECT_TRUE(isnan(obj.via.dec));
    else if (isinf(val))
      EXPECT_TRUE(isinf(obj.via.dec));
    else
      EXPECT_TRUE(fabs(obj.via.dec - val) <= kEPS);
    msgpack_zone_destroy(&z);
    msgpack_sbuffer_destroy(&sbuf);
  }
}

TEST(MSGPACKC, simple_buffer_nil)
{
  msgpack_sbuffer sbuf;
  msgpack_sbuffer_init(&sbuf);
  msgpack_packer pk;
  msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
  msgpack_pack_nil(&pk);
  msgpack_zone z;
  msgpack_zone_init(&z, 2048);
  msgpack_object obj;
  msgpack_unpack_return ret =
    msgpack_unpack(sbuf.data, sbuf.size, NULL, &z, &obj);
  EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);
  EXPECT_EQ(MSGPACK_OBJECT_NIL, obj.type);
  msgpack_zone_destroy(&z);
  msgpack_sbuffer_destroy(&sbuf);
}

TEST(MSGPACKC, simple_buffer_true)
{
  msgpack_sbuffer sbuf;
  msgpack_sbuffer_init(&sbuf);
  msgpack_packer pk;
  msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
  msgpack_pack_true(&pk);
  msgpack_zone z;
  msgpack_zone_init(&z, 2048);
  msgpack_object obj;
  msgpack_unpack_return ret =
    msgpack_unpack(sbuf.data, sbuf.size, NULL, &z, &obj);
  EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);
  EXPECT_EQ(MSGPACK_OBJECT_BOOLEAN, obj.type);
  EXPECT_EQ(true, obj.via.boolean);
  msgpack_zone_destroy(&z);
  msgpack_sbuffer_destroy(&sbuf);
}

TEST(MSGPACKC, simple_buffer_false)
{
  msgpack_sbuffer sbuf;
  msgpack_sbuffer_init(&sbuf);
  msgpack_packer pk;
  msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
  msgpack_pack_false(&pk);
  msgpack_zone z;
  msgpack_zone_init(&z, 2048);
  msgpack_object obj;
  msgpack_unpack_return ret =
    msgpack_unpack(sbuf.data, sbuf.size, NULL, &z, &obj);
  EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);
  EXPECT_EQ(MSGPACK_OBJECT_BOOLEAN, obj.type);
  EXPECT_EQ(false, obj.via.boolean);
  msgpack_zone_destroy(&z);
  msgpack_sbuffer_destroy(&sbuf);
}

TEST(MSGPACKC, simple_buffer_array)
{
  unsigned int array_size = 5;

  msgpack_sbuffer sbuf;
  msgpack_sbuffer_init(&sbuf);
  msgpack_packer pk;
  msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
  msgpack_pack_array(&pk, array_size);
  msgpack_pack_nil(&pk);
  msgpack_pack_true(&pk);
  msgpack_pack_false(&pk);
  msgpack_pack_int(&pk, 10);
  msgpack_pack_int(&pk, -10);

  msgpack_zone z;
  msgpack_zone_init(&z, 2048);
  msgpack_object obj;
  msgpack_unpack_return ret;
  ret = msgpack_unpack(sbuf.data, sbuf.size, NULL, &z, &obj);
  EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);
  EXPECT_EQ(MSGPACK_OBJECT_ARRAY, obj.type);
  EXPECT_EQ(array_size, obj.via.array.size);

  for (unsigned int i = 0; i < obj.via.array.size; i++) {
    msgpack_object o = obj.via.array.ptr[i];
    switch (i) {
    case 0:
      EXPECT_EQ(MSGPACK_OBJECT_NIL, o.type);
      break;
    case 1:
      EXPECT_EQ(MSGPACK_OBJECT_BOOLEAN, o.type);
      EXPECT_EQ(true, o.via.boolean);
      break;
    case 2:
      EXPECT_EQ(MSGPACK_OBJECT_BOOLEAN, o.type);
      EXPECT_EQ(false, o.via.boolean);
      break;
    case 3:
      EXPECT_EQ(MSGPACK_OBJECT_POSITIVE_INTEGER, o.type);
      EXPECT_EQ(10, o.via.u64);
      break;
    case 4:
      EXPECT_EQ(MSGPACK_OBJECT_NEGATIVE_INTEGER, o.type);
      EXPECT_EQ(-10, o.via.i64);
      break;
    }
  }

  msgpack_zone_destroy(&z);
  msgpack_sbuffer_destroy(&sbuf);
}

TEST(MSGPACKC, simple_buffer_map)
{
  unsigned int map_size = 2;

  msgpack_sbuffer sbuf;
  msgpack_sbuffer_init(&sbuf);
  msgpack_packer pk;
  msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
  msgpack_pack_map(&pk, map_size);
  msgpack_pack_true(&pk);
  msgpack_pack_false(&pk);
  msgpack_pack_int(&pk, 10);
  msgpack_pack_int(&pk, -10);

  msgpack_zone z;
  msgpack_zone_init(&z, 2048);
  msgpack_object obj;
  msgpack_unpack_return ret;
  ret = msgpack_unpack(sbuf.data, sbuf.size, NULL, &z, &obj);
  EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);
  EXPECT_EQ(MSGPACK_OBJECT_MAP, obj.type);
  EXPECT_EQ(map_size, obj.via.map.size);

  for (unsigned int i = 0; i < map_size; i++) {
    msgpack_object key = obj.via.map.ptr[i].key;
    msgpack_object val = obj.via.map.ptr[i].val;
    switch (i) {
    case 0:
      EXPECT_EQ(MSGPACK_OBJECT_BOOLEAN, key.type);
      EXPECT_EQ(true, key.via.boolean);
      EXPECT_EQ(MSGPACK_OBJECT_BOOLEAN, val.type);
      EXPECT_EQ(false, val.via.boolean);
      break;
    case 1:
      EXPECT_EQ(MSGPACK_OBJECT_POSITIVE_INTEGER, key.type);
      EXPECT_EQ(10, key.via.u64);
      EXPECT_EQ(MSGPACK_OBJECT_NEGATIVE_INTEGER, val.type);
      EXPECT_EQ(-10, val.via.i64);
      break;
    }
  }

  msgpack_zone_destroy(&z);
  msgpack_sbuffer_destroy(&sbuf);
}

TEST(MSGPACKC, simple_buffer_raw)
{
  unsigned int raw_size = 7;

  msgpack_sbuffer sbuf;
  msgpack_sbuffer_init(&sbuf);
  msgpack_packer pk;
  msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
  msgpack_pack_raw(&pk, raw_size);
  msgpack_pack_raw_body(&pk, "fr", 2);
  msgpack_pack_raw_body(&pk, "syuki", 5);
  // invalid data
  msgpack_pack_raw_body(&pk, "", 0);
  msgpack_pack_raw_body(&pk, "kzk", 0);

  msgpack_zone z;
  msgpack_zone_init(&z, 2048);
  msgpack_object obj;
  msgpack_unpack_return ret;
  ret = msgpack_unpack(sbuf.data, sbuf.size, NULL, &z, &obj);
  EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);
  EXPECT_EQ(MSGPACK_OBJECT_RAW, obj.type);
  EXPECT_EQ(raw_size, obj.via.raw.size);
  EXPECT_EQ(0, memcmp("frsyuki", obj.via.raw.ptr, raw_size));

  msgpack_zone_destroy(&z);
  msgpack_sbuffer_destroy(&sbuf);
}

TEST(MSGPACKC, unpack_str8)
{
  size_t raw_size = 7;
  const char buf[] = {
    (char)0xd9, 7, 'f', 'r', 's', 'y', 'u', 'k', 'i'
  };

  msgpack_zone z;
  msgpack_zone_init(&z, 2048);
  msgpack_object obj;
  msgpack_unpack_return ret;
  ret = msgpack_unpack(buf, sizeof(buf), NULL, &z, &obj);
  EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);
  EXPECT_EQ(MSGPACK_OBJECT_RAW, obj.type);
  EXPECT_EQ(raw_size, obj.via.raw.size);
  EXPECT_EQ(0, memcmp("frsyuki", obj.via.raw.ptr, raw_size));

  msgpack_zone_destroy(&z);
}

TEST(MSGPACKC, unpack_bin8)
{
  size_t raw_size = 7;
  const char buf[] = {
    (char)0xc4, 7, 'f', 'r', 's', 'y', 'u', 'k', 'i'
  };

  msgpack_zone z;
  msgpack_zone_init(&z, 2048);
  msgpack_object obj;
  msgpack_unpack_return ret;
  ret = msgpack_unpack(buf, sizeof(buf), NULL, &z, &obj);
  EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);
  EXPECT_EQ(MSGPACK_OBJECT_RAW, obj.type);
  EXPECT_EQ(raw_size, obj.via.raw.size);
  EXPECT_EQ(0, memcmp("frsyuki", obj.via.raw.ptr, raw_size));

  msgpack_zone_destroy(&z);
}

TEST(MSGPACKC, unpack_bin16)
{
  size_t raw_size = 7;
  const char buf[] = {
    (char)0xc5, 0, 7, 'f', 'r', 's', 'y', 'u', 'k', 'i'
  };

  msgpack_zone z;
  msgpack_zone_init(&z, 2048);
  msgpack_object obj;
  msgpack_unpack_return ret;
  ret = msgpack_unpack(buf, sizeof(buf), NULL, &z, &obj);
  EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);
  EXPECT_EQ(MSGPACK_OBJECT_RAW, obj.type);
  EXPECT_EQ(raw_size, obj.via.raw.size);
  EXPECT_EQ(0, memcmp("frsyuki", obj.via.raw.ptr, raw_size));

  msgpack_zone_destroy(&z);
}

TEST(MSGPACKC, unpack_bin32)
{
  size_t raw_size = 7;
  const char buf[] = {
    (char)0xc6, 0, 0, 0, 7, 'f', 'r', 's', 'y', 'u', 'k', 'i'
  };

  msgpack_zone z;
  msgpack_zone_init(&z, 2048);
  msgpack_object obj;
  msgpack_unpack_return ret;
  ret = msgpack_unpack(buf, sizeof(buf), NULL, &z, &obj);
  EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);
  EXPECT_EQ(MSGPACK_OBJECT_RAW, obj.type);
  EXPECT_EQ(raw_size, obj.via.raw.size);
  EXPECT_EQ(0, memcmp("frsyuki", obj.via.raw.ptr, raw_size));

  msgpack_zone_destroy(&z);
}

TEST(MSGPACKC, unpack_array_uint64)
{
  const char buf[] = {
    (char)0x91, (char)0xcf, (char)0xff, (char)0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
  };
  msgpack_zone z;
  msgpack_zone_init(&z, 2048);
  msgpack_object obj;
  msgpack_unpack_return ret;
  ret = msgpack_unpack(buf, sizeof(buf), NULL, &z, &obj);
  EXPECT_EQ(MSGPACK_UNPACK_SUCCESS, ret);
  EXPECT_EQ(MSGPACK_OBJECT_ARRAY, obj.type);
  EXPECT_EQ(1, obj.via.array.size);
  EXPECT_EQ(MSGPACK_OBJECT_POSITIVE_INTEGER, obj.via.array.ptr[0].type);
  EXPECT_EQ(0xFFF0000000000001LL, obj.via.array.ptr[0].via.u64);
  msgpack_zone_destroy(&z);
}
