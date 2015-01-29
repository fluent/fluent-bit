#include <msgpack.h>
#include <gtest/gtest.h>
#include <stdio.h>

TEST(streaming, basic)
{
	msgpack_sbuffer* buffer = msgpack_sbuffer_new();

	msgpack_packer* pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);

	// 1, 2, 3, "raw", ["data"], {0.3: 0.4}
	EXPECT_EQ(0, msgpack_pack_int(pk, 1));
	EXPECT_EQ(0, msgpack_pack_int(pk, 2));
	EXPECT_EQ(0, msgpack_pack_int(pk, 3));
	EXPECT_EQ(0, msgpack_pack_raw(pk, 3));
	EXPECT_EQ(0, msgpack_pack_raw_body(pk, "raw", 3));
	EXPECT_EQ(0, msgpack_pack_array(pk, 1));
	EXPECT_EQ(0, msgpack_pack_raw(pk, 4));
	EXPECT_EQ(0, msgpack_pack_raw_body(pk, "data", 4));
	EXPECT_EQ(0, msgpack_pack_map(pk, 1));
	EXPECT_EQ(0, msgpack_pack_float(pk, 0.4));
	EXPECT_EQ(0, msgpack_pack_double(pk, 0.8));
	int max_count = 6;

	msgpack_packer_free(pk);

	const char* input = buffer->data;
	const char* const eof = input + buffer->size;

	msgpack_unpacker pac;
	msgpack_unpacker_init(&pac, MSGPACK_UNPACKER_INIT_BUFFER_SIZE);

	msgpack_unpacked result;
	msgpack_unpacked_init(&result);

	int count = 0;
	while(count < max_count) {
		bool unpacked = false;

		msgpack_unpacker_reserve_buffer(&pac, 32*1024);

		while(!unpacked) {
			/* read buffer into msgpack_unapcker_buffer(&pac) upto
			 * msgpack_unpacker_buffer_capacity(&pac) bytes. */
			memcpy(msgpack_unpacker_buffer(&pac), input, 1);
			input += 1;

			EXPECT_TRUE(input <= eof);

			msgpack_unpacker_buffer_consumed(&pac, 1);

			while(msgpack_unpacker_next(&pac, &result)) {
				unpacked = 1;
				msgpack_object obj = result.data;
				msgpack_object e;
				switch(count++) {
				case 0:
					EXPECT_EQ(MSGPACK_OBJECT_POSITIVE_INTEGER, obj.type);
					EXPECT_EQ(1, obj.via.u64);
					break;
				case 1:
					EXPECT_EQ(MSGPACK_OBJECT_POSITIVE_INTEGER, obj.type);
					EXPECT_EQ(2, obj.via.u64);
					break;
				case 2:
					EXPECT_EQ(MSGPACK_OBJECT_POSITIVE_INTEGER, obj.type);
					EXPECT_EQ(3, obj.via.u64);
					break;
				case 3:
					EXPECT_EQ(MSGPACK_OBJECT_RAW, obj.type);
					EXPECT_EQ(std::string("raw",3), std::string(obj.via.raw.ptr, obj.via.raw.size));
					break;
				case 4:
					EXPECT_EQ(MSGPACK_OBJECT_ARRAY, obj.type);
					EXPECT_EQ(1, obj.via.array.size);
					e = obj.via.array.ptr[0];
					EXPECT_EQ(MSGPACK_OBJECT_RAW, e.type);
					EXPECT_EQ(std::string("data",4), std::string(e.via.raw.ptr, e.via.raw.size));
					break;
				case 5:
					EXPECT_EQ(MSGPACK_OBJECT_MAP, obj.type);
					EXPECT_EQ(1, obj.via.map.size);
					e = obj.via.map.ptr[0].key;
					EXPECT_EQ(MSGPACK_OBJECT_DOUBLE, e.type);
					ASSERT_FLOAT_EQ(0.4, (float)e.via.dec);
					e = obj.via.map.ptr[0].val;
					EXPECT_EQ(MSGPACK_OBJECT_DOUBLE, e.type);
					ASSERT_DOUBLE_EQ(0.8, e.via.dec);
					break;
				}
			}
		}
	}

	msgpack_unpacker_destroy(&pac);
	msgpack_unpacked_destroy(&result);
}

