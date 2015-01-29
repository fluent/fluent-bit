#include <msgpack.hpp>
#include <fstream>
#include <gtest/gtest.h>

static void feed_file(msgpack::unpacker& pac, const char* path)
{
	std::ifstream fin(path);
	while(true) {
		pac.reserve_buffer(32*1024);
		fin.read(pac.buffer(), pac.buffer_capacity());
		if(fin.bad()) {
			throw std::runtime_error("read failed");
		}
		pac.buffer_consumed(fin.gcount());
		if(fin.fail()) {
			break;
		}
	}
}

TEST(cases, format)
{
	msgpack::unpacker pac;
	msgpack::unpacker pac_compact;

	feed_file(pac, "cases.mpac");
	feed_file(pac_compact, "cases_compact.mpac");

	msgpack::unpacked result;
	while(pac.next(&result)) {
		msgpack::unpacked result_compact;
		EXPECT_TRUE( pac_compact.next(&result_compact) );
		EXPECT_EQ(result_compact.get(), result.get());
	}

	EXPECT_FALSE( pac_compact.next(&result) );
}

