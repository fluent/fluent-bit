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


TEST(unpack, myclass)
{
	msgpack::sbuffer sbuf;
	myclass m1(1, "phraser");
	msgpack::pack(sbuf, m1);

	msgpack::zone z;
	msgpack::object obj;

	msgpack::unpack_return ret =
		msgpack::unpack(sbuf.data(), sbuf.size(), NULL, &z, &obj);

	EXPECT_EQ(ret, msgpack::UNPACK_SUCCESS);

	myclass m2 = obj.as<myclass>();
	EXPECT_EQ(m1.num, m2.num);
	EXPECT_EQ(m1.str, m2.str);
}


TEST(unpack, sequence)
{
	msgpack::sbuffer sbuf;
	msgpack::pack(sbuf, 1);
	msgpack::pack(sbuf, 2);
	msgpack::pack(sbuf, 3);

	size_t offset = 0;

	msgpack::unpacked msg;

	msgpack::unpack(&msg, sbuf.data(), sbuf.size(), &offset);
	EXPECT_EQ(1, msg.get().as<int>());

	msgpack::unpack(&msg, sbuf.data(), sbuf.size(), &offset);
	EXPECT_EQ(2, msg.get().as<int>());

	msgpack::unpack(&msg, sbuf.data(), sbuf.size(), &offset);
	EXPECT_EQ(3, msg.get().as<int>());
}


TEST(unpack, sequence_compat)
{
	msgpack::sbuffer sbuf;
	msgpack::pack(sbuf, 1);
	msgpack::pack(sbuf, 2);
	msgpack::pack(sbuf, 3);

	size_t offset = 0;

	msgpack::zone z;
	msgpack::object obj;
	msgpack::unpack_return ret;

	ret = msgpack::unpack(sbuf.data(), sbuf.size(), &offset, &z, &obj);
	EXPECT_TRUE(ret >= 0);
	EXPECT_EQ(ret, msgpack::UNPACK_EXTRA_BYTES);
	EXPECT_EQ(1, obj.as<int>());

	ret = msgpack::unpack(sbuf.data(), sbuf.size(), &offset, &z, &obj);
	EXPECT_TRUE(ret >= 0);
	EXPECT_EQ(ret, msgpack::UNPACK_EXTRA_BYTES);
	EXPECT_EQ(2, obj.as<int>());

	ret = msgpack::unpack(sbuf.data(), sbuf.size(), &offset, &z, &obj);
	EXPECT_TRUE(ret >= 0);
	EXPECT_EQ(ret, msgpack::UNPACK_SUCCESS);
	EXPECT_EQ(3, obj.as<int>());
}

