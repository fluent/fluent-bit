#include <msgpack.hpp>
#include <gtest/gtest.h>

class compatibility {
public:
	compatibility() : str1("default"), str2("default") { }

	std::string str1;
	std::string str2;

	MSGPACK_DEFINE(str1, str2);
};

TEST(convert, compatibility_less)
{
	std::vector<std::string> src(1);
	src[0] = "kumofs";

	msgpack::zone z;
	msgpack::object obj(src, &z);

	compatibility c;
	EXPECT_NO_THROW( obj.convert(&c) );

	EXPECT_EQ("kumofs",  c.str1);
	EXPECT_EQ("default", c.str2);
}

TEST(convert, compatibility_more)
{
	std::vector<std::string> src(3);
	src[0] = "kumofs";
	src[1] = "mpio";
	src[2] = "cloudy";

	msgpack::zone z;
	msgpack::object obj(src, &z);

	compatibility to;
	EXPECT_NO_THROW( obj.convert(&to) );

	EXPECT_EQ("kumofs", to.str1);
	EXPECT_EQ("mpio",   to.str2);
}


class enum_member {
public:
	enum_member() : flag(A) { }

	enum flags_t {
		A = 0,
		B = 1,
	};

	flags_t flag;

	MSGPACK_DEFINE(flag);
};

MSGPACK_ADD_ENUM(enum_member::flags_t);

TEST(convert, enum_member)
{
	enum_member src;
	src.flag = enum_member::B;

	msgpack::zone z;
	msgpack::object obj(src, &z);

	enum_member to;
	EXPECT_NO_THROW( obj.convert(&to) );

	EXPECT_EQ(enum_member::B, to.flag);
}

