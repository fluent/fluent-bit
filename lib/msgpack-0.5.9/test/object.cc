#include <msgpack.hpp>
#include <gtest/gtest.h>

struct myclass {
	myclass() : num(0), str("default") { }

	myclass(int num, const std::string& str) :
		num(0), str("default") { }

	~myclass() { }

	int num;
	std::string str;

	MSGPACK_DEFINE(num, str);

	bool operator==(const myclass& o) const
	{
		return num == o.num && str == o.str;
	}
};

std::ostream& operator<<(std::ostream& o, const myclass& m)
{
	return o << "myclass("<<m.num<<",\""<<m.str<<"\")";
}


TEST(object, convert)
{
	myclass m1;

	msgpack::sbuffer sbuf;
	msgpack::pack(sbuf, m1);

	msgpack::zone z;
	msgpack::object obj;

	msgpack::unpack_return ret =
		msgpack::unpack(sbuf.data(), sbuf.size(), NULL, &z, &obj);
	EXPECT_EQ(ret, msgpack::UNPACK_SUCCESS);

	myclass m2;
	obj.convert(&m2);

	EXPECT_EQ(m1, m2);
}


TEST(object, as)
{
	myclass m1;

	msgpack::sbuffer sbuf;
	msgpack::pack(sbuf, m1);

	msgpack::zone z;
	msgpack::object obj;

	msgpack::unpack_return ret =
		msgpack::unpack(sbuf.data(), sbuf.size(), NULL, &z, &obj);
	EXPECT_EQ(ret, msgpack::UNPACK_SUCCESS);

	EXPECT_EQ(m1, obj.as<myclass>());
}


TEST(object, print)
{
	msgpack::object obj;
	std::cout << obj << std::endl;
}


TEST(object, is_nil)
{
	msgpack::object obj;
	EXPECT_TRUE(obj.is_nil());
}


TEST(object, type_error)
{
	msgpack::object obj(1);
	EXPECT_THROW(obj.as<std::string>(), msgpack::type_error);
	EXPECT_THROW(obj.as<std::vector<int> >(), msgpack::type_error);
	EXPECT_EQ(1, obj.as<int>());
	EXPECT_EQ(1, obj.as<short>());
	EXPECT_EQ(1u, obj.as<unsigned int>());
	EXPECT_EQ(1u, obj.as<unsigned long>());
}


TEST(object, equal_primitive)
{
	msgpack::object obj_nil;
	EXPECT_EQ(obj_nil, msgpack::object());

	msgpack::object obj_int(1);
	EXPECT_EQ(obj_int, msgpack::object(1));
	EXPECT_EQ(obj_int, 1);

	msgpack::object obj_double(1.2);
	EXPECT_EQ(obj_double, msgpack::object(1.2));
	EXPECT_EQ(obj_double, 1.2);

	msgpack::object obj_bool(true);
	EXPECT_EQ(obj_bool, msgpack::object(true));
	EXPECT_EQ(obj_bool, true);
}


TEST(object, construct_primitive)
{
	msgpack::object obj_nil;
	EXPECT_EQ(msgpack::type::NIL, obj_nil.type);

	msgpack::object obj_uint(1);
	EXPECT_EQ(msgpack::type::POSITIVE_INTEGER, obj_uint.type);
	EXPECT_EQ(1u, obj_uint.via.u64);

	msgpack::object obj_int(-1);
	EXPECT_EQ(msgpack::type::NEGATIVE_INTEGER, obj_int.type);
	EXPECT_EQ(-1, obj_int.via.i64);

	msgpack::object obj_double(1.2);
	EXPECT_EQ(msgpack::type::DOUBLE, obj_double.type);
	EXPECT_EQ(1.2, obj_double.via.dec);

	msgpack::object obj_bool(true);
	EXPECT_EQ(msgpack::type::BOOLEAN, obj_bool.type);
	EXPECT_EQ(true, obj_bool.via.boolean);
}

