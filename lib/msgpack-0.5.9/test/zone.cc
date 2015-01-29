#include <msgpack.hpp>
#include <gtest/gtest.h>

TEST(zone, malloc)
{
	msgpack::zone z;
	char* buf1 = (char*)z.malloc(4);
	memcpy(buf1, "test", 4);
	char* buf2 = (char*)z.malloc(4);
	memcpy(buf2, "test", 4);
}


class myclass {
public:
	myclass() : num(0), str("default") { }

	myclass(int num, const std::string& str) :
		num(num), str(str) { }

	~myclass() { }

	int num;
	std::string str;

private:
	myclass(const myclass&);
};


TEST(zone, allocate)
{
	msgpack::zone z;
	myclass* m = z.allocate<myclass>();
	EXPECT_EQ(m->num, 0);
	EXPECT_EQ(m->str, "default");
}


TEST(zone, allocate_constructor)
{
	msgpack::zone z;
	myclass* m = z.allocate<myclass>(7, "msgpack");
	EXPECT_EQ(m->num, 7);
	EXPECT_EQ(m->str, "msgpack");
}


static void custom_finalizer_func(void* user)
{
	myclass* m = (myclass*)user;
	delete m;
}

TEST(zone, push_finalizer)
{
	msgpack::zone z;
	myclass* m = new myclass();
	z.push_finalizer(custom_finalizer_func, (void*)m);
}


TEST(zone, push_finalizer_auto_ptr)
{
	msgpack::zone z;
	std::auto_ptr<myclass> am(new myclass());
	z.push_finalizer(am);
}


TEST(zone, malloc_no_align)
{
	msgpack::zone z;
	char* buf1 = (char*)z.malloc_no_align(4);
	char* buf2 = (char*)z.malloc_no_align(4);
	EXPECT_EQ(buf1+4, buf2);
}

