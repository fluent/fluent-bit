#include <msgpack.hpp>
#include <gtest/gtest.h>

TEST(version, print)
{
	printf("MSGPACK_VERSION          : %s\n", MSGPACK_VERSION);
	printf("MSGPACK_VERSION_MAJOR    : %d\n", MSGPACK_VERSION_MAJOR);
	printf("MSGPACK_VERSION_MINOR    : %d\n", MSGPACK_VERSION_MINOR);
	printf("msgpack_version()        : %s\n", msgpack_version());
	printf("msgpack_version_major()  : %d\n", msgpack_version_major());
	printf("msgpack_version_minor()  : %d\n", msgpack_version_minor());
}

