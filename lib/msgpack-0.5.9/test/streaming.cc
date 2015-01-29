#include <msgpack.hpp>
#include <gtest/gtest.h>
#include <sstream>

TEST(streaming, basic)
{
	msgpack::sbuffer buffer;

	msgpack::packer<msgpack::sbuffer> pk(&buffer);
	pk.pack(1);
	pk.pack(2);
	pk.pack(3);

	const char* input = buffer.data();
	const char* const eof = input + buffer.size();

	msgpack::unpacker pac;
	msgpack::unpacked result;

	int count = 0;
	while(count < 3) {
		pac.reserve_buffer(32*1024);

		// read buffer into pac.buffer() upto
		// pac.buffer_capacity() bytes.
		size_t len = 1;
		memcpy(pac.buffer(), input, len);
		input += len;

		pac.buffer_consumed(len);

		while(pac.next(&result)) {
			msgpack::object obj = result.get();
			switch(count++) {
			case 0:
				EXPECT_EQ(1, obj.as<int>());
				break;
			case 1:
				EXPECT_EQ(2, obj.as<int>());
				break;
			case 2:
				EXPECT_EQ(3, obj.as<int>());
				return;
			}
		}

		EXPECT_TRUE(input < eof);
	}
}


class event_handler {
public:
	event_handler(std::istream& input) : input(input) { }
	~event_handler() { }

	void on_read()
	{
		while(true) {
			pac.reserve_buffer(32*1024);

			size_t len = input.readsome(pac.buffer(), pac.buffer_capacity());

			if(len == 0) {
				return;
			}

			pac.buffer_consumed(len);

			msgpack::unpacked result;
			while(pac.next(&result)) {
				on_message(result.get(), result.zone());
			}

			if(pac.message_size() > 10*1024*1024) {
				throw std::runtime_error("message is too large");
			}
		}
	}

	void on_message(msgpack::object obj, std::auto_ptr<msgpack::zone> z)
	{
		EXPECT_EQ(expect, obj.as<int>());
	}

	int expect;

private:
	std::istream& input;
	msgpack::unpacker pac;
};

TEST(streaming, event)
{
	std::stringstream stream;
	msgpack::packer<std::ostream> pk(&stream);

	event_handler handler(stream);

	pk.pack(1);
	handler.expect = 1;
	handler.on_read();

	pk.pack(2);
	handler.expect = 2;
	handler.on_read();

	pk.pack(3);
	handler.expect = 3;
	handler.on_read();
}


// backward compatibility
TEST(streaming, basic_compat)
{
	std::ostringstream stream;
	msgpack::packer<std::ostream> pk(&stream);

	pk.pack(1);
	pk.pack(2);
	pk.pack(3);

	std::istringstream input(stream.str());

	msgpack::unpacker pac;

	int count = 0;
	while(count < 3) {
		pac.reserve_buffer(32*1024);

		size_t len = input.readsome(pac.buffer(), pac.buffer_capacity());
		pac.buffer_consumed(len);

		while(pac.execute()) {
			std::auto_ptr<msgpack::zone> z(pac.release_zone());
			msgpack::object obj = pac.data();
			pac.reset();

			switch(count++) {
			case 0:
				EXPECT_EQ(1, obj.as<int>());
				break;
			case 1:
				EXPECT_EQ(2, obj.as<int>());
				break;
			case 2:
				EXPECT_EQ(3, obj.as<int>());
				return;
			}

		}
	}
}


// backward compatibility
class event_handler_compat {
public:
	event_handler_compat(std::istream& input) : input(input) { }
	~event_handler_compat() { }

	void on_read()
	{
		while(true) {
			pac.reserve_buffer(32*1024);

			size_t len = input.readsome(pac.buffer(), pac.buffer_capacity());

			if(len == 0) {
				return;
			}

			pac.buffer_consumed(len);

			while(pac.execute()) {
				std::auto_ptr<msgpack::zone> z(pac.release_zone());
				msgpack::object obj = pac.data();
				pac.reset();
				on_message(obj, z);
			}

			if(pac.message_size() > 10*1024*1024) {
				throw std::runtime_error("message is too large");
			}
		}
	}

	void on_message(msgpack::object obj, std::auto_ptr<msgpack::zone> z)
	{
		EXPECT_EQ(expect, obj.as<int>());
	}

	int expect;

private:
	std::istream& input;
	msgpack::unpacker pac;
};

TEST(streaming, event_compat)
{
	std::stringstream stream;
	msgpack::packer<std::ostream> pk(&stream);

	event_handler_compat handler(stream);

	pk.pack(1);
	handler.expect = 1;
	handler.on_read();

	pk.pack(2);
	handler.expect = 2;
	handler.on_read();

	pk.pack(3);
	handler.expect = 3;
	handler.on_read();
}

