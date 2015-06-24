#include <msgpack.hpp>
#include <msgpack/fbuffer.hpp>
#include <msgpack/fbuffer.h>
#include <msgpack/zbuffer.hpp>
#include <gtest/gtest.h>
#include <string.h>

TEST(buffer, sbuffer)
{
    msgpack::sbuffer sbuf;
    sbuf.write("a", 1);
    sbuf.write("a", 1);
    sbuf.write("a", 1);

    EXPECT_EQ(3, sbuf.size());
    EXPECT_TRUE( memcmp(sbuf.data(), "aaa", 3) == 0 );

    sbuf.clear();
    sbuf.write("a", 1);
    sbuf.write("a", 1);
    sbuf.write("a", 1);

    EXPECT_EQ(3, sbuf.size());
    EXPECT_TRUE( memcmp(sbuf.data(), "aaa", 3) == 0 );
}


TEST(buffer, vrefbuffer)
{
    msgpack::vrefbuffer vbuf;
    vbuf.write("a", 1);
    vbuf.write("a", 1);
    vbuf.write("a", 1);

    const struct iovec* vec = vbuf.vector();
    size_t veclen = vbuf.vector_size();

    msgpack::sbuffer sbuf;
    for(size_t i=0; i < veclen; ++i) {
        sbuf.write((const char*)vec[i].iov_base, vec[i].iov_len);
    }

    EXPECT_EQ(3, sbuf.size());
    EXPECT_TRUE( memcmp(sbuf.data(), "aaa", 3) == 0 );


    vbuf.clear();
    vbuf.write("a", 1);
    vbuf.write("a", 1);
    vbuf.write("a", 1);

    vec = vbuf.vector();
    veclen = vbuf.vector_size();

    sbuf.clear();
    for(size_t i=0; i < veclen; ++i) {
        sbuf.write((const char*)vec[i].iov_base, vec[i].iov_len);
    }

    EXPECT_EQ(3, sbuf.size());
    EXPECT_TRUE( memcmp(sbuf.data(), "aaa", 3) == 0 );
}


TEST(buffer, zbuffer)
{
    msgpack::zbuffer zbuf;
    zbuf.write("a", 1);
    zbuf.write("a", 1);
    zbuf.write("a", 1);

    zbuf.flush();
}


TEST(buffer, fbuffer)
{
    FILE* file = tmpfile();
    EXPECT_TRUE( file != NULL );

    msgpack::fbuffer fbuf(file);
    EXPECT_EQ(file, fbuf.file());

    fbuf.write("a", 1);
    fbuf.write("a", 1);
    fbuf.write("a", 1);

    fflush(file);
    rewind(file);
    for (size_t i=0; i < 3; ++i) {
        int ch = fgetc(file);
        EXPECT_TRUE(ch != EOF);
        EXPECT_EQ('a', static_cast<char>(ch));
    }
    EXPECT_EQ(EOF, fgetc(file));
    fclose(file);
}


TEST(buffer, fbuffer_c)
{
    FILE* file = tmpfile();
    void* fbuf = (void*)file;

    EXPECT_TRUE( file != NULL );
    EXPECT_EQ(0, msgpack_fbuffer_write(fbuf, "a", 1));
    EXPECT_EQ(0, msgpack_fbuffer_write(fbuf, "a", 1));
    EXPECT_EQ(0, msgpack_fbuffer_write(fbuf, "a", 1));

    fflush(file);
    rewind(file);
    for (size_t i=0; i < 3; ++i) {
        int ch = fgetc(file);
        EXPECT_TRUE(ch != EOF);
        EXPECT_EQ('a', (char) ch);
    }
    EXPECT_EQ(EOF, fgetc(file));
    fclose(file);
}
