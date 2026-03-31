/*
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "func_types.h"
#include "test_helper.h"
#include "wasm_export.h"
#include "gtest/gtest.h"
#include <limits.h>

#include "../interpreter/wasm.h"

void *func_ptr;
#define CALL_FUNC(name, ...) \
    ((name##_func_type)get_func(#name))(dummy_exec_env.get(), ##__VA_ARGS__)

extern "C" {
extern uint32_t
get_libc_builtin_export_apis(NativeSymbol **p_libc_builtin_apis);

extern bool
wasm_native_lookup_libc_builtin_global(const char *module_name,
                                       const char *global_name,
                                       WASMGlobalImport *global);
}

class LibcBuiltinTest : public testing::Test
{
  protected:
    // You should make the members protected s.t. they can be
    // accessed from sub-classes.

    // virtual void SetUp() will be called before each test is run.  You
    // should define it if you need to initialize the variables.
    // Otherwise, this can be skipped.
    virtual void SetUp()
    {
        n_native_symbols = get_libc_builtin_export_apis(&native_symbols);
    }

    // virtual void TearDown() will be called after each test is run.
    // You should define it if there is cleanup work to do.  Otherwise,
    // you don't have to provide it.
    //
    virtual void TearDown() {}

  public:
    WAMRRuntimeRAII<512 * 1024> runtime;
    DummyExecEnv dummy_exec_env;
    static NativeSymbol *native_symbols;
    static uint32_t n_native_symbols;

    static void *get_func(const char *name)
    {
        int32_t i;

        for (i = 0; i < n_native_symbols; i++) {
            if (strcmp(native_symbols[i].symbol, name) == 0) {
                return native_symbols[i].func_ptr;
            }
        }

        return NULL;
    }
};

NativeSymbol *LibcBuiltinTest::native_symbols;
uint32_t LibcBuiltinTest::n_native_symbols;

static const char very_long_string[] =
    R"(2mwa9vxDhuuvO47XePZvc4DAMdR8dzgKrmRNAM3qVoedFhG7GYyhlC4JiuSdrw8G
         7vrPoCLGlVlGwMw7ATDL3bA5Filds8krTxS7h8ioq6CY4UmKl1zjHlmnOYRO3Wmp
         ylp21RrG8LzfHFerFyKFxA1GB93OuTFcasO2n9uQljCx8h5KRolbvjdHVnado4B6
         3zNV990V7T7LIJHwZKb0RGg0fFo4GQd6Mfdl6aD3UlpKBIxjbonyeaQBY7hPZB8R
         J1JV5iw2PWB2BJEGoGhTvlc0a9FxmeqWIjpnU3yNEg2lD3NjZU627pTFcoAy5GCz
         wDyF5QzcvtAgWBR95kRpDtV21CRyQ6HteorX1aHemoMYWOLIvX52stUTAnOImMD8
         tIw6xwkOZx5fs3x9m540pPnRDiihLn2XuQ1PLPwA6orWOGm3dBKthqsycTqaIl0L
         0gpycKbVYFHmakfgEyP9fyMziLT11B6EPzomHQAYgTVUdDl9u63P6sQCeaPwAYsY
         gus28uK9YYjpXgOOziG8ocBddvids1iLJLdbiAqKyHaVY4IBLVWU3F74tKGF7TeI
         DGAfvpzHls19VM9bKReBfCmDgbib7mCpYEFAQCmu5my0C8QrJlUoOgiljIO0x3sH
         ByNf4k9OfhzYi1V4cvDnMELVrk0fyZWmIxDvig7nfzI57OltT28pughPBlLxTn8X
         xyMNVYn1dD6Wpp7sqOBjxWGWmdrjleyin0iQ05UbfioHazvLKHtDfm5P2WwVejm6)";

TEST_F(LibcBuiltinTest, puts)
{
    char ll_string[2048];

    /* Capture the stdout */
    testing::internal::CaptureStdout();
    EXPECT_EQ(CALL_FUNC(puts, "Hello World"), strlen("Hello World\n"));
    EXPECT_EQ(testing::internal::GetCapturedStdout(), "Hello World\n");

    testing::internal::CaptureStdout();
    EXPECT_EQ(CALL_FUNC(puts, "c"), strlen("c\n"));
    EXPECT_EQ(testing::internal::GetCapturedStdout(), "c\n");

    testing::internal::CaptureStdout();
    EXPECT_EQ(CALL_FUNC(puts, very_long_string), strlen(very_long_string) + 1);
    EXPECT_EQ(testing::internal::GetCapturedStdout(),
              std::string(very_long_string) + "\n");

    memset(ll_string, 0xAA, sizeof(ll_string));
    testing::internal::CaptureStdout();
    EXPECT_EQ(CALL_FUNC(puts, ll_string), strlen(ll_string) + 1);
    EXPECT_EQ(testing::internal::GetCapturedStdout(),
              std::string(ll_string) + "\n");
}

TEST_F(LibcBuiltinTest, printf)
{
    WAMRVaList empty_va_list(dummy_exec_env.get());

    /* Capture the stdout */
    testing::internal::CaptureStdout();
    EXPECT_EQ(CALL_FUNC(printf, "Hello World", empty_va_list.get()),
              strlen("Hello World"));
    EXPECT_EQ(testing::internal::GetCapturedStdout(), "Hello World");

    testing::internal::CaptureStdout();
    EXPECT_EQ(CALL_FUNC(printf, "c", empty_va_list.get()), strlen("c"));
    EXPECT_EQ(testing::internal::GetCapturedStdout(), "c");

    testing::internal::CaptureStdout();
    EXPECT_EQ(CALL_FUNC(printf, very_long_string, empty_va_list.get()),
              strlen(very_long_string));
    EXPECT_EQ(testing::internal::GetCapturedStdout(), very_long_string);

    /* type */
    {
        /* Construct a va_list to call printf */
        WAMRVaList va_list(dummy_exec_env.get());

        va_list.add(20);            //%d 20
        va_list.add(65);            //%i 65
        va_list.add(10);            //%O 12
        va_list.add(10);            //%u 10
        va_list.add(255);           //%x ff
        va_list.add(255);           //%X FF
        va_list.add(3.14);          //%f 3.14
        va_list.add(3.14);          //%F 3.14
        va_list.add(0.000001);      //%e 1.000000e-06
        va_list.add(0.000001);      //%E 1.000000E-06
        va_list.add(0.000001);      //%g 1e-06
        va_list.add(0.000001);      //%G 1E-06
        va_list.add("Hello World"); //%s Hello World

        testing::internal::CaptureStdout();
        /* clang-format off */
        EXPECT_EQ(CALL_FUNC(printf, "%d, %i, %o, %u, %x, %X, %f, %F, %e, %E, %g, %G, %s", va_list.get()), 97);
        EXPECT_EQ(testing::internal::GetCapturedStdout(),
        "20, 65, 12, 10, ff, FF, 3.140000, 3.140000, 1.000000e-06, 1.000000E-06, 1e-06, 1E-06, Hello World");
        /* clang-format on */
    }

    /* %c */
    {
        /* Construct a va_list to call printf */
        WAMRVaList va_list(dummy_exec_env.get());

        va_list.add('C'); //%c C
        // va_list.add("Hello"); //%p
        testing::internal::CaptureStdout();
        EXPECT_EQ(CALL_FUNC(printf, "%c", va_list.get()), 1);
        EXPECT_EQ(testing::internal::GetCapturedStdout(), "C");
    }

    /* %p */
    {
        /* Construct a va_list to call printf */
        WAMRVaList va_list(dummy_exec_env.get());

        va_list.add("Hello");
        testing::internal::CaptureStdout();
        EXPECT_EQ(CALL_FUNC(printf, "%p", va_list.get()), 7);
        EXPECT_EQ(testing::internal::GetCapturedStdout(), "0x200a8");
    }

    {
        /* clang-format off */
        /* Construct a va_list to call printf */
        WAMRVaList va_list(dummy_exec_env.get());

        va_list.add(20);        //%td
        va_list.add(20);        //%zd
        va_list.add(20);        //%ld

        va_list.add(intmax_t(20));        //%jd

        testing::internal::CaptureStdout();

        EXPECT_EQ(CALL_FUNC(printf, "%td, %zd, %ld, %jd", va_list.get()), 14);
        EXPECT_EQ(testing::internal::GetCapturedStdout(),
                  "20, 20, 20, 20");
        /* clang-format on */
    }

    /* %% */
    {
        /* Construct a va_list to call printf */
        WAMRVaList va_list(dummy_exec_env.get());
        EXPECT_TRUE(CALL_FUNC(printf, "%%", va_list.get()));
    }

    /* %n */
    {
        /* Construct a va_list to call printf */
        WAMRVaList empty_va_list(dummy_exec_env.get());

        /* Capture the stdout */
        testing::internal::CaptureStdout();
        CALL_FUNC(printf, "0123%n", empty_va_list.get());
        EXPECT_EQ(testing::internal::GetCapturedStdout(), "0123");
    }

    /* flag */
    {
        /* Construct a va_list to call printf */
        WAMRVaList va_list(dummy_exec_env.get());

        /*%-*/
        va_list.add(20); //%-d 20
        va_list.add(20); //%d 20

        /*%+*/
        va_list.add(20);  //%+d +20
        va_list.add(-20); //%+d -20

        /*% */
        va_list.add(20);  //% d  20
        va_list.add(-20); //% d -20

        /*%#*/
        va_list.add(20);   //%#o 024
        va_list.add(255);  //%#x 0xff
        va_list.add(255);  //%#X 0xFF
        va_list.add(3.14); //%#.f 3.
        va_list.add(3.14); //%#.lf 3.
        va_list.add(3.14); //%#.e 3.e+00
        va_list.add(3.14); //%#.E 3.E+00
        va_list.add(3.14); //%#.g 3.
        va_list.add(3.14); //%#.G 3.
        va_list.add(20);   //%#.a %a
        va_list.add(20);   //%#.A %A

        /*%0*/
        va_list.add(20); //%03d 020

        testing::internal::CaptureStdout();
        /* clang-format off */
        EXPECT_EQ(CALL_FUNC(printf, "%-d, %d, %+d, %+d, % d, % d, %#o, %#x, %#X, %#.f, %#.lf, %#.e, %#.E, %#.g, %#.G, %#.a, %#.A, %03d", va_list.get()), 88);
        EXPECT_EQ(testing::internal::GetCapturedStdout(),
                  "20, 20, +20, -20,  20, -20, 024, 0xff, 0XFF, 3., 3., 3.e+00, 3.E+00, 3., 3., %a, %A, 020");
        /* clang-format on */
    }

    /* precision */
    {
        /* Construct a va_list to call printf */
        WAMRVaList va_list(dummy_exec_env.get());

        va_list.add(20); //%d 20
        va_list.add(20); //%.1d 20
        va_list.add(20); //%.2d 20
        va_list.add(20); //%.3d 020
        va_list.add(20); //%.4d 0020
        va_list.add(20); //%.5d 00020
        va_list.add(20); //%.6d 000020
        va_list.add(20); //%.7d 0000020
        va_list.add(20); //%.8d 00000020
        va_list.add(20); //%.9d 000000020
        testing::internal::CaptureStdout();
        /* clang-format off */
        EXPECT_EQ(CALL_FUNC(printf, "%d, %.1d, %.2d, %.3d, %.4d, %.5d, %.6d, %.7d, %.8d, %.9d", va_list.get()), 66);
        EXPECT_EQ(testing::internal::GetCapturedStdout(),
                  "20, 20, 20, 020, 0020, 00020, 000020, 0000020, 00000020, 000000020");
        /* clang-format on */
    }

    /*length*/
    {
        /* clang-format off */
        /* Construct a va_list to call printf */
        WAMRVaList va_list(dummy_exec_env.get());

        va_list.add(0x7F);        //%hhd 127  -char
        va_list.add(0xFF);        //%hhu.1d 255 -unsiged char
        va_list.add(0x7FFF);      //%hd 32767 -sing short int
        va_list.add(0xFFFF);      //%hu 65535 -unsiged short
        va_list.add(0x7FFFFFFF); //%ld 2147483647 - sing long
        va_list.add(0xFFFFFFFF); //%lu 4294967295 -unsigned long
        va_list.add(0x7FFFFFFFFFFFFFFF); //%lld 9223372036854775807 sing long long
        va_list.add(0xFFFFFFFFFFFFFFFF);//%llu 18446744073709551615 unsigned long long

        testing::internal::CaptureStdout();

        EXPECT_EQ(CALL_FUNC(printf, "%hhd, %hhu, %hd, %hu, %ld, %lu, %lld, %llu", va_list.get()), 89);
        EXPECT_EQ(testing::internal::GetCapturedStdout(),
                  "127, 255, 32767, 65535, 2147483647, 4294967295, 9223372036854775807, 18446744073709551615");
        /* clang-format on */
    }

    EXPECT_EQ(CALL_FUNC(printf, "Hello World", 0), 0);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    EXPECT_EQ(CALL_FUNC(printf, "Hello World", NULL), 0);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    EXPECT_EQ(CALL_FUNC(printf, "Hello World", (char *)-1), 0);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    EXPECT_EQ(CALL_FUNC(printf, (char *)-1, (char *)-1), 0);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();
}

TEST_F(LibcBuiltinTest, sprintf)
{
    char buf[200] = {0};
    const char *str = "Hello World";
    const char *str_sig = "c";
    const char *str_f = "20, 3.140000, Hello World";
    const char *str_long = "eqwewerwerqwer34were"; // test ok
    // const char *str_long = "TDSFGAWE%#$TERFQ@$%$@!%$@!RS!$#@$%"
    //                             "WAWAAEWAFSDNGFUTKNZDAERQWYNZREWGHAH";
    //                             //fail

    WAMRVaList empty_va_list(dummy_exec_env.get());

    AppData buf_app{ dummy_exec_env.get(), buf };
    AppData str_app{ dummy_exec_env.get(), str };
    AppData str_sig_app{ dummy_exec_env.get(), str_sig };
    AppData str_long_app{ dummy_exec_env.get(), str_long };

    EXPECT_EQ(CALL_FUNC(sprintf, (char *)buf_app.get_native_addr(),
                        (char *)str_app.get_native_addr(), 0),
              0);
    EXPECT_EQ(CALL_FUNC(sprintf, (char *)buf_app.get_native_addr(),
                        (char *)str_app.get_native_addr(), NULL),
              0);
    EXPECT_EQ(CALL_FUNC(sprintf, (char *)buf_app.get_native_addr(),
                        (char *)str_app.get_native_addr(), (char *)-1),
              0);

    EXPECT_FALSE(CALL_FUNC(sprintf, (char *)-1,
                           (char *)str_app.get_native_addr(),
                           empty_va_list.get()));

    EXPECT_EQ(CALL_FUNC(sprintf, (char *)buf_app.get_native_addr(),
                        (char *)str_app.get_native_addr(), empty_va_list.get()),
              strlen(str));
    EXPECT_EQ(CALL_FUNC(memcmp, buf_app.get_native_addr(),
                        str_app.get_native_addr(), strlen(str)),
              0);

    EXPECT_EQ(CALL_FUNC(sprintf, (char *)buf_app.get_native_addr(),
                        (char *)str_sig_app.get_native_addr(),
                        empty_va_list.get()),
              strlen(str_sig));
    EXPECT_EQ(CALL_FUNC(memcmp, buf_app.get_native_addr(),
                        str_sig_app.get_native_addr(), strlen(str_sig)),
              0);

    EXPECT_EQ(CALL_FUNC(sprintf, (char *)buf_app.get_native_addr(),
                        (char *)str_long_app.get_native_addr(),
                        empty_va_list.get()),
              strlen(str_long));
    EXPECT_EQ(CALL_FUNC(memcmp, buf_app.get_native_addr(),
                        str_long_app.get_native_addr(), strlen(str_long)),
              0);

    {
        /* Construct a va_list to call printf */
        WAMRVaList va_list(dummy_exec_env.get());

        va_list.add(20);
        va_list.add(3.14);
        va_list.add("Hello World");

        /* This is like printf("%d, %f, %s", 20, 3.14, "Hello World") */
        EXPECT_EQ(CALL_FUNC(sprintf, (char *)buf_app.get_native_addr(),
                            "%d, %f, %s", va_list.get()),
                  25);
        EXPECT_EQ(CALL_FUNC(memcmp, buf_app.get_native_addr(), str_f, 25), 0);
    }
}

TEST_F(LibcBuiltinTest, snprintf)
{
    char buf[1024];
    char buf1[10];

    WAMRVaList empty_va_list(dummy_exec_env.get());

    EXPECT_EQ(CALL_FUNC(snprintf, buf, strlen("Hello World"), "Hello World", 0),
              0);
    EXPECT_EQ(
        CALL_FUNC(snprintf, buf, strlen("Hello World"), "Hello World", NULL),
        0);
    EXPECT_EQ(CALL_FUNC(snprintf, buf, strlen("Hello World"), "Hello World",
                        (char *)-1),
              0);

    EXPECT_EQ(CALL_FUNC(snprintf, buf, strlen("Hello World"), "Hello World",
                        empty_va_list.get()),
              strlen("Hello World"));
    EXPECT_EQ(CALL_FUNC(memcmp, buf, "Hello World", strlen("Hello World")), 0);

    EXPECT_EQ(CALL_FUNC(snprintf, buf, strlen(very_long_string),
                        very_long_string, empty_va_list.get()),
              strlen(very_long_string));
    {
        /* Construct a va_list to call printf */
        WAMRVaList va_list(dummy_exec_env.get());

        va_list.add(20);
        va_list.add(3.14);
        va_list.add("Hello World");

        EXPECT_EQ(CALL_FUNC(snprintf, buf, 25, "%d, %f, %s", va_list.get()),
                  25);
    }
}

TEST_F(LibcBuiltinTest, putchar)
{
    char ch;

    for (ch = 'a'; ch <= 'z'; ch++)
        EXPECT_EQ(CALL_FUNC(putchar, ch), 1);

    for (ch = '0'; ch <= '9'; ch++)
        EXPECT_EQ(CALL_FUNC(putchar, ch), 1);

    for (ch = 0; ch < 127; ch++)
        EXPECT_EQ(CALL_FUNC(putchar, ch), 1);
}

TEST_F(LibcBuiltinTest, strdup)
{
    const char *src = "Hello World!";

    AppData src_app{ dummy_exec_env.get(), src };

    /* exception */
    EXPECT_EQ(CALL_FUNC(strdup, NULL), 0);

    EXPECT_GE(CALL_FUNC(strdup, (char *)src_app.get_native_addr()), 0);
}

TEST_F(LibcBuiltinTest, _strdup)
{
    const char *src = "Hello World!";

    AppData src_app{ dummy_exec_env.get(), src };

    /* exception */
    EXPECT_EQ(CALL_FUNC(_strdup, NULL), 0);

    EXPECT_GE(CALL_FUNC(_strdup, (char *)src_app.get_native_addr()), 0);
}

TEST_F(LibcBuiltinTest, memcmp)
{
    const char *a = "aBcDeF";
    const char *b = "AbCdEf";
    const char *c = "aacdef";
    const char *d = "aBcDeF";

    AppData a_app{ dummy_exec_env.get(), a };
    AppData b_app{ dummy_exec_env.get(), b };
    AppData c_app{ dummy_exec_env.get(), c };
    AppData d_app{ dummy_exec_env.get(), d };

    /* exception */
    EXPECT_EQ(CALL_FUNC(memcmp, (void *)-1, d_app.get_native_addr(), 0), 0);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    /* size = 0 */
    EXPECT_EQ(
        CALL_FUNC(memcmp, a_app.get_native_addr(), d_app.get_native_addr(), 0),
        0);

    // /* s1>s2 */
    EXPECT_GT(CALL_FUNC(memcmp, a_app.get_native_addr(),
                        b_app.get_native_addr(), strlen(a)),
              0);
    // /* s1<s2 */
    EXPECT_LT(CALL_FUNC(memcmp, a_app.get_native_addr(),
                        c_app.get_native_addr(), strlen(a)),
              0);

    // /* s1=s2 */
    EXPECT_EQ(CALL_FUNC(memcmp, a_app.get_native_addr(),
                        d_app.get_native_addr(), strlen(a)),
              0);
}

TEST_F(LibcBuiltinTest, memcpy)
{
    const char *src = "Hell World";
    char dest[sizeof(src)] = {0};

    AppData src_app{ dummy_exec_env.get(), src };
    AppData dest_app{ dummy_exec_env.get(), dest };

    /* exception */
    EXPECT_EQ(CALL_FUNC(memcpy, (void *)-1, src_app.get_native_addr(), 0), 0);

    EXPECT_EQ(CALL_FUNC(memcpy, dest_app.get_native_addr(),
                        src_app.get_native_addr(), 0),
              dest_app.get_app_addr());

    EXPECT_EQ(CALL_FUNC(memcpy, (void *)-1, src_app.get_native_addr(), 10), 0);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    CALL_FUNC(memcpy, dest_app.get_native_addr(), src_app.get_native_addr(),
              strlen(src));
    EXPECT_EQ(CALL_FUNC(memcmp, dest_app.get_native_addr(),
                        src_app.get_native_addr(), strlen(src)),
              0);
}

TEST_F(LibcBuiltinTest, memmove)
{
    const char *src = "Hell World";
    char dest[sizeof(src)] = {0};

    AppData src_app{ dummy_exec_env.get(), src };
    AppData dest_app{ dummy_exec_env.get(), dest };

    /* exception */
    EXPECT_EQ(CALL_FUNC(memmove, (void *)-1, dest_app.get_native_addr(), 0), 0);

    EXPECT_EQ(CALL_FUNC(memmove, dest_app.get_native_addr(),
                        src_app.get_native_addr(), 0),
              dest_app.get_app_addr());

    EXPECT_EQ(CALL_FUNC(memmove, (void *)-1, dest_app.get_native_addr(), 10),
              0);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    CALL_FUNC(memmove, dest_app.get_native_addr(), src_app.get_native_addr(),
              strlen(src));
    EXPECT_EQ(CALL_FUNC(memcmp, dest_app.get_native_addr(),
                        src_app.get_native_addr(), strlen(src)),
              0);
}

TEST_F(LibcBuiltinTest, memset)
{
    const char *src = "Hello World!";
    AppData src_app{ dummy_exec_env.get(), src };

    /* exception */
    EXPECT_EQ(CALL_FUNC(memset, (void *)-1, 1, strlen(src)), 0);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    EXPECT_EQ(CALL_FUNC(memcmp, src_app.get_native_addr(), "Hello World!",
                        strlen(src)),
              0);
    EXPECT_GE(CALL_FUNC(memset, src_app.get_native_addr(), '\0', strlen(src)),
              0);
    EXPECT_EQ(CALL_FUNC(memcmp, src_app.get_native_addr(),
                        "\0\0\0\0\0\0\0\0\0\0\0\0", strlen(src)),
              0);
}

TEST_F(LibcBuiltinTest, strchr)
{
    const char *src = "Hell World";
    unsigned int ch_existent = 'o';
    unsigned int ch_non_existent = '$';

    AppData src_app{ dummy_exec_env.get(), src };

    EXPECT_EQ(
        CALL_FUNC(strchr, (char *)src_app.get_native_addr(), ch_non_existent),
        0);
    EXPECT_GE(CALL_FUNC(strchr, (char *)src_app.get_native_addr(), ch_existent),
              0);
}

TEST_F(LibcBuiltinTest, strcmp)
{
    const char *a = "Hello World!";
    const char *b = "hello World!";
    const char *c = "Hello World!";

    AppData a_app{ dummy_exec_env.get(), a };
    AppData b_app{ dummy_exec_env.get(), b };
    AppData c_app{ dummy_exec_env.get(), c };

    /*s1>s2*/
    EXPECT_GT(CALL_FUNC(strcmp, (char *)b_app.get_native_addr(),
                        (char *)a_app.get_native_addr()),
              0);
    /*s1<s2*/
    EXPECT_LT(CALL_FUNC(strcmp, (char *)a_app.get_native_addr(),
                        (char *)b_app.get_native_addr()),
              0);
    /*s1=s2*/
    EXPECT_EQ(CALL_FUNC(strcmp, (char *)a_app.get_native_addr(),
                        (char *)c_app.get_native_addr()),
              0);
}

TEST_F(LibcBuiltinTest, strncmp)
{
    const char *a = "Hello World!";
    const char *b = "hello World!";
    const char *c = "Hello World!";

    AppData a_app{ dummy_exec_env.get(), a };
    AppData b_app{ dummy_exec_env.get(), b };
    AppData c_app{ dummy_exec_env.get(), c };

    /* exception */
    EXPECT_EQ(CALL_FUNC(strncmp, (char *)-1, (char *)a_app.get_native_addr(),
                        strlen(a)),
              0);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    /* size = 0 */
    EXPECT_EQ(CALL_FUNC(strncmp, (char *)a_app.get_native_addr(),
                        (char *)c_app.get_native_addr(), 0),
              0);

    /*s1>s2*/
    EXPECT_GT(CALL_FUNC(strncmp, (char *)b_app.get_native_addr(),
                        (char *)a_app.get_native_addr(), strlen(a)),
              0);
    /*s1<s2*/
    EXPECT_LT(CALL_FUNC(strncmp, (char *)a_app.get_native_addr(),
                        (char *)b_app.get_native_addr(), strlen(a)),
              0);
    /*s1=s2*/
    EXPECT_EQ(CALL_FUNC(strncmp, (char *)a_app.get_native_addr(),
                        (char *)c_app.get_native_addr(), strlen(a)),
              0);

    /*s1>s2*/
    EXPECT_GT(CALL_FUNC(strncmp, (char *)b_app.get_native_addr(),
                        (char *)a_app.get_native_addr(), 3),
              0);
    /*s1<s2*/
    EXPECT_LT(CALL_FUNC(strncmp, (char *)a_app.get_native_addr(),
                        (char *)b_app.get_native_addr(), 3),
              0);
    /*s1=s2*/
    EXPECT_EQ(CALL_FUNC(strncmp, (char *)a_app.get_native_addr(),
                        (char *)c_app.get_native_addr(), 3),
              0);
}

TEST_F(LibcBuiltinTest, strcpy)
{
    char *src = (char *)"Hello World!";
    char dest[sizeof(src)] = {0};

    AppData src_app{ dummy_exec_env.get(), src };
    AppData dest_app{ dummy_exec_env.get(), dest };

    /* exception */
    EXPECT_EQ(CALL_FUNC(strcpy, (char *)-1, (char *)src_app.get_native_addr()),
              0);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    EXPECT_GE(CALL_FUNC(strcpy, (char *)dest_app.get_native_addr(),
                        (char *)src_app.get_native_addr()),
              0);
    EXPECT_EQ(CALL_FUNC(memcmp, dest_app.get_native_addr(),
                        (char *)src_app.get_native_addr(), strlen(src)),
              0);
}

TEST_F(LibcBuiltinTest, strncpy)
{
    char *src = (char *)"Hello World!";
    char dest[sizeof(src)] = {0};

    AppData src_app{ dummy_exec_env.get(), src };
    AppData dest_app{ dummy_exec_env.get(), dest };

    /* exception */
    EXPECT_EQ(CALL_FUNC(strncpy, (char *)-1, (char *)src_app.get_native_addr(),
                        strlen(src)),
              0);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    EXPECT_GE(CALL_FUNC(strncpy, (char *)dest_app.get_native_addr(),
                        (char *)src_app.get_native_addr(), strlen(src)),
              0);
    EXPECT_EQ(CALL_FUNC(memcmp, (char *)dest_app.get_native_addr(),
                        (char *)src_app.get_native_addr(), strlen(src)),
              0);

    EXPECT_GE(CALL_FUNC(strncpy, (char *)dest_app.get_native_addr(),
                        (char *)src_app.get_native_addr(), 3),
              0);
    EXPECT_EQ(CALL_FUNC(memcmp, (char *)dest_app.get_native_addr(),
                        (char *)src_app.get_native_addr(), 3),
              0);
}

TEST_F(LibcBuiltinTest, strlen)
{
    const char *src = "Hello World!";

    AppData src_app{ dummy_exec_env.get(), src };

    EXPECT_EQ(CALL_FUNC(strlen, (char *)src_app.get_native_addr()), 12);
}

TEST_F(LibcBuiltinTest, malloc)
{
    EXPECT_GT(CALL_FUNC(malloc, 0), 0);
    EXPECT_GT(CALL_FUNC(malloc, 100), 0);
    EXPECT_EQ(CALL_FUNC(malloc, 0xFFFFFFFF), 0);
}

TEST_F(LibcBuiltinTest, calloc)
{
    /* nmemb = 1 size=0xffffffff total_size >= UINT32_MAX  */
    EXPECT_EQ(CALL_FUNC(calloc, 1, 0xffffffff), 0);

    /* nmemb = 1 size=0xffffffff-1 total_size >= UINT32_MAX-1  */
    EXPECT_EQ(CALL_FUNC(calloc, 1, (0xffffffff - 1)), 0);

    /* nmemb = 1 size = 0 total_size = 0 */
    /* According to Linux man page:
    If nmemb or size is 0, then calloc() returns either NULL, or a unique
    pointer value that can later be successfully  passed  to free() */
    EXPECT_GE(CALL_FUNC(calloc, 1, 0), 0);

    /* nmemb = 10 size = 1024 total_size < UINT32_MAX */
    EXPECT_GT(CALL_FUNC(calloc, 10, 1024), 0);
}

TEST_F(LibcBuiltinTest, realloc)
{
    unsigned int ptr = 0;

    // ptr = 0;
    // EXPECT_EQ(CALL_FUNC(realloc, ptr, 1024), 0);

    // ptr = 1;
    // EXPECT_GT(CALL_FUNC(realloc, ptr, 1024), 0);

    // ptr = 3;
    // EXPECT_GT(CALL_FUNC(realloc, ptr, 1024), 0);

    /* If ptr is NULL, then the call is equivalent to malloc(size), for all
     * values of size */
    ptr = CALL_FUNC(realloc, ptr, 1024);
    EXPECT_EQ(ptr, ptr);
    EXPECT_EQ(CALL_FUNC(realloc, ptr, 10), ptr);
    EXPECT_EQ(CALL_FUNC(realloc, ptr, 15), ptr);

    ptr = CALL_FUNC(realloc, ptr, 2048);
    EXPECT_EQ(ptr, ptr);

    /* If size is equal to zero, and ptr is not NULL, then
       the call is equivalent to free(ptr) */
    CALL_FUNC(realloc, ptr, 0);
}

TEST_F(LibcBuiltinTest, free)
{
    const char *src;
    const char *s = "Hello World!";

    AppMemory src_mem{ dummy_exec_env.get(), 15 };
    AppData s_app{ dummy_exec_env.get(), s };

    CALL_FUNC(free, (char *)0xFFFFFFFF);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    CALL_FUNC(free, (char *)-1);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    CALL_FUNC(free, NULL);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    memset((char *)src_mem.get_native_addr(), '\0', 15);
    strcpy((char *)src_mem.get_native_addr(), (char *)s_app.get_native_addr());
    EXPECT_EQ(CALL_FUNC(memcmp, (char *)src_mem.get_native_addr(),
                        s_app.get_native_addr(), 15),
              0);

    /* free */
    CALL_FUNC(free, (char *)src_mem.get_native_addr());
    EXPECT_NE(CALL_FUNC(memcmp, (char *)src_mem.get_native_addr(),
                        s_app.get_native_addr(), 15),
              0);
}

TEST_F(LibcBuiltinTest, atoi)
{
    char *src = (char *)"123";
    char *src1 = (char *)"-123";

    AppData src_app{ dummy_exec_env.get(), src };
    AppData src1_app{ dummy_exec_env.get(), src1 };

    EXPECT_EQ(CALL_FUNC(atoi, (char *)src_app.get_native_addr()), 123);
    EXPECT_EQ(CALL_FUNC(atoi, (char *)src1_app.get_native_addr()), -123);
}

TEST_F(LibcBuiltinTest, exit)
{
    CALL_FUNC(exit, 3);
    EXPECT_STREQ(dummy_exec_env.get_exception(), "Exception: env.exit(3)");
    dummy_exec_env.clear_exception();
}

TEST_F(LibcBuiltinTest, strtol)
{
    char str[20] = "20";
    char str1[20] = "-20";
    char buffer[20] = "0x31";
    char buffer1[20] = "10379cend$3";
    char *ptr;

    AppData src_app{ dummy_exec_env.get(), str };
    AppData src1_app{ dummy_exec_env.get(), str1 };
    AppData buffer_app{ dummy_exec_env.get(), buffer };
    AppData buffer1_app{ dummy_exec_env.get(), buffer1 };
    AppMemory ptr_app{ dummy_exec_env.get(), 20 };

    CALL_FUNC(strtol, (char *)src_app.get_native_addr(), NULL, 10);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    CALL_FUNC(strtol, (char *)src_app.get_native_addr(), &ptr, 10);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    EXPECT_EQ(CALL_FUNC(strtol, (char *)src_app.get_native_addr(), NULL, 2), 0);
    EXPECT_EQ(CALL_FUNC(strtol, (char *)src_app.get_native_addr(), NULL, 8), 0);
    EXPECT_EQ(CALL_FUNC(strtol, (char *)src_app.get_native_addr(), NULL, 10),
              0);
    EXPECT_EQ(CALL_FUNC(strtol, (char *)src_app.get_native_addr(), NULL, 16),
              0);
    EXPECT_EQ(CALL_FUNC(strtol, (char *)src_app.get_native_addr(), NULL, 32),
              0);

    EXPECT_EQ(CALL_FUNC(strtol, (char *)src_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 2),
              0);
    EXPECT_EQ(CALL_FUNC(strtol, (char *)src_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 8),
              16);
    EXPECT_EQ(CALL_FUNC(strtol, (char *)src_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 10),
              20);
    EXPECT_EQ(CALL_FUNC(strtol, (char *)src_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 16),
              32);
    EXPECT_EQ(CALL_FUNC(strtol, (char *)src_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 32),
              64);

    EXPECT_EQ(CALL_FUNC(strtol, (char *)src1_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 2),
              0);
    EXPECT_EQ(CALL_FUNC(strtol, (char *)src1_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 8),
              -16);
    EXPECT_EQ(CALL_FUNC(strtol, (char *)src1_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 10),
              -20);
    EXPECT_EQ(CALL_FUNC(strtol, (char *)src1_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 16),
              -32);
    EXPECT_EQ(CALL_FUNC(strtol, (char *)src1_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 32),
              -64);

    EXPECT_EQ(CALL_FUNC(strtol, (char *)buffer_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 0),
              49);
    EXPECT_EQ(CALL_FUNC(strtol, (char *)buffer_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 16),
              49);

    EXPECT_EQ(CALL_FUNC(strtol, (char *)buffer_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 10),
              0);

    EXPECT_EQ(CALL_FUNC(strtol, (char *)buffer1_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 10),
              10379);
    // EXPECT_STREQ((char *)ptr_app.get_native_addr(), "cend$3");

    uint32_t str_app_addr = *(uint32_t *)ptr_app.get_native_addr();
    EXPECT_GT(str_app_addr, 0);
    char *str_native_addr = (char *)dummy_exec_env.app_to_native(str_app_addr);
    EXPECT_NE(str_native_addr, nullptr);
    EXPECT_STREQ(str_native_addr, "cend$3");
}

TEST_F(LibcBuiltinTest, strtoul)
{
    char str[20] = "20";
    char buffer[20] = "0x31";
    char buffer1[20] = "10379cend$3";
    char *ptr;

    AppData src_app{ dummy_exec_env.get(), str };
    AppData buffer_app{ dummy_exec_env.get(), buffer };
    AppData buffer1_app{ dummy_exec_env.get(), buffer1 };
    AppMemory ptr_app{ dummy_exec_env.get(), 20 };

    CALL_FUNC(strtoul, (char *)src_app.get_native_addr(), NULL, 10);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    CALL_FUNC(strtoul, (char *)src_app.get_native_addr(), &ptr, 10);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    EXPECT_EQ(CALL_FUNC(strtoul, (char *)src_app.get_native_addr(), NULL, 2),
              0);
    EXPECT_EQ(CALL_FUNC(strtoul, (char *)src_app.get_native_addr(), NULL, 8),
              0);
    EXPECT_EQ(CALL_FUNC(strtoul, (char *)src_app.get_native_addr(), NULL, 10),
              0);
    EXPECT_EQ(CALL_FUNC(strtoul, (char *)src_app.get_native_addr(), NULL, 16),
              0);
    EXPECT_EQ(CALL_FUNC(strtoul, (char *)src_app.get_native_addr(), NULL, 32),
              0);

    EXPECT_EQ(CALL_FUNC(strtoul, (char *)src_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 2),
              0);
    EXPECT_EQ(CALL_FUNC(strtoul, (char *)src_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 8),
              16);
    EXPECT_EQ(CALL_FUNC(strtoul, (char *)src_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 10),
              20);
    EXPECT_EQ(CALL_FUNC(strtoul, (char *)src_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 16),
              32);
    EXPECT_EQ(CALL_FUNC(strtoul, (char *)src_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 32),
              64);

    EXPECT_EQ(CALL_FUNC(strtoul, (char *)buffer_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 0),
              49);
    EXPECT_EQ(CALL_FUNC(strtoul, (char *)buffer_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 16),
              49);

    EXPECT_EQ(CALL_FUNC(strtoul, (char *)buffer_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 10),
              0);

    EXPECT_EQ(CALL_FUNC(strtoul, (char *)buffer1_app.get_native_addr(),
                        (char **)ptr_app.get_native_addr(), 10),
              10379);

    uint32_t str_app_addr = *(uint32_t *)ptr_app.get_native_addr();
    EXPECT_GT(str_app_addr, 0);
    char *str_native_addr = (char *)dummy_exec_env.app_to_native(str_app_addr);
    EXPECT_NE(str_native_addr, nullptr);
    EXPECT_STREQ(str_native_addr, "cend$3");
}

TEST_F(LibcBuiltinTest, memchr)
{
    const char src[] = "Hello World.";
    char ch = 'o';

    AppData src_app{ dummy_exec_env.get(), src };

    /* exception */
    EXPECT_EQ(CALL_FUNC(memchr, (char *)-1, ch, strlen(src)), 0);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: out of bounds memory access");
    dummy_exec_env.clear_exception();

    EXPECT_GE(CALL_FUNC(memchr, src_app.get_native_addr(), ch, strlen(src)), 0);
}

TEST_F(LibcBuiltinTest, strncasecmp)
{
    const char *src1 = "Hello World.";
    const char *src2 = "hel";
    const char *src3 = "HELLO WORLD.";

    AppData src1_app{ dummy_exec_env.get(), src1 };
    AppData src2_app{ dummy_exec_env.get(), src2 };
    AppData src3_app{ dummy_exec_env.get(), src3 };

    EXPECT_GT(CALL_FUNC(strncasecmp, (char *)src1_app.get_native_addr(),
                        (char *)src2_app.get_native_addr(), 4),
              0);

    EXPECT_LT(CALL_FUNC(strncasecmp, (char *)src2_app.get_native_addr(),
                        (char *)src1_app.get_native_addr(), 4),
              0);

    EXPECT_EQ(CALL_FUNC(strncasecmp, (char *)src1_app.get_native_addr(),
                        (char *)src3_app.get_native_addr(), strlen(src1)),
              0);
}

TEST_F(LibcBuiltinTest, strspn)
{
    const char *src1 = "Hello world!";
    const char *src2 = "abcd";
    const char *src3 = "l";
    const char *src4 = "Hell";
    const char *src5 = "Helo";

    AppData src1_app{ dummy_exec_env.get(), src1 };
    AppData src2_app{ dummy_exec_env.get(), src2 };
    AppData src3_app{ dummy_exec_env.get(), src3 };
    AppData src4_app{ dummy_exec_env.get(), src4 };
    AppData src5_app{ dummy_exec_env.get(), src5 };

    EXPECT_EQ(CALL_FUNC(strspn, (char *)src1_app.get_native_addr(),
                        (char *)src2_app.get_native_addr()),
              0);

    EXPECT_EQ(CALL_FUNC(strspn, (char *)src1_app.get_native_addr(),
                        (char *)src3_app.get_native_addr()),
              0);

    EXPECT_EQ(CALL_FUNC(strspn, (char *)src1_app.get_native_addr(),
                        (char *)src4_app.get_native_addr()),
              4);

    EXPECT_EQ(CALL_FUNC(strspn, (char *)src1_app.get_native_addr(),
                        (char *)src5_app.get_native_addr()),
              5);
}

TEST_F(LibcBuiltinTest, strcspn)
{
    const char *src1 = "Hello world!";
    const char *src2 = ".?";
    const char *src3 = "llo";
    const char *src4 = "http://www.baidu.com/";
    const char *src5 = "?.,:\"\'-!";

    AppData src1_app{ dummy_exec_env.get(), src1 };
    AppData src2_app{ dummy_exec_env.get(), src2 };
    AppData src3_app{ dummy_exec_env.get(), src3 };
    AppData src4_app{ dummy_exec_env.get(), src4 };
    AppData src5_app{ dummy_exec_env.get(), src5 };

    EXPECT_EQ(CALL_FUNC(strcspn, (char *)src1_app.get_native_addr(),
                        (char *)src2_app.get_native_addr()),
              12);

    EXPECT_EQ(CALL_FUNC(strcspn, (char *)src1_app.get_native_addr(),
                        (char *)src3_app.get_native_addr()),
              2);

    EXPECT_EQ(CALL_FUNC(strcspn, (char *)src4_app.get_native_addr(),
                        (char *)src5_app.get_native_addr()),
              4);
}

TEST_F(LibcBuiltinTest, strstr)
{
    const char *src1 = "Hello world!";
    const char *src2 = "abcd";
    const char *src3 = "Hello";
    const char *src4 = "H";
    const char *src5 = "llo";

    AppData src1_app{ dummy_exec_env.get(), src1 };
    AppData src2_app{ dummy_exec_env.get(), src2 };
    AppData src3_app{ dummy_exec_env.get(), src3 };
    AppData src4_app{ dummy_exec_env.get(), src4 };
    AppData src5_app{ dummy_exec_env.get(), src5 };

    EXPECT_EQ(CALL_FUNC(strstr, (char *)src1_app.get_native_addr(),
                        (char *)src2_app.get_native_addr()),
              0);

    EXPECT_EQ(CALL_FUNC(strstr, (char *)src3_app.get_native_addr(),
                        (char *)src1_app.get_native_addr()),
              0);

    EXPECT_GT(CALL_FUNC(strstr, (char *)src1_app.get_native_addr(),
                        (char *)src4_app.get_native_addr()),
              0);

    EXPECT_GT(CALL_FUNC(strstr, (char *)src1_app.get_native_addr(),
                        (char *)src5_app.get_native_addr()),
              0);
}

TEST_F(LibcBuiltinTest, isupper)
{
    EXPECT_FALSE(CALL_FUNC(isupper, 'a'));

    EXPECT_FALSE(CALL_FUNC(isupper, 97));

    EXPECT_FALSE(CALL_FUNC(isupper, '0'));

    EXPECT_FALSE(CALL_FUNC(isupper, '.'));

    EXPECT_TRUE(CALL_FUNC(isupper, 'A'));

    EXPECT_TRUE(CALL_FUNC(isupper, 65));
}

TEST_F(LibcBuiltinTest, isalpha)
{
    EXPECT_FALSE(CALL_FUNC(isalpha, '0'));

    EXPECT_FALSE(CALL_FUNC(isalpha, 0));

    EXPECT_FALSE(CALL_FUNC(isalpha, '?'));

    EXPECT_TRUE(CALL_FUNC(isalpha, 'A'));

    EXPECT_TRUE(CALL_FUNC(isalpha, 'a'));
}

TEST_F(LibcBuiltinTest, isspace)
{
    EXPECT_FALSE(CALL_FUNC(isspace, '0'));

    EXPECT_FALSE(CALL_FUNC(isspace, 0));

    EXPECT_FALSE(CALL_FUNC(isspace, '?'));

    EXPECT_TRUE(CALL_FUNC(isspace, ' '));
    EXPECT_TRUE(CALL_FUNC(isspace, '\t'));
    EXPECT_TRUE(CALL_FUNC(isspace, '\n'));
    EXPECT_TRUE(CALL_FUNC(isspace, '\v'));
    EXPECT_TRUE(CALL_FUNC(isspace, '\f'));
    EXPECT_TRUE(CALL_FUNC(isspace, '\r'));
}

TEST_F(LibcBuiltinTest, isgraph)
{
    /* ASCII 0x00-0x20 */
    EXPECT_FALSE(CALL_FUNC(isgraph, 0x00));
    EXPECT_FALSE(CALL_FUNC(isgraph, 0x20));

    /* ASCII 0x7F */
    EXPECT_FALSE(CALL_FUNC(isgraph, 0x7F));
    EXPECT_FALSE(CALL_FUNC(isgraph, 0x80));

    /* ASCII 0x21-0x7E */
    EXPECT_TRUE(CALL_FUNC(isgraph, 0x21));
    EXPECT_TRUE(CALL_FUNC(isgraph, 0x7E));
}

TEST_F(LibcBuiltinTest, isprint)
{
    /* ASCII 0x00-0x1F */
    EXPECT_FALSE(CALL_FUNC(isprint, 0x00));
    EXPECT_FALSE(CALL_FUNC(isprint, 0x1F));

    /* ASCII 0x7F */
    EXPECT_FALSE(CALL_FUNC(isprint, 0x7F));
    EXPECT_FALSE(CALL_FUNC(isprint, 0x80));

    /* ASCII 0x20-0x7E */
    EXPECT_TRUE(CALL_FUNC(isprint, 0x20));
    EXPECT_TRUE(CALL_FUNC(isprint, 0x7E));
}

TEST_F(LibcBuiltinTest, isdigit)
{
    /* ASCII 0x00-0x2F */
    EXPECT_FALSE(CALL_FUNC(isdigit, 0x00));
    EXPECT_FALSE(CALL_FUNC(isdigit, 0x2F));

    /* ASCII 0x3A-0x7F */
    EXPECT_FALSE(CALL_FUNC(isdigit, 0x3A));
    EXPECT_FALSE(CALL_FUNC(isdigit, 0x7F));

    /* ASCII 0x30-0x39 */
    EXPECT_TRUE(CALL_FUNC(isdigit, 0x30));
    EXPECT_TRUE(CALL_FUNC(isdigit, 0x39));
}

TEST_F(LibcBuiltinTest, isxdigit)
{
    char str[] = "-FFEE";
    char str1[] = "FFEE";

    EXPECT_FALSE(CALL_FUNC(isxdigit, str[0]));
    EXPECT_TRUE(CALL_FUNC(isxdigit, str1[0]));

    /* ASCII 0x00-0x2F */
    EXPECT_FALSE(CALL_FUNC(isxdigit, 0x00));
    EXPECT_FALSE(CALL_FUNC(isxdigit, 0x2F));

    /* ASCII 0x3A-0x40 */
    EXPECT_FALSE(CALL_FUNC(isxdigit, 0x3A));
    EXPECT_FALSE(CALL_FUNC(isxdigit, 0x40));

    /* ASCII 0x49-0x60 */
    EXPECT_FALSE(CALL_FUNC(isxdigit, 0x49));
    EXPECT_FALSE(CALL_FUNC(isxdigit, 0x60));

    /* ASCII 0x67-0x7F */
    EXPECT_FALSE(CALL_FUNC(isxdigit, 0x67));
    EXPECT_FALSE(CALL_FUNC(isxdigit, 0x7F));

    /* ASCII 0x30-0x39 */
    EXPECT_TRUE(CALL_FUNC(isxdigit, 0x30));
    EXPECT_TRUE(CALL_FUNC(isxdigit, 0x39));

    /* ASCII 0x41-0x46 */
    EXPECT_TRUE(CALL_FUNC(isxdigit, 0x41));
    EXPECT_TRUE(CALL_FUNC(isxdigit, 0x46));

    /* ASCII 0x61-0x66 */
    EXPECT_TRUE(CALL_FUNC(isxdigit, 0x61));
    EXPECT_TRUE(CALL_FUNC(isxdigit, 0x66));
}

TEST_F(LibcBuiltinTest, tolower)
{
    char src[] = "aBcDeFgH12345;!#$";
    char dest[sizeof(src)];
    int i;

    for (i = 0; i < sizeof(src); i++) {
        dest[i] = CALL_FUNC(tolower, (src[i]));
    }
    EXPECT_STREQ(dest, "abcdefgh12345;!#$");
}

TEST_F(LibcBuiltinTest, toupper)
{
    char src[] = "aBcDeFgH12345;!#$";
    char dest[sizeof(src)];
    int i;

    for (i = 0; i < sizeof(src); i++) {
        dest[i] = CALL_FUNC(toupper, (src[i]));
    }
    EXPECT_STREQ(dest, "ABCDEFGH12345;!#$");
}

TEST_F(LibcBuiltinTest, isalnum)
{
    char src[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678"
                 "9!\"#$%&'()*+,-./:;<=>?@[^_'{|}~";
    int i;
    int isalnum_cnt = 0;

    for (i = 0; i < sizeof(src); i++) {
        if (CALL_FUNC(isalnum, (src[i])))
            isalnum_cnt++;
    }
    EXPECT_EQ(isalnum_cnt, 62);
}

TEST_F(LibcBuiltinTest, emscripten_memcpy_big)
{
    const char *src = "Hell World";
    char dest[sizeof(src)] = {0};

    AppData src_app{ dummy_exec_env.get(), src };
    AppData dest_app{ dummy_exec_env.get(), dest };

    /* exception */
    EXPECT_EQ(CALL_FUNC(emscripten_memcpy_big, (void *)-1,
                        src_app.get_native_addr(), 0),
              0);

    CALL_FUNC(emscripten_memcpy_big, dest_app.get_native_addr(),
              src_app.get_native_addr(), strlen(src));
    EXPECT_EQ(CALL_FUNC(memcmp, dest_app.get_native_addr(),
                        src_app.get_native_addr(), strlen(src)),
              0);
}

TEST_F(LibcBuiltinTest, abort)
{
    CALL_FUNC(abort, 33);
    EXPECT_STREQ(dummy_exec_env.get_exception(), "Exception: env.abort(33)");
    dummy_exec_env.clear_exception();
}

TEST_F(LibcBuiltinTest, abortStackOverflow)
{
    CALL_FUNC(abortStackOverflow, 33);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: env.abortStackOverflow(33)");
    dummy_exec_env.clear_exception();
}

TEST_F(LibcBuiltinTest, nullFunc_X)
{
    CALL_FUNC(nullFunc_X, 33);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: env.nullFunc_X(33)");
    dummy_exec_env.clear_exception();
}

TEST_F(LibcBuiltinTest, __cxa_allocate_exception)
{
    EXPECT_NE(CALL_FUNC(__cxa_allocate_exception, 0x0), 0x0);
    EXPECT_EQ(CALL_FUNC(__cxa_allocate_exception, 0xFFFF), 0x0);
}

TEST_F(LibcBuiltinTest, __cxa_begin_catch)
{
    /* 无函数原型 */
}

TEST_F(LibcBuiltinTest, __cxa_throw)
{
    void *excepton;
    void *tinfo;

    CALL_FUNC(__cxa_throw, excepton, tinfo, 1);
    EXPECT_STREQ(dummy_exec_env.get_exception(),
                 "Exception: exception thrown by stdc++");
    dummy_exec_env.clear_exception();
}

struct timespec_app app;
TEST_F(LibcBuiltinTest, clock_gettime)
{
    struct timespec_app *tsapp;
    tsapp = &app;

    AppMemory tsapp_app{ dummy_exec_env.get(), sizeof(struct timespec_app) };

    /* exception */
    EXPECT_EQ(CALL_FUNC(clock_gettime, 0, (struct timespec_app *)-1), -1);

    EXPECT_EQ(CALL_FUNC(clock_gettime, 100, NULL), -1);

    EXPECT_EQ(CALL_FUNC(clock_gettime, 100, 0), -1);

    EXPECT_EQ(CALL_FUNC(clock_gettime, 10,
                        (struct timespec_app *)tsapp_app.get_native_addr()),
              0);
}

TEST_F(LibcBuiltinTest, clock)
{
    EXPECT_GE(CALL_FUNC(clock), 0);
}

WASMGlobalImport glb;
TEST_F(LibcBuiltinTest, wasm_native_lookup_libc_builtin_global)
{
    const char *module_name = "module name";
    const char *global_name = "global name";

    const char *module_name1 = "global";
    const char *global_name1 = "NaN";
    const char *global_name2 = "Infinity";
    WASMGlobalImport *global = &glb;

    EXPECT_FALSE(
        wasm_native_lookup_libc_builtin_global(NULL, global_name, global));
    EXPECT_FALSE(
        wasm_native_lookup_libc_builtin_global(module_name, NULL, global));
    EXPECT_FALSE(
        wasm_native_lookup_libc_builtin_global(module_name, global_name, NULL));
    EXPECT_FALSE(wasm_native_lookup_libc_builtin_global(module_name,
                                                        global_name, global));
    EXPECT_FALSE(wasm_native_lookup_libc_builtin_global(module_name,
                                                        global_name1, global));

    EXPECT_TRUE(wasm_native_lookup_libc_builtin_global(module_name1,
                                                       global_name1, global));

    EXPECT_TRUE(wasm_native_lookup_libc_builtin_global(module_name1,
                                                       global_name2, global));
}
