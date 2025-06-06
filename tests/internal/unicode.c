#include <fluent-bit/flb_unicode.h>

#include "flb_tests_internal.h"

void test_generic_converters()
{
    const char *encoding_names[] = {
      "ShiftJIS", "GB18030", "UHC", "Big5",
      "Win866", "Win874", "Win1250", "Win1251", "Win1252", "Win1253",
      "Win1254", "Win1255", "Win1256", "GBK",
      NULL
    };
    const char *encoding_name;
    int ret = FLB_FALSE;
    int i;

    for (i = 0; encoding_names[i] != NULL; i++) {
        ret = flb_unicode_generic_supported_encoding(encoding_names[i]);
        if (!TEST_CHECK(ret == FLB_TRUE)) {
            TEST_MSG("supported converter check failed with %s", encoding_names[i]);
            return;
        }
    }

    encoding_name = "Nonexisitent";
    ret = flb_unicode_generic_supported_encoding(encoding_name);
    if (!TEST_CHECK(ret != FLB_TRUE)) {
        TEST_MSG("supported converter check unexpectedly succeeded with %s", encoding_name);
        return;
    }
}

void test_generic_converters_alias()
{
    const char *encoding_names[] = {
      "SJIS",
      "CP866", "CP874", "CP932", "Windows-31J", "CP949", "CP1250", "CP1251", "CP1252", "CP1253",
      "CP1254", "CP1255", "CP1256",
      NULL
    };
    int ret = FLB_FALSE;
    int i;

    for (i = 0; encoding_names[i] != NULL; i++) {
        ret = flb_unicode_generic_supported_encoding(encoding_names[i]);
        if (!TEST_CHECK(ret == FLB_TRUE)) {
            TEST_MSG("supported converter check failed with %s", encoding_names[i]);
            return;
        }
    }
}

void test_generic_conversions_sjis()
{
    /* "こんにちは" in SJIS */
    const char *sjis_input = "\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd";
    unsigned char *utf8_output = NULL;
    unsigned char *sjis_output = NULL;
    int utf8_len = 0;
    int sjis_len = 0;

    utf8_len = flb_unicode_generic_convert_to_utf8("ShiftJIS", (const unsigned char *)sjis_input, &utf8_output, strlen(sjis_input));
    if (!TEST_CHECK(utf8_len > 0)) {
        TEST_MSG("SJIS to UTF-8 conversion failed.");
        return;
    }
    printf("UTF-8: %s", utf8_output);
    if (!TEST_CHECK(strncmp((char *)utf8_output, "こんにちは", utf8_len) == 0)) {
        TEST_MSG("conversion check failed");
        return;
    }

    sjis_len = flb_unicode_generic_convert_from_utf8("ShiftJIS", utf8_output, &sjis_output, utf8_len);
    if (!TEST_CHECK(sjis_len > 0)) {
        TEST_MSG("UTF-8 to SJIS conversion failed.");
        return;
    }

    if (!TEST_CHECK(strncmp((char *)sjis_output, "\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd", sjis_len) == 0)) {
        TEST_MSG("conversion check failed");
        return;
    }

    flb_free(utf8_output);
    flb_free(sjis_output);
}

void test_generic_conversions_gbk()
{
    const char *gbk_input = "\xc4\xe3\xba\xc3"; // "你好" (Nǐ hǎo) in GBK
    const char *utf8_equivalent = "你好";
    unsigned char *utf8_output = NULL;
    unsigned char *gbk_output = NULL;

    int utf8_len = flb_unicode_generic_convert_to_utf8("GBK", (const unsigned char *)gbk_input, &utf8_output, strlen(gbk_input));
    if (!TEST_CHECK(utf8_len > 0)) {
        TEST_MSG("GBK to UTF-8 conversion failed.");
        return;
    }
    if (!TEST_CHECK(strncmp((char *)utf8_output, utf8_equivalent, utf8_len) == 0)) {
        TEST_MSG("GBK conversion check failed");
        return;
    }

    int gbk_len = flb_unicode_generic_convert_from_utf8("GBK", utf8_output, &gbk_output, utf8_len);
    if (!TEST_CHECK(gbk_len > 0)) {
        TEST_MSG("UTF-8 to GBK conversion failed.");
        return;
    }
    if (!TEST_CHECK(gbk_len == strlen(gbk_input) && memcmp(gbk_output, gbk_input, gbk_len) == 0)) {
        TEST_MSG("GBK round-trip check failed");
        return;
    }

    flb_free(utf8_output);
    flb_free(gbk_output);
}

void test_generic_conversions_big5()
{
    const char *big5_input = "\xa4\xa4\xa4\xe5"; // "中文" (Zhōngwén) in Big5
    const char *utf8_equivalent = "中文";
    unsigned char *utf8_output = NULL;
    unsigned char *big5_output = NULL;

    int utf8_len = flb_unicode_generic_convert_to_utf8("Big5", (const unsigned char *)big5_input, &utf8_output, strlen(big5_input));
    if (!TEST_CHECK(utf8_len > 0)) {
        TEST_MSG("Big5 to UTF-8 conversion failed.");
        return;
    }
    if (!TEST_CHECK(strncmp((char *)utf8_output, utf8_equivalent, utf8_len) == 0)) {
        TEST_MSG("Big5 conversion check failed");
        return;
    }

    int big5_len = flb_unicode_generic_convert_from_utf8("Big5", utf8_output, &big5_output, utf8_len);
    if (!TEST_CHECK(big5_len > 0)) {
        TEST_MSG("UTF-8 to Big5 conversion failed.");
        return;
    }
    if (!TEST_CHECK(big5_len == strlen(big5_input) && memcmp(big5_output, big5_input, big5_len) == 0)) {
        TEST_MSG("Big5 round-trip check failed");
        return;
    }

    flb_free(utf8_output);
    flb_free(big5_output);
}

void test_generic_conversions_gb18030()
{
    const char *gb18030_input = "\xd6\xd0\xce\xc4";
    const char *utf8_equivalent = "\xe4\xb8\xad\xe6\x96\x87";
    unsigned char *utf8_output = NULL;
    unsigned char *gb18030_output = NULL;
    int utf8_len;
    int gb18030_len;

    utf8_len = flb_unicode_generic_convert_to_utf8("GB18030", (const unsigned char *)gb18030_input, &utf8_output, strlen(gb18030_input));
    if (!TEST_CHECK(utf8_len > 0)) {
      TEST_MSG("GB18030 to UTF-8 conversion failed.\n");
      if (utf8_output) {
          flb_free(utf8_output);
      }
      return;
    }
    if (!TEST_CHECK(strncmp((char *)utf8_output, utf8_equivalent, utf8_len) == 0)) {
        TEST_MSG("GB18030 to UTF-8 conversion check failed.\n");
        flb_free(utf8_output);
        return;
    }

    gb18030_len = flb_unicode_generic_convert_from_utf8("GB18030", (const unsigned char *)utf8_output, &gb18030_output, utf8_len);
    if (!TEST_CHECK(gb18030_len > 0)) {
        TEST_MSG("UTF-8 to GB18030 conversion failed.\n");
        flb_free(utf8_output);
        if (gb18030_output) {
            flb_free(gb18030_output);
        }
        return;
    }
    if (!TEST_CHECK(gb18030_len == strlen(gb18030_input) && memcmp(gb18030_output, gb18030_input, gb18030_len) == 0)) {
        TEST_MSG("UTF-8 to GB18030 roundtrip check failed.\n");
        flb_free(utf8_output);
        flb_free(gb18030_output);
        return;
    }

    flb_free(utf8_output);
    flb_free(gb18030_output);
}

/* --- Test Case Data Structure --- */
struct encoding_test_case {
    const char *encoding_name;
    const char *test_string_desc;
    const char *encoded_string;
    size_t      encoded_len;
    const char *utf8_string;
    size_t      utf8_len;
    int         skip_length_validation;
};

/* --- Comprehensive Test Data --- */
static const struct encoding_test_case ALL_TEST_CASES[] = {
  {"SJIS", "こんにちは", "\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd", 10, "\xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1\xe3\x81\xaf", 15, FLB_FALSE},
  {"CP866", "Привет", "\x8f\xe0\xa8\xa2\xa5\xe2", 6, "\xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82", 12, FLB_FALSE},
  {"CP874", "สวัสดี", "\xca\xc7\xd1\xca\xb4\xd5", 6, "\xe0\xb8\xaa\xe0\xb8\xa7\xe0\xb8\xb1\xe0\xb8\xaa\xe0\xb8\x94\xe0\xb8\xb5", 18, FLB_FALSE},
  {"CP932", "こんにちは", "\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd", 10, "\xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1\xe3\x81\xaf", 15, FLB_FALSE},
  {"Windows-31J", "こんにちは", "\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd", 10, "\xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1\xe3\x81\xaf", 15, FLB_FALSE},
  {"CP949", "안녕하세요", "\xbe\xc8\xb3\xe7\xc7\xcf\xbc\xbc\xbf\xe4", 10, "\xec\x95\x88\xeb\x85\x95\xed\x95\x98\xec\x84\xb8\xec\x9a\x94", 15, FLB_FALSE},
  {"CP1250", "Děkuji", "\x44\xec\x6b\x75\x6a\xed", 6, "\x44\xc4\x9b\x6b\x75\x6a\xc3\xad", 8, FLB_FALSE},
  {"CP1251", "Спасибо", "\xd1\xef\xe0\xf1\xe8\xe1\xee", 7, "\xd0\xa1\xd0\xbf\xd0\xb0\xd1\x81\xd0\xb8\xd0\xb1\xd0\xbe", 14, FLB_FALSE},
  {"CP1252", "¡Hola!", "\xa1\x48\x6f\x6c\x61\x21", 6, "\xc2\xa1\x48\x6f\x6c\x61\x21", 7, FLB_FALSE},
  {"CP1253", "Ευχαριστώ", "\xc5\xf5\xf7\xe1\xf1\xe9\xf3\xf4\xfe", 9, "Ευχαριστώ", 17, FLB_TRUE},
  {"CP1254", "Teşekkürler", "\x54\x65\xfe\x65\x6b\x6b\xfc\x72\x6c\x65\x72", 11, "\x54\x65\xc5\x9f\x65\x6b\x6b\xc3\xbc\x72\x6c\x65\x72", 13, FLB_FALSE},
  {"CP1255", "תודה", "\xfa\xe5\xe3\xe4", 4, "\xd7\xaa\xd7\x95\xd7\x93\xd7\x94", 8, FLB_FALSE},
  {"CP1256", "شكرا", "\xd4\xdf\xd1\xc7", 4, "\xd8\xb4\xd9\x83\xd8\xb1\xd8\xa7", 8, FLB_FALSE},
};

/* --- Generic Test Runner --- */
void perform_generic_conversion_test(const struct encoding_test_case* test)
{
    unsigned char *utf8_output = NULL;
    unsigned char *encoded_output = NULL;
    int utf8_len = 0;
    int encoded_len = 0;

    printf("--- Testing [%s]: \"%s\" ---\n", test->encoding_name, test->test_string_desc);

    /* Test conversion from specific encoding to UTF-8 */
    utf8_len = flb_unicode_generic_convert_to_utf8(test->encoding_name, (const unsigned char *)test->encoded_string, &utf8_output, test->encoded_len);
    if (!TEST_CHECK(utf8_len > 0)) {
        TEST_MSG("[%s] to UTF-8 conversion failed to produce output.\n", test->encoding_name);
        goto cleanup;
    }
    if (!test->skip_length_validation) {
        if (!TEST_CHECK(utf8_len == test->utf8_len &&
                        memcmp(utf8_output, test->utf8_string, utf8_len) == 0)) {
            TEST_MSG("[%s] to UTF-8 conversion produced incorrect output. with %s\n", test->encoding_name, utf8_output);
            goto cleanup;
        }
    }
    printf("  %s to UTF-8: OK\n", test->encoding_name);

    /* Test conversion from UTF-8 back to the specific encoding */
    encoded_len = flb_unicode_generic_convert_from_utf8(test->encoding_name, utf8_output, &encoded_output, utf8_len);
    if (!TEST_CHECK(encoded_len > 0)) {
        TEST_MSG("UTF-8 to [%s] conversion failed to produce output.\n", test->encoding_name);
        goto cleanup;
    }
    if (!TEST_CHECK(encoded_len == test->encoded_len && memcmp(encoded_output, test->encoded_string, encoded_len) == 0)) {
        TEST_MSG("UTF-8 to [%s] roundtrip check failed.\n", test->encoding_name);
        goto cleanup;
    }
    printf("  UTF-8 to %s: OK\n", test->encoding_name);

cleanup:
    if (utf8_output) {
        flb_free(utf8_output);
    }
    if (encoded_output) {
        flb_free(encoded_output);
    }
}

/* Main test function to iterate through all defined cases */
void test_all_generic_conversions()
{
    int i;
    int count = sizeof(ALL_TEST_CASES) / sizeof(struct encoding_test_case);
    for (i = 0; i < count; i++) {
        perform_generic_conversion_test(&ALL_TEST_CASES[i]);
        printf("\n");
    }
}

TEST_LIST = {
    { "generic_converters", test_generic_converters },
    { "generic_converters_alias", test_generic_converters_alias },
    { "generic_conversions_sjis", test_generic_conversions_sjis },
    { "generic_conversions_gbk", test_generic_conversions_gbk },
    { "generic_conversions_big5", test_generic_conversions_big5 },
    { "generic_conversions_gb18030", test_generic_conversions_gb18030 },
    { "generic_conversions_all", test_all_generic_conversions },
    { 0 }
};
