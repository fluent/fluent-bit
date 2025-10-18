#include <fluent-bit/flb_pack.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "acutest.h"

void test_flb_pack_json_leak()
{
    const char *malformed_json = "{\"key1\": \"value1\", \"key2\": "; // incomplete JSON
    char *buffer = NULL;
    size_t size = 0;
    int root_type = 0;
    int ret;

    ret = flb_pack_json(malformed_json, strlen(malformed_json), &buffer, &size, &root_type, NULL);

    TEST_CHECK(ret != 0); // Should fail
    TEST_CHECK(buffer == NULL); // Should not allocate buffer on error
}

TEST_LIST = {
    { "flb_pack_json_leak", test_flb_pack_json_leak },
    { 0 }
};