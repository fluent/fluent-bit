#include "flb_tests_internal.h"
#include "../../plugins/in_opentelemetry/opentelemetry_protobuf.h"

static void test_protobuf_depth(void)
{
    Opentelemetry__Proto__Common__V1__AnyValue values[51];
    Opentelemetry__Proto__Common__V1__ArrayValue arrays[50];
    Opentelemetry__Proto__Common__V1__AnyValue *children[50];
    unsigned char buffer[1024];
    size_t size;
    int index;

    for (index = 0; index < 51; index++) {
        opentelemetry__proto__common__v1__any_value__init(&values[index]);
    }
    values[50].value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE;
    values[50].int_value = 7;
    for (index = 49; index >= 0; index--) {
        opentelemetry__proto__common__v1__array_value__init(&arrays[index]);
        children[index] = &values[index + 1];
        arrays[index].values = &children[index];
        arrays[index].n_values = 1;
        values[index].value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE;
        values[index].array_value = &arrays[index];
    }

    /* 99, 100 and 101 schema messages, including scalar AnyValue leaves. */
    size = opentelemetry__proto__common__v1__any_value__pack(&values[1], buffer);
    TEST_CHECK(opentelemetry_protobuf_validate(values[1].base.descriptor, buffer, size) == 0);
    size = opentelemetry__proto__common__v1__array_value__pack(&arrays[0], buffer);
    TEST_CHECK(opentelemetry_protobuf_validate(arrays[0].base.descriptor, buffer, size) == 0);
    size = opentelemetry__proto__common__v1__any_value__pack(&values[0], buffer);
    TEST_CHECK(opentelemetry_protobuf_validate(values[0].base.descriptor, buffer, size) != 0);
}

static void test_protobuf_wire_boundaries(void)
{
    const ProtobufCMessageDescriptor *descriptor;
    unsigned char truncated[] = {0x2a, 0x02, 0x0a};
    unsigned char overflow[] = {0x2a, 0xff, 0xff, 0xff, 0xff, 0xff,
                               0xff, 0xff, 0xff, 0xff, 0x02};
    unsigned char opaque[] = {0x0a, 0x03, 0xff, 0xff, 0xff};
    unsigned char unknown[] = {0x7a, 0x03, 0xff, 0xff, 0xff};
    unsigned char zero_tag[] = {0x00, 0x00};
    unsigned char fixed[] = {0x21, 0, 0, 0, 0, 0, 0, 0, 0};

    descriptor = &opentelemetry__proto__common__v1__any_value__descriptor;
    TEST_CHECK(opentelemetry_protobuf_validate(descriptor, NULL, 0) == 0);
    TEST_CHECK(opentelemetry_protobuf_validate(descriptor, truncated, sizeof(truncated)) != 0);
    TEST_CHECK(opentelemetry_protobuf_validate(descriptor, overflow, sizeof(overflow)) != 0);
    TEST_CHECK(opentelemetry_protobuf_validate(descriptor, opaque, sizeof(opaque)) == 0);
    TEST_CHECK(opentelemetry_protobuf_validate(descriptor, unknown, sizeof(unknown)) == 0);
    TEST_CHECK(opentelemetry_protobuf_validate(descriptor, zero_tag, sizeof(zero_tag)) != 0);
    TEST_CHECK(opentelemetry_protobuf_validate(descriptor, fixed, sizeof(fixed)) == 0);
    TEST_CHECK(opentelemetry_protobuf_validate(descriptor, fixed, sizeof(fixed) - 1) != 0);
}

TEST_LIST = {
    {"protobuf_depth", test_protobuf_depth},
    {"protobuf_wire_boundaries", test_protobuf_wire_boundaries},
    {0}
};
