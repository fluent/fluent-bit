/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/aws/flb_aws_compress.h>
#include <fluent-bit/flb_mem.h>

#include <arrow/api.h>
#include <arrow/io/api.h>
#include <parquet/file_reader.h>

#include <cstring>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>

#include "flb_tests_internal.h"
#include "protobuf.h"

namespace {

const unsigned char wire_log_record[] = {
    0x08, 0x07,
    0x10, 0x80, 0xe4, 0x97, 0xd0, 0x12,
    0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x3f,
    0x22, 0x05, 'a', 'l', 'p', 'h', 'a',
    0x2a, 0x0a, 0x08, 0x09, 0x12, 0x06,
    'n', 'e', 's', 't', 'e', 'd',
    0x32, 0x03, 0x01, 0xac, 0x02,
    0x3a, 0x0a, 0x0a, 0x06, 'r', 'e', 'g', 'i', 'o', 'n',
    0x10, 0x0b,
    0x42, 0x02, 0x00, 0xff,
    0x4a, 0x00
};

const unsigned char invalid_wire_log_record[] = {0xff};

std::string read_descriptor()
{
    std::ifstream input(FLB_TEST_PROTOBUF_DESCRIPTOR_PATH,
                        std::ios::in | std::ios::binary);

    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

struct flb_aws_protobuf_schema *load_schema(
                                        const std::string &descriptor,
                                        const char *message,
                                        char *error, size_t error_size)
{
    return flb_aws_protobuf_schema_create(
                descriptor.data(), descriptor.size(), message,
                error, error_size);
}

void test_protobuf_to_parquet_preserves_types()
{
    std::string descriptor = read_descriptor();
    struct flb_aws_protobuf_schema *schema;
    struct flb_aws_protobuf_record records[] = {
        {wire_log_record, sizeof(wire_log_record)},
        {nullptr, 0}
    };
    std::shared_ptr<arrow::Table> table;
    std::shared_ptr<arrow::Int32Array> count;
    std::shared_ptr<arrow::Int64Array> total;
    std::shared_ptr<arrow::DoubleArray> score;
    std::shared_ptr<arrow::StringArray> name;
    std::shared_ptr<arrow::StructArray> child;
    std::shared_ptr<arrow::Int64Array> child_value;
    std::shared_ptr<arrow::ListArray> ids;
    std::shared_ptr<arrow::UInt32Array> id_values;
    std::shared_ptr<arrow::MapArray> labels;
    std::shared_ptr<arrow::StringArray> label_keys;
    std::shared_ptr<arrow::Int64Array> label_values;
    std::shared_ptr<arrow::BinaryArray> payload;
    std::shared_ptr<arrow::BooleanArray> marker;
    void *output = nullptr;
    size_t output_size = 0;
    char error[512] = {0};
    arrow::Status status;
    int ret;

    TEST_ASSERT(!descriptor.empty());
    schema = load_schema(descriptor, "fluent.test.WireLog",
                         error, sizeof(error));
    TEST_ASSERT_(schema != nullptr, "%s", error);

    status = flb_aws_protobuf_records_to_arrow_table(
                schema, records, 2, &table);
    TEST_ASSERT_(status.ok(), "%s", status.ToString().c_str());
    TEST_CHECK(table->num_rows() == 2);
    TEST_CHECK(table->num_columns() == 9);

    TEST_CHECK(table->schema()->field(0)->type()->id() ==
               arrow::Type::INT32);
    TEST_CHECK(table->schema()->field(1)->type()->id() ==
               arrow::Type::INT64);
    TEST_CHECK(table->schema()->field(2)->type()->id() ==
               arrow::Type::DOUBLE);
    TEST_CHECK(table->schema()->field(3)->type()->id() ==
               arrow::Type::STRING);
    TEST_CHECK(table->schema()->field(4)->type()->id() ==
               arrow::Type::STRUCT);
    TEST_CHECK(table->schema()->field(5)->type()->id() ==
               arrow::Type::LIST);
    TEST_CHECK(table->schema()->field(6)->type()->id() ==
               arrow::Type::MAP);
    TEST_CHECK(table->schema()->field(7)->type()->id() ==
               arrow::Type::BINARY);
    TEST_CHECK(table->schema()->field(8)->type()->id() ==
               arrow::Type::BOOL);

    count = std::static_pointer_cast<arrow::Int32Array>(
                table->column(0)->chunk(0));
    total = std::static_pointer_cast<arrow::Int64Array>(
                table->column(1)->chunk(0));
    score = std::static_pointer_cast<arrow::DoubleArray>(
                table->column(2)->chunk(0));
    name = std::static_pointer_cast<arrow::StringArray>(
                table->column(3)->chunk(0));
    child = std::static_pointer_cast<arrow::StructArray>(
                table->column(4)->chunk(0));
    ids = std::static_pointer_cast<arrow::ListArray>(
                table->column(5)->chunk(0));
    labels = std::static_pointer_cast<arrow::MapArray>(
                table->column(6)->chunk(0));
    payload = std::static_pointer_cast<arrow::BinaryArray>(
                table->column(7)->chunk(0));
    marker = std::static_pointer_cast<arrow::BooleanArray>(
                table->column(8)->chunk(0));

    TEST_CHECK(count->Value(0) == 7);
    TEST_CHECK(count->Value(1) == 0);
    TEST_CHECK(total->Value(0) == 5000000000LL);
    TEST_CHECK(total->Value(1) == 0);
    TEST_CHECK(score->Value(0) == 1.5);
    TEST_CHECK(score->Value(1) == 0);
    TEST_CHECK(name->GetString(0) == "alpha");
    TEST_CHECK(name->GetString(1).empty());

    TEST_CHECK(!child->IsNull(0));
    TEST_CHECK(child->IsNull(1));
    child_value = std::static_pointer_cast<arrow::Int64Array>(
                      child->field(0));
    TEST_CHECK(child_value->Value(0) == 9);

    TEST_CHECK(ids->value_length(0) == 2);
    TEST_CHECK(ids->value_length(1) == 0);
    id_values = std::static_pointer_cast<arrow::UInt32Array>(
                    ids->values());
    TEST_CHECK(id_values->Value(0) == 1);
    TEST_CHECK(id_values->Value(1) == 300);

    TEST_CHECK(labels->value_length(0) == 1);
    TEST_CHECK(labels->value_length(1) == 0);
    label_keys = std::static_pointer_cast<arrow::StringArray>(
                     labels->keys());
    label_values = std::static_pointer_cast<arrow::Int64Array>(
                       labels->items());
    TEST_CHECK(label_keys->GetString(0) == "region");
    TEST_CHECK(label_values->Value(0) == 11);

    TEST_CHECK(payload->GetView(0).size() == 2);
    TEST_CHECK(payload->GetView(0)[0] == '\0');
    TEST_CHECK(static_cast<unsigned char>(payload->GetView(0)[1]) == 0xff);
    TEST_CHECK(!marker->IsNull(0));
    TEST_CHECK(marker->Value(0));
    TEST_CHECK(marker->IsNull(1));

    ret = flb_aws_compression_compress_protobuf_columnar(
                FLB_AWS_COMPRESS_FORMAT_PARQUET, schema,
                records, 2, &output, &output_size,
                FLB_AWS_COMPRESS_ZSTD, error, sizeof(error));
    TEST_ASSERT_(ret == 0, "%s", error);
    TEST_ASSERT(output != nullptr);
    TEST_ASSERT(output_size >= 8);
    TEST_CHECK(memcmp(output, "PAR1", 4) == 0);
    TEST_CHECK(memcmp(static_cast<char *>(output) + output_size - 4,
                      "PAR1", 4) == 0);

    {
        std::shared_ptr<arrow::io::BufferReader> input;
        std::unique_ptr<parquet::ParquetFileReader> reader;
        std::shared_ptr<parquet::FileMetaData> metadata;

        input = std::make_shared<arrow::io::BufferReader>(
                    static_cast<const uint8_t *>(output),
                    static_cast<int64_t>(output_size));
        reader = parquet::ParquetFileReader::Open(input);
        metadata = reader->metadata();
        TEST_ASSERT(metadata != nullptr);
        TEST_CHECK(metadata->num_rows() == 2);
        TEST_CHECK(metadata->schema()->group_node()->field_count() == 9);
    }

    flb_free(output);
    flb_aws_protobuf_schema_destroy(schema);
}

void test_protobuf_rejects_invalid_descriptor()
{
    const char descriptor[] = "not-a-descriptor";
    struct flb_aws_protobuf_schema *schema;
    char error[256] = {0};

    schema = flb_aws_protobuf_schema_create(
                descriptor, sizeof(descriptor) - 1,
                "fluent.test.WireLog", error, sizeof(error));
    TEST_CHECK(schema == nullptr);
    TEST_CHECK(strstr(error, "FileDescriptorSet") != nullptr);
}

void test_protobuf_rejects_unknown_message()
{
    std::string descriptor = read_descriptor();
    struct flb_aws_protobuf_schema *schema;
    char error[256] = {0};

    TEST_ASSERT(!descriptor.empty());
    schema = load_schema(descriptor, "fluent.test.Unknown",
                         error, sizeof(error));
    TEST_CHECK(schema == nullptr);
    TEST_CHECK(strstr(error, "not found") != nullptr);
}

void test_protobuf_rejects_recursive_schema()
{
    std::string descriptor = read_descriptor();
    struct flb_aws_protobuf_schema *schema;
    char error[256] = {0};

    TEST_ASSERT(!descriptor.empty());
    schema = load_schema(descriptor, "fluent.test.Recursive",
                         error, sizeof(error));
    TEST_CHECK(schema == nullptr);
    TEST_CHECK(strstr(error, "recursive") != nullptr);
}

void test_protobuf_rejects_invalid_record()
{
    std::string descriptor = read_descriptor();
    struct flb_aws_protobuf_schema *schema;
    struct flb_aws_protobuf_record record = {
        invalid_wire_log_record,
        sizeof(invalid_wire_log_record)
    };
    void *output = nullptr;
    size_t output_size = 0;
    char error[256] = {0};
    int ret;

    TEST_ASSERT(!descriptor.empty());
    schema = load_schema(descriptor, "fluent.test.WireLog",
                         error, sizeof(error));
    TEST_ASSERT_(schema != nullptr, "%s", error);

    ret = flb_aws_compression_compress_protobuf_columnar(
                FLB_AWS_COMPRESS_FORMAT_PARQUET, schema,
                &record, 1, &output, &output_size,
                FLB_AWS_COMPRESS_ZSTD, error, sizeof(error));
    TEST_CHECK(ret == -1);
    TEST_CHECK(output == nullptr);
    TEST_CHECK(strstr(error, "failed to decode") != nullptr);

    flb_aws_protobuf_schema_destroy(schema);
}

} /* namespace */

TEST_LIST = {
    {"protobuf_to_parquet_preserves_types",
     test_protobuf_to_parquet_preserves_types},
    {"protobuf_rejects_invalid_descriptor",
     test_protobuf_rejects_invalid_descriptor},
    {"protobuf_rejects_unknown_message",
     test_protobuf_rejects_unknown_message},
    {"protobuf_rejects_recursive_schema",
     test_protobuf_rejects_recursive_schema},
    {"protobuf_rejects_invalid_record",
     test_protobuf_rejects_invalid_record},
    {nullptr, nullptr}
};
