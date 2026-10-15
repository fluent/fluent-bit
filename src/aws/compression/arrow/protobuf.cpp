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

#include "compress.h"
#include "protobuf.h"

#include <fluent-bit/aws/flb_aws_compress.h>

#include <arrow/api.h>
#include <arrow-glib/table.hpp>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>
#include <google/protobuf/descriptor_database.h>
#include <google/protobuf/dynamic_message.h>
#include <google/protobuf/message.h>

#include <algorithm>
#include <climits>
#include <cstdio>
#include <exception>
#include <memory>
#include <string>
#include <vector>

namespace pb = google::protobuf;

namespace {

constexpr size_t MAX_DESCRIPTOR_SET_SIZE = 16 * 1024 * 1024;
constexpr int MAX_DESCRIPTOR_FILES = 4096;
constexpr size_t MAX_SCHEMA_DEPTH = 64;
const unsigned char EMPTY_PROTOBUF_RECORD = 0;

class DescriptorErrors : public pb::DescriptorPool::ErrorCollector {
public:
    std::string text;

    void AddError(const std::string &filename,
                  const std::string &element_name,
                  const pb::Message *,
                  ErrorLocation,
                  const std::string &message) override
    {
        if (!text.empty()) {
            return;
        }

        text = filename;
        if (!element_name.empty()) {
            text += ": ";
            text += element_name;
        }
        text += ": ";
        text += message;
    }
};

void report_error(char *error, size_t error_size, const std::string &message)
{
    if (error != nullptr && error_size > 0) {
        std::snprintf(error, error_size, "%s", message.c_str());
    }
}

void clear_error(char *error, size_t error_size)
{
    if (error != nullptr && error_size > 0) {
        error[0] = '\0';
    }
}

bool is_opaque_well_known_type(const pb::Descriptor *descriptor)
{
    const std::string &name = descriptor->full_name();

    /*
     * Struct and Value describe dynamically typed, recursive data. There is
     * no finite Arrow schema that can represent every possible value, so keep
     * their original Protobuf encoding instead of guessing a schema.
     */
    return name == "google.protobuf.Struct" ||
           name == "google.protobuf.Value" ||
           name == "google.protobuf.ListValue";
}

bool protobuf_field_nullable(const pb::FieldDescriptor *field)
{
    return !field->is_repeated() &&
           !field->is_required() &&
           field->has_presence();
}

arrow::Status protobuf_message_type(
                      const pb::Descriptor *descriptor,
                      std::vector<const pb::Descriptor *> *path,
                      std::shared_ptr<arrow::DataType> *out);

arrow::Status protobuf_singular_type(
                      const pb::FieldDescriptor *field,
                      std::vector<const pb::Descriptor *> *path,
                      std::shared_ptr<arrow::DataType> *out)
{
    switch (field->cpp_type()) {
    case pb::FieldDescriptor::CPPTYPE_DOUBLE:
        *out = arrow::float64();
        return arrow::Status::OK();
    case pb::FieldDescriptor::CPPTYPE_FLOAT:
        *out = arrow::float32();
        return arrow::Status::OK();
    case pb::FieldDescriptor::CPPTYPE_INT64:
        *out = arrow::int64();
        return arrow::Status::OK();
    case pb::FieldDescriptor::CPPTYPE_UINT64:
        *out = arrow::uint64();
        return arrow::Status::OK();
    case pb::FieldDescriptor::CPPTYPE_INT32:
        *out = arrow::int32();
        return arrow::Status::OK();
    case pb::FieldDescriptor::CPPTYPE_UINT32:
        *out = arrow::uint32();
        return arrow::Status::OK();
    case pb::FieldDescriptor::CPPTYPE_BOOL:
        *out = arrow::boolean();
        return arrow::Status::OK();
    case pb::FieldDescriptor::CPPTYPE_ENUM:
        *out = arrow::int32();
        return arrow::Status::OK();
    case pb::FieldDescriptor::CPPTYPE_STRING:
        if (field->type() == pb::FieldDescriptor::TYPE_BYTES) {
            *out = arrow::binary();
        }
        else {
            *out = arrow::utf8();
        }
        return arrow::Status::OK();
    case pb::FieldDescriptor::CPPTYPE_MESSAGE:
        return protobuf_message_type(field->message_type(), path, out);
    }

    return arrow::Status::Invalid("unsupported Protobuf field type for ",
                                  field->full_name());
}

arrow::Status protobuf_field_type(
                      const pb::FieldDescriptor *field,
                      std::vector<const pb::Descriptor *> *path,
                      std::shared_ptr<arrow::DataType> *out)
{
    std::shared_ptr<arrow::DataType> value_type;
    std::shared_ptr<arrow::DataType> key_type;
    const pb::Descriptor *entry;
    const pb::FieldDescriptor *key;
    const pb::FieldDescriptor *value;
    arrow::Status status;

    if (field->is_map()) {
        entry = field->message_type();
        key = entry->FindFieldByName("key");
        value = entry->FindFieldByName("value");
        if (key == nullptr || value == nullptr) {
            return arrow::Status::Invalid("invalid Protobuf map descriptor for ",
                                          field->full_name());
        }

        status = protobuf_singular_type(key, path, &key_type);
        if (!status.ok()) {
            return status;
        }
        status = protobuf_singular_type(value, path, &value_type);
        if (!status.ok()) {
            return status;
        }

        *out = arrow::map(key_type, value_type);
        return arrow::Status::OK();
    }

    status = protobuf_singular_type(field, path, &value_type);
    if (!status.ok()) {
        return status;
    }

    if (field->is_repeated()) {
        *out = arrow::list(value_type);
    }
    else {
        *out = value_type;
    }
    return arrow::Status::OK();
}

arrow::Status protobuf_message_type(
                      const pb::Descriptor *descriptor,
                      std::vector<const pb::Descriptor *> *path,
                      std::shared_ptr<arrow::DataType> *out)
{
    std::vector<std::shared_ptr<arrow::Field>> fields;
    std::shared_ptr<arrow::DataType> type;
    const pb::FieldDescriptor *field;
    arrow::Status status;
    int i;

    if (descriptor->field_count() == 0) {
        /*
         * A zero-field message still carries presence information. Represent
         * it as true when present and null when absent so Parquet never sees
         * an invalid zero-child struct.
         */
        *out = arrow::boolean();
        return arrow::Status::OK();
    }

    if (is_opaque_well_known_type(descriptor)) {
        *out = arrow::binary();
        return arrow::Status::OK();
    }

    if (std::find(path->begin(), path->end(), descriptor) != path->end()) {
        return arrow::Status::Invalid(
                    "recursive Protobuf message cannot be represented as a "
                    "finite Arrow schema: ", descriptor->full_name());
    }
    if (path->size() >= MAX_SCHEMA_DEPTH) {
        return arrow::Status::Invalid(
                    "Protobuf schema nesting exceeds supported depth: ",
                    descriptor->full_name());
    }

    path->push_back(descriptor);
    fields.reserve(descriptor->field_count());
    for (i = 0; i < descriptor->field_count(); i++) {
        field = descriptor->field(i);
        status = protobuf_field_type(field, path, &type);
        if (!status.ok()) {
            path->pop_back();
            return status;
        }
        fields.push_back(arrow::field(field->name(), type,
                                      protobuf_field_nullable(field)));
    }
    path->pop_back();

    *out = arrow::struct_(fields);
    return arrow::Status::OK();
}

arrow::Status protobuf_schema(
                      const pb::Descriptor *descriptor,
                      std::shared_ptr<arrow::Schema> *out)
{
    std::vector<std::shared_ptr<arrow::Field>> fields;
    std::vector<const pb::Descriptor *> path;
    std::shared_ptr<arrow::DataType> type;
    const pb::FieldDescriptor *field;
    arrow::Status status;
    int i;

    if (descriptor->field_count() == 0) {
        return arrow::Status::Invalid(
                    "root Protobuf message must contain at least one field");
    }

    path.push_back(descriptor);
    fields.reserve(descriptor->field_count());
    for (i = 0; i < descriptor->field_count(); i++) {
        field = descriptor->field(i);
        status = protobuf_field_type(field, &path, &type);
        if (!status.ok()) {
            return status;
        }
        fields.push_back(arrow::field(field->name(), type,
                                      protobuf_field_nullable(field)));
    }

    *out = arrow::schema(fields);
    return arrow::Status::OK();
}

arrow::Status append_field(const pb::Message &message,
                           const pb::FieldDescriptor *field,
                           arrow::ArrayBuilder *builder);

arrow::Status append_message(const pb::Message &value,
                             const pb::FieldDescriptor *field,
                             arrow::ArrayBuilder *builder)
{
    arrow::StructBuilder *struct_builder;
    arrow::BinaryBuilder *binary_builder;
    arrow::BooleanBuilder *boolean_builder;
    const pb::Descriptor *descriptor;
    std::string encoded;
    arrow::Status status;
    int i;

    descriptor = field->message_type();
    switch (builder->type()->id()) {
    case arrow::Type::BOOL:
        boolean_builder = static_cast<arrow::BooleanBuilder *>(builder);
        return boolean_builder->Append(true);
    case arrow::Type::BINARY:
        if (!value.SerializeToString(&encoded)) {
            return arrow::Status::Invalid(
                        "failed to serialize opaque Protobuf field ",
                        field->full_name());
        }
        if (encoded.size() > INT32_MAX) {
            return arrow::Status::CapacityError(
                        "opaque Protobuf field exceeds Arrow binary limit: ",
                        field->full_name());
        }
        binary_builder = static_cast<arrow::BinaryBuilder *>(builder);
        return binary_builder->Append(encoded.data(),
                                      static_cast<int32_t>(encoded.size()));
    case arrow::Type::STRUCT:
        struct_builder = static_cast<arrow::StructBuilder *>(builder);
        status = struct_builder->Append();
        if (!status.ok()) {
            return status;
        }
        for (i = 0; i < descriptor->field_count(); i++) {
            status = append_field(value, descriptor->field(i),
                                  struct_builder->field_builder(i));
            if (!status.ok()) {
                return status;
            }
        }
        return arrow::Status::OK();
    default:
        return arrow::Status::Invalid(
                    "unexpected Arrow type for Protobuf message field ",
                    field->full_name());
    }
}

arrow::Status append_singular(const pb::Message &message,
                              const pb::FieldDescriptor *field,
                              int repeated_index,
                              arrow::ArrayBuilder *builder)
{
    const pb::Reflection *reflection = message.GetReflection();
    const pb::Message *message_value;
    const pb::EnumValueDescriptor *enum_value;
    std::string string_value;
    bool repeated = repeated_index >= 0;

    if (!repeated && field->has_presence() &&
        !reflection->HasField(message, field)) {
        return builder->AppendNull();
    }

    switch (field->cpp_type()) {
    case pb::FieldDescriptor::CPPTYPE_DOUBLE:
        return static_cast<arrow::DoubleBuilder *>(builder)->Append(
                    repeated ?
                    reflection->GetRepeatedDouble(message, field,
                                                  repeated_index) :
                    reflection->GetDouble(message, field));
    case pb::FieldDescriptor::CPPTYPE_FLOAT:
        return static_cast<arrow::FloatBuilder *>(builder)->Append(
                    repeated ?
                    reflection->GetRepeatedFloat(message, field,
                                                 repeated_index) :
                    reflection->GetFloat(message, field));
    case pb::FieldDescriptor::CPPTYPE_INT64:
        return static_cast<arrow::Int64Builder *>(builder)->Append(
                    repeated ?
                    reflection->GetRepeatedInt64(message, field,
                                                 repeated_index) :
                    reflection->GetInt64(message, field));
    case pb::FieldDescriptor::CPPTYPE_UINT64:
        return static_cast<arrow::UInt64Builder *>(builder)->Append(
                    repeated ?
                    reflection->GetRepeatedUInt64(message, field,
                                                  repeated_index) :
                    reflection->GetUInt64(message, field));
    case pb::FieldDescriptor::CPPTYPE_INT32:
        return static_cast<arrow::Int32Builder *>(builder)->Append(
                    repeated ?
                    reflection->GetRepeatedInt32(message, field,
                                                 repeated_index) :
                    reflection->GetInt32(message, field));
    case pb::FieldDescriptor::CPPTYPE_UINT32:
        return static_cast<arrow::UInt32Builder *>(builder)->Append(
                    repeated ?
                    reflection->GetRepeatedUInt32(message, field,
                                                  repeated_index) :
                    reflection->GetUInt32(message, field));
    case pb::FieldDescriptor::CPPTYPE_BOOL:
        return static_cast<arrow::BooleanBuilder *>(builder)->Append(
                    repeated ?
                    reflection->GetRepeatedBool(message, field,
                                                repeated_index) :
                    reflection->GetBool(message, field));
    case pb::FieldDescriptor::CPPTYPE_ENUM:
        enum_value = repeated ?
                     reflection->GetRepeatedEnum(message, field,
                                                 repeated_index) :
                     reflection->GetEnum(message, field);
        return static_cast<arrow::Int32Builder *>(builder)->Append(
                    enum_value->number());
    case pb::FieldDescriptor::CPPTYPE_STRING:
        string_value = repeated ?
                       reflection->GetRepeatedString(message, field,
                                                     repeated_index) :
                       reflection->GetString(message, field);
        if (string_value.size() > INT32_MAX) {
            return arrow::Status::CapacityError(
                        "Protobuf string exceeds Arrow binary limit: ",
                        field->full_name());
        }
        if (field->type() == pb::FieldDescriptor::TYPE_BYTES) {
            return static_cast<arrow::BinaryBuilder *>(builder)->Append(
                        string_value.data(),
                        static_cast<int32_t>(string_value.size()));
        }
        return static_cast<arrow::StringBuilder *>(builder)->Append(
                    string_value);
    case pb::FieldDescriptor::CPPTYPE_MESSAGE:
        message_value = repeated ?
                        &reflection->GetRepeatedMessage(message, field,
                                                       repeated_index) :
                        &reflection->GetMessage(message, field);
        return append_message(*message_value, field, builder);
    }

    return arrow::Status::Invalid("unsupported Protobuf field ",
                                  field->full_name());
}

arrow::Status append_map(const pb::Message &message,
                         const pb::FieldDescriptor *field,
                         arrow::ArrayBuilder *builder)
{
    arrow::MapBuilder *map_builder;
    const pb::Reflection *reflection;
    const pb::Descriptor *entry;
    const pb::FieldDescriptor *key;
    const pb::FieldDescriptor *value;
    const pb::Message *item;
    arrow::Status status;
    int count;
    int i;

    map_builder = static_cast<arrow::MapBuilder *>(builder);
    reflection = message.GetReflection();
    entry = field->message_type();
    key = entry->FindFieldByName("key");
    value = entry->FindFieldByName("value");
    count = reflection->FieldSize(message, field);

    status = map_builder->Append();
    if (!status.ok()) {
        return status;
    }

    for (i = 0; i < count; i++) {
        item = &reflection->GetRepeatedMessage(message, field, i);
        status = append_singular(*item, key, -1,
                                 map_builder->key_builder());
        if (!status.ok()) {
            return status;
        }
        status = append_singular(*item, value, -1,
                                 map_builder->item_builder());
        if (!status.ok()) {
            return status;
        }
    }

    return arrow::Status::OK();
}

arrow::Status append_repeated(const pb::Message &message,
                              const pb::FieldDescriptor *field,
                              arrow::ArrayBuilder *builder)
{
    arrow::ListBuilder *list_builder;
    const pb::Reflection *reflection;
    arrow::Status status;
    int count;
    int i;

    list_builder = static_cast<arrow::ListBuilder *>(builder);
    reflection = message.GetReflection();
    count = reflection->FieldSize(message, field);

    status = list_builder->Append();
    if (!status.ok()) {
        return status;
    }

    for (i = 0; i < count; i++) {
        status = append_singular(message, field, i,
                                 list_builder->value_builder());
        if (!status.ok()) {
            return status;
        }
    }

    return arrow::Status::OK();
}

arrow::Status append_field(const pb::Message &message,
                           const pb::FieldDescriptor *field,
                           arrow::ArrayBuilder *builder)
{
    if (field->is_map()) {
        return append_map(message, field, builder);
    }
    if (field->is_repeated()) {
        return append_repeated(message, field, builder);
    }
    return append_singular(message, field, -1, builder);
}

} /* namespace */

struct flb_aws_protobuf_schema {
    pb::SimpleDescriptorDatabase descriptors;
    pb::DescriptorPoolDatabase generated;
    pb::MergedDescriptorDatabase merged;
    DescriptorErrors errors;
    pb::DescriptorPool pool;
    pb::DynamicMessageFactory factory;
    const pb::Descriptor *message_descriptor;
    const pb::Message *prototype;
    std::shared_ptr<arrow::Schema> arrow_schema;

    flb_aws_protobuf_schema() :
        generated(*pb::DescriptorPool::generated_pool()),
        merged(&descriptors, &generated),
        pool(&merged, &errors),
        factory(&pool),
        message_descriptor(nullptr),
        prototype(nullptr)
    {
    }
};

extern "C" struct flb_aws_protobuf_schema *
flb_aws_protobuf_schema_create(const void *descriptor_set,
                               size_t descriptor_set_size,
                               const char *message_type,
                               char *error, size_t error_size)
{
    std::unique_ptr<flb_aws_protobuf_schema> schema;
    pb::FileDescriptorSet files;
    std::string name;
    arrow::Status status;
    int i;

    try {
        clear_error(error, error_size);

        if (descriptor_set == nullptr || descriptor_set_size == 0 ||
            descriptor_set_size > MAX_DESCRIPTOR_SET_SIZE ||
            descriptor_set_size > INT_MAX ||
            message_type == nullptr || message_type[0] == '\0') {
            report_error(error, error_size,
                         "invalid Protobuf descriptor configuration");
            return nullptr;
        }

        if (!files.ParseFromArray(descriptor_set,
                                  static_cast<int>(descriptor_set_size))) {
            report_error(error, error_size,
                         "invalid Protobuf FileDescriptorSet");
            return nullptr;
        }
        if (files.file_size() == 0 ||
            files.file_size() > MAX_DESCRIPTOR_FILES) {
            report_error(error, error_size,
                         "invalid Protobuf descriptor file count");
            return nullptr;
        }

        schema.reset(new flb_aws_protobuf_schema());
        for (i = 0; i < files.file_size(); i++) {
            if (!schema->descriptors.Add(files.file(i))) {
                report_error(error, error_size,
                             "duplicate or invalid Protobuf file descriptor");
                return nullptr;
            }
        }

        name = message_type;
        if (!name.empty() && name[0] == '.') {
            name.erase(0, 1);
        }
        schema->message_descriptor =
                    schema->pool.FindMessageTypeByName(name);
        if (schema->message_descriptor == nullptr) {
            if (!schema->errors.text.empty()) {
                report_error(error, error_size, schema->errors.text);
            }
            else {
                report_error(error, error_size,
                             "Protobuf message type not found: " + name);
            }
            return nullptr;
        }
        if (schema->message_descriptor->options().map_entry()) {
            report_error(error, error_size,
                         "Protobuf root message cannot be a map entry");
            return nullptr;
        }

        status = protobuf_schema(schema->message_descriptor,
                                 &schema->arrow_schema);
        if (!status.ok()) {
            report_error(error, error_size, status.ToString());
            return nullptr;
        }

        schema->prototype =
                    schema->factory.GetPrototype(
                        schema->message_descriptor);
        if (schema->prototype == nullptr) {
            report_error(error, error_size,
                         "cannot create Protobuf message prototype");
            return nullptr;
        }

        return schema.release();
    }
    catch (const std::exception &exception) {
        report_error(error, error_size, exception.what());
        return nullptr;
    }
    catch (...) {
        report_error(error, error_size,
                     "exception while loading Protobuf descriptor");
        return nullptr;
    }
}

extern "C" void
flb_aws_protobuf_schema_destroy(struct flb_aws_protobuf_schema *schema)
{
    delete schema;
}

arrow::Status flb_aws_protobuf_records_to_arrow_table(
                    struct flb_aws_protobuf_schema *schema,
                    const struct flb_aws_protobuf_record *records,
                    size_t record_count,
                    std::shared_ptr<arrow::Table> *table)
{
    std::unique_ptr<arrow::RecordBatchBuilder> builder;
    std::unique_ptr<pb::Message> message;
    std::shared_ptr<arrow::RecordBatch> batch;
    std::vector<std::shared_ptr<arrow::RecordBatch>> batches;
    arrow::Result<std::shared_ptr<arrow::Table>> table_result;
    arrow::Status status;
    const void *record_data;
    size_t row;
    int field;

    if (schema == nullptr || records == nullptr || record_count == 0 ||
        record_count > INT64_MAX || table == nullptr) {
        return arrow::Status::Invalid("invalid Protobuf record batch");
    }

    status = arrow::RecordBatchBuilder::Make(
                schema->arrow_schema, arrow::default_memory_pool(),
                static_cast<int64_t>(record_count), &builder);
    if (!status.ok()) {
        return status;
    }

    message.reset(schema->prototype->New());
    if (message == nullptr) {
        return arrow::Status::OutOfMemory(
                    "cannot allocate Protobuf message");
    }

    for (row = 0; row < record_count; row++) {
        if ((records[row].data == nullptr && records[row].size != 0) ||
            records[row].size > INT_MAX) {
            return arrow::Status::Invalid("invalid Protobuf record");
        }

        record_data = records[row].data;
        if (record_data == nullptr) {
            record_data = &EMPTY_PROTOBUF_RECORD;
        }

        message->Clear();
        if (!message->ParseFromArray(
                record_data,
                static_cast<int>(records[row].size))) {
            return arrow::Status::Invalid(
                        "failed to decode Protobuf record ",
                        row);
        }
        if (!message->IsInitialized()) {
            return arrow::Status::Invalid(
                        "missing required fields in Protobuf record ",
                        row);
        }

        for (field = 0;
             field < schema->message_descriptor->field_count();
             field++) {
            status = append_field(
                        *message,
                        schema->message_descriptor->field(field),
                        builder->GetField(field));
            if (!status.ok()) {
                return status;
            }
        }
    }

    status = builder->Flush(&batch);
    if (!status.ok()) {
        return status;
    }

    batches.push_back(batch);
    table_result = arrow::Table::FromRecordBatches(
                        schema->arrow_schema, batches);
    if (!table_result.ok()) {
        return table_result.status();
    }

    *table = table_result.ValueOrDie();
    return arrow::Status::OK();
}

extern "C" int flb_aws_compression_compress_protobuf_columnar(
                                  int columnar_format,
                                  struct flb_aws_protobuf_schema *schema,
                                  const struct flb_aws_protobuf_record *records,
                                  size_t record_count,
                                  void **out_buf, size_t *out_size,
                                  int compression_type,
                                  char *error, size_t error_size)
{
    std::shared_ptr<arrow::Table> table;
    GArrowTable *gtable;
    arrow::Status status;
    int ret;

    try {
        clear_error(error, error_size);

        if (out_buf != nullptr) {
            *out_buf = nullptr;
        }
        if (out_size != nullptr) {
            *out_size = 0;
        }

        if (out_buf == nullptr || out_size == nullptr) {
            report_error(error, error_size, "invalid output buffer");
            return -1;
        }

        status = flb_aws_protobuf_records_to_arrow_table(
                    schema, records, record_count, &table);
        if (!status.ok()) {
            report_error(error, error_size, status.ToString());
            return -1;
        }

        gtable = garrow_table_new_raw(&table);
        if (gtable == nullptr) {
            report_error(error, error_size,
                         "failed to create Arrow table");
            return -1;
        }

        ret = flb_aws_compression_write_columnar_table(
                    columnar_format, gtable, out_buf, out_size,
                    compression_type);
        g_object_unref(gtable);
        if (ret != 0) {
            report_error(error, error_size,
                         "failed to write Protobuf Arrow table");
            return -1;
        }

        return 0;
    }
    catch (const std::exception &exception) {
        report_error(error, error_size, exception.what());
        return -1;
    }
    catch (...) {
        report_error(error, error_size,
                     "exception while converting Protobuf records");
        return -1;
    }
}
