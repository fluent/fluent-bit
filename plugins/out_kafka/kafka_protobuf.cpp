/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include "kafka_protobuf.h"

#include <google/protobuf/compiler/importer.h>
#include <google/protobuf/descriptor_database.h>
#include <google/protobuf/dynamic_message.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/util/json_util.h>
/* Register the standard imports in the generated descriptor pool. */
#include <google/protobuf/any.pb.h>
#include <google/protobuf/api.pb.h>
#include <google/protobuf/duration.pb.h>
#include <google/protobuf/empty.pb.h>
#include <google/protobuf/field_mask.pb.h>
#include <google/protobuf/struct.pb.h>
#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/wrappers.pb.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace pb = google::protobuf;

namespace {
class RegistrySources : public pb::compiler::SourceTree {
public:
    std::map<std::string, std::string> files;
    size_t bytes = 0;

    pb::io::ZeroCopyInputStream *Open(const std::string &name) override
    {
        auto it = files.find(name);
        if (it == files.end()) {
            return nullptr;
        }
        return new pb::io::ArrayInputStream(it->second.data(), it->second.size());
    }
};

class SchemaErrors : public pb::compiler::MultiFileErrorCollector {
public:
    std::string text;

    void AddError(const std::string &file, int line, int column,
                  const std::string &message) override
    {
        if (text.empty()) {
            text = file + ":" + std::to_string(line + 1) + ":" +
                   std::to_string(column + 1) + ": " + message;
        }
    }
};

void report_error(char *error, size_t size, const char *message)
{
    if (error != nullptr && size != 0) {
        std::snprintf(error, size, "%s", message);
    }
}

void append_varint(std::string &out, uint32_t value)
{
    while (value >= 128) {
        out.push_back(static_cast<char>((value & 127) | 128));
        value >>= 7;
    }
    out.push_back(static_cast<char>(value));
}
}

struct flb_kafka_protobuf {
    RegistrySources sources;
    SchemaErrors errors;
    pb::DescriptorPoolDatabase generated{*pb::DescriptorPool::generated_pool()};
    pb::compiler::SourceTreeDescriptorDatabase database{&sources, &generated};
    pb::DescriptorPool pool{&database, database.GetValidationErrorCollector()};
    pb::DynamicMessageFactory factory{&pool};
    const pb::Message *prototype = nullptr;
    std::string indexes;

    flb_kafka_protobuf()
    {
        /* Force well-known descriptor objects into static as well as shared builds. */
        pb::Any::descriptor();
        pb::Api::descriptor();
        pb::Duration::descriptor();
        pb::Empty::descriptor();
        pb::FieldMask::descriptor();
        pb::Struct::descriptor();
        pb::Timestamp::descriptor();
        pb::DoubleValue::descriptor();
        database.RecordErrorsTo(&errors);
    }
};

struct flb_kafka_protobuf *flb_kafka_protobuf_create(void) noexcept
{
    try {
        /* Release Protobuf's process-wide descriptor cache only at process exit.
         * Plugin teardown may be followed by hot reload or another output instance.
         */
        static const int shutdown_registered = std::atexit(pb::ShutdownProtobufLibrary);
        if (shutdown_registered != 0) {
            return nullptr;
        }
        return new flb_kafka_protobuf;
    }
    catch (...) {
        return nullptr;
    }
}

int flb_kafka_protobuf_add(struct flb_kafka_protobuf *ctx,
                         const char *name, const char *schema, size_t size) noexcept
{
    try {
        std::map<std::string, std::string>::iterator previous;

        if (ctx == nullptr || name == nullptr || schema == nullptr ||
            ctx->prototype != nullptr || size > FLB_KAFKA_PROTOBUF_MAX_SCHEMA_BYTES ||
            ctx->sources.bytes > FLB_KAFKA_PROTOBUF_MAX_SCHEMA_BYTES - size) {
            return -1;
        }
        previous = ctx->sources.files.find(name);
        if (previous != ctx->sources.files.end()) {
            return previous->second == std::string(schema, size) ? 0 : -1;
        }
        if (ctx->sources.files.size() >= FLB_KAFKA_PROTOBUF_MAX_FILES) {
            return -1;
        }
        ctx->sources.files.emplace(name, std::string(schema, size));
        ctx->sources.bytes += size;
        return 0;
    }
    catch (...) {
        return -1;
    }
}

int flb_kafka_protobuf_compile(struct flb_kafka_protobuf *ctx,
                             const char *message, char *error, size_t error_size) noexcept
{
    try {
        const pb::FileDescriptor *file;
        const pb::Descriptor *descriptor = nullptr;
        const pb::Descriptor *current;
        const pb::Descriptor *parent;
        std::vector<uint32_t> path;
        uint32_t index;
        int i;

        if (ctx == nullptr || ctx->prototype != nullptr) {
            report_error(error, error_size, "invalid Protobuf schema state");
            return -1;
        }
        file = ctx->pool.FindFileByName(FLB_KAFKA_PROTOBUF_ROOT);
        if (file == nullptr) {
            report_error(error, error_size, ctx->errors.text.c_str());
            return -1;
        }
        if (message != nullptr && message[0] != '\0') {
            descriptor = ctx->pool.FindMessageTypeByName(message);
        }
        else if (file->message_type_count() == 1) {
            descriptor = file->message_type(0);
        }
        if (descriptor == nullptr || descriptor->file() != file || descriptor->options().map_entry()) {
            report_error(error, error_size,
                         "protobuf_message must select a message in the registered root schema");
            return -1;
        }

        for (current = descriptor; current != nullptr;
             current = current->containing_type()) {
            index = 0;
            parent = current->containing_type();
            /* Map entries are synthetic descriptors, absent from the .proto source indexes. */
            for (i = 0; i < current->index(); i++) {
                if (parent == nullptr || !parent->nested_type(i)->options().map_entry()) {
                    index++;
                }
            }
            path.push_back(index);
        }
        std::reverse(path.begin(), path.end());
        if (path.size() == 1 && path[0] == 0) {
            ctx->indexes.push_back(0);
        }
        else {
            append_varint(ctx->indexes, static_cast<uint32_t>(path.size()) << 1);
            for (uint32_t index : path) {
                append_varint(ctx->indexes, index << 1);
            }
        }
        ctx->prototype = ctx->factory.GetPrototype(descriptor);
        if (ctx->prototype == nullptr) {
            report_error(error, error_size, "cannot create Protobuf message prototype");
            return -1;
        }
        return 0;
    }
    catch (...) {
        report_error(error, error_size, "exception while compiling Protobuf schema");
        return -1;
    }
}

int flb_kafka_protobuf_encode(struct flb_kafka_protobuf *ctx, int32_t schema_id,
                            const char *json, size_t json_size,
                            char **out, size_t *out_size,
                            char *error, size_t error_size) noexcept
{
    *out = nullptr;
    *out_size = 0;
    try {
        std::unique_ptr<pb::Message> message;
        pb::util::JsonParseOptions options;
        decltype(pb::util::JsonStringToMessage(std::string(), nullptr)) status;
        std::string payload;
        char *result;
        int shift;

        if (ctx == nullptr || ctx->prototype == nullptr || schema_id <= 0 || json == nullptr) {
            report_error(error, error_size, "invalid Protobuf encoder state");
            return -1;
        }
        message.reset(ctx->prototype->New());
        options.ignore_unknown_fields = false;
        status = pb::util::JsonStringToMessage(std::string(json, json_size), message.get(), options);
        if (!status.ok()) {
            report_error(error, error_size, status.ToString().c_str());
            return -1;
        }
        if (!message->IsInitialized()) {
            report_error(error, error_size, "missing required Protobuf fields");
            return -1;
        }
        payload.push_back(0);
        for (shift = 24; shift >= 0; shift -= 8) {
            payload.push_back(static_cast<char>((static_cast<uint32_t>(schema_id) >> shift) & 255));
        }
        payload += ctx->indexes;
        if (!message->AppendToString(&payload)) {
            report_error(error, error_size, "cannot serialize Protobuf message");
            return -1;
        }
        result = static_cast<char *>(std::malloc(payload.size()));
        if (result == nullptr) {
            report_error(error, error_size, "cannot allocate Protobuf payload");
            return -1;
        }
        std::memcpy(result, payload.data(), payload.size());
        *out = result;
        *out_size = payload.size();
        return 0;
    }
    catch (...) {
        report_error(error, error_size, "exception while encoding Protobuf message");
        return -1;
    }
}

void flb_kafka_protobuf_free(void *payload) noexcept
{
    std::free(payload);
}

void flb_kafka_protobuf_destroy(struct flb_kafka_protobuf *ctx) noexcept
{
    delete ctx;
}
