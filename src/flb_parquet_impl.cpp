/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <arrow/api.h>
#include <arrow/io/api.h>
#include <parquet/arrow/writer.h>
#include <parquet/exception.h>

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>

extern "C" {
#include <fluent-bit/flb_macros.h>  // FLB_FALSE
#include <fluent-bit/flb_log.h>     // flb_error, flb_debug, flb_warn
#include <fluent-bit/flb_mem.h>     // flb_malloc, flb_free
#include <fluent-bit/flb_parquet.h> // Function signature
#include <msgpack.h>                // msgpack_object, msgpack_unpacked, etc.
#include <yyjson.h>                 // JSON parsing

/* Forward declarations to avoid including flb_pack.h which transitively includes mpack.h
 * mpack.h has C function overloading that conflicts with C++ compilation */
char* flb_msgpack_to_json_str(size_t size, const msgpack_object *obj, int escape_unicode);
}

namespace {

// Constants
constexpr size_t INITIAL_PARQUET_BUFFER_SIZE = 16 * 1024;  // 16KB initial buffer for Arrow
constexpr int MAX_JSON_NESTING_DEPTH = 32;                 // Prevent stack overflow

// Helper function to convert msgpack object to JSON string using Fluent Bit's function
std::string msgpack_object_to_json_string(const msgpack_object* obj) {
    /* Use Fluent Bit's built-in msgpack to JSON converter */
    char *json_str = flb_msgpack_to_json_str(256, obj, FLB_FALSE);
    if (!json_str) {
        return "{}";
    }

    std::string result(json_str);
    flb_free(json_str);
    return result;
}

// Convert msgpack object to Arrow array builders
class MsgpackToArrowConverter {
public:
    /* Statistics for overflow/clamping operations - per field */
    std::unordered_map<std::string, size_t> int32_overflow_by_field;
    std::unordered_map<std::string, size_t> int64_overflow_by_field;
    std::unordered_map<std::string, size_t> float_to_int_clamp_by_field;

    /* Statistics for type conversions - per field */
    std::unordered_map<std::string, size_t> complex_to_string_by_field;
    std::unordered_map<std::string, size_t> string_parsed_to_int_by_field;
    std::unordered_map<std::string, size_t> string_parsed_to_float_by_field;
    std::unordered_map<std::string, size_t> string_parsed_to_bool_by_field;

    arrow::Status convert_value(const msgpack_object* obj,
                                arrow::ArrayBuilder* builder,
                                const std::shared_ptr<arrow::DataType>& type,
                                const std::string& field_name) {

        // Handle null values
        if (obj->type == MSGPACK_OBJECT_NIL) {
            return builder->AppendNull();
        }

        switch (type->id()) {
            case arrow::Type::BOOL:
                return convert_to_bool(obj, static_cast<arrow::BooleanBuilder*>(builder), field_name);

            case arrow::Type::INT32:
                return convert_to_int32(obj, static_cast<arrow::Int32Builder*>(builder), field_name);

            case arrow::Type::INT64:
                return convert_to_int64(obj, static_cast<arrow::Int64Builder*>(builder), field_name);

            case arrow::Type::FLOAT:
                return convert_to_float(obj, static_cast<arrow::FloatBuilder*>(builder), field_name);

            case arrow::Type::DOUBLE:
                return convert_to_double(obj, static_cast<arrow::DoubleBuilder*>(builder), field_name);

            case arrow::Type::STRING:
                return convert_to_string(obj, static_cast<arrow::StringBuilder*>(builder), field_name);

            case arrow::Type::BINARY:
                return convert_to_binary(obj, static_cast<arrow::BinaryBuilder*>(builder), field_name);

            case arrow::Type::TIMESTAMP:
                return convert_to_timestamp(obj, static_cast<arrow::TimestampBuilder*>(builder), field_name);

            default:
                return arrow::Status::NotImplemented(
                    "Unsupported Arrow type: " + type->ToString());
        }
    }

private:
    arrow::Status convert_to_bool(const msgpack_object* obj, arrow::BooleanBuilder* builder,
                                  const std::string& field_name) {
        if (obj->type == MSGPACK_OBJECT_BOOLEAN) {
            return builder->Append(obj->via.boolean);
        } else if (obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            return builder->Append(obj->via.u64 != 0);
        } else if (obj->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            return builder->Append(obj->via.i64 != 0);
        }
        /* Enhanced: Support string parsing to bool */
        else if (obj->type == MSGPACK_OBJECT_STR) {
            std::string str(obj->via.str.ptr, obj->via.str.size);
            std::transform(str.begin(), str.end(), str.begin(), ::tolower);

            if (str == "true" || str == "1" || str == "yes" || str == "y" || str == "on") {
                string_parsed_to_bool_by_field[field_name]++;
                return builder->Append(true);
            } else if (str == "false" || str == "0" || str == "no" || str == "n" || str == "off") {
                string_parsed_to_bool_by_field[field_name]++;
                return builder->Append(false);
            } else {
                return arrow::Status::Invalid("Cannot parse string to bool");
            }
        }
        else if (obj->type == MSGPACK_OBJECT_FLOAT32 || obj->type == MSGPACK_OBJECT_FLOAT64) {
            return builder->Append(obj->via.f64 != 0.0);
        }
        else {
            /* Return error instead of NULL for type mismatch - let caller decide */
            return arrow::Status::Invalid("Cannot convert msgpack type to bool");
        }
    }

    arrow::Status convert_to_int32(const msgpack_object* obj, arrow::Int32Builder* builder,
                                   const std::string& field_name) {
        if (obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            /* Check for overflow: uint64 → int32 */
            if (obj->via.u64 > INT32_MAX) {
                int32_overflow_by_field[field_name]++;
                return builder->Append(INT32_MAX);
            }
            return builder->Append(static_cast<int32_t>(obj->via.u64));
        } else if (obj->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            /* Check for underflow: int64 → int32 */
            if (obj->via.i64 < INT32_MIN || obj->via.i64 > INT32_MAX) {
                int32_overflow_by_field[field_name]++;
                return builder->Append(obj->via.i64 < INT32_MIN ? INT32_MIN : INT32_MAX);
            }
            return builder->Append(static_cast<int32_t>(obj->via.i64));
        } else if (obj->type == MSGPACK_OBJECT_FLOAT32 || obj->type == MSGPACK_OBJECT_FLOAT64) {
            /* Allow float to int32 conversion with clamping (common use case) */
            if (obj->via.f64 > INT32_MAX || obj->via.f64 < INT32_MIN) {
                float_to_int_clamp_by_field[field_name]++;
                return builder->Append(obj->via.f64 > INT32_MAX ? INT32_MAX : INT32_MIN);
            }
            return builder->Append(static_cast<int32_t>(obj->via.f64));
        }
        /* Enhanced: Support string parsing to int32 */
        else if (obj->type == MSGPACK_OBJECT_STR) {
            try {
                std::string str(obj->via.str.ptr, obj->via.str.size);
                char* endptr;
                errno = 0;
                long val = std::strtol(str.c_str(), &endptr, 10);

                if (endptr == str.c_str() || *endptr != '\0' || errno == ERANGE) {
                    return arrow::Status::Invalid("Cannot parse string to int32");
                }

                if (val > INT32_MAX || val < INT32_MIN) {
                    int32_overflow_by_field[field_name]++;
                    return builder->Append(val > INT32_MAX ? INT32_MAX : INT32_MIN);
                }

                string_parsed_to_int_by_field[field_name]++;
                return builder->Append(static_cast<int32_t>(val));
            } catch (...) {
                return arrow::Status::Invalid("Cannot parse string to int32");
            }
        }
        else if (obj->type == MSGPACK_OBJECT_BOOLEAN) {
            return builder->Append(obj->via.boolean ? 1 : 0);
        }
        else {
            /* Return error instead of NULL for type mismatch */
            return arrow::Status::Invalid("Cannot convert msgpack type to int32");
        }
    }

    arrow::Status convert_to_int64(const msgpack_object* obj, arrow::Int64Builder* builder,
                                   const std::string& field_name) {
        if (obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            /* Check for overflow: uint64 → int64 */
            if (obj->via.u64 > static_cast<uint64_t>(INT64_MAX)) {
                int64_overflow_by_field[field_name]++;
                return builder->Append(INT64_MAX);
            }
            return builder->Append(static_cast<int64_t>(obj->via.u64));
        } else if (obj->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            return builder->Append(obj->via.i64);
        } else if (obj->type == MSGPACK_OBJECT_FLOAT32 || obj->type == MSGPACK_OBJECT_FLOAT64) {
            return builder->Append(static_cast<int64_t>(obj->via.f64));
        }
        /* Enhanced: Support string parsing to int64 */
        else if (obj->type == MSGPACK_OBJECT_STR) {
            try {
                std::string str(obj->via.str.ptr, obj->via.str.size);
                char* endptr;
                errno = 0;
                long long val = std::strtoll(str.c_str(), &endptr, 10);

                if (endptr == str.c_str() || *endptr != '\0' || errno == ERANGE) {
                    return arrow::Status::Invalid("Cannot parse string to int64");
                }

                string_parsed_to_int_by_field[field_name]++;
                return builder->Append(static_cast<int64_t>(val));
            } catch (...) {
                return arrow::Status::Invalid("Cannot parse string to int64");
            }
        }
        else if (obj->type == MSGPACK_OBJECT_BOOLEAN) {
            return builder->Append(obj->via.boolean ? 1 : 0);
        } else {
            /* Return error instead of NULL for type mismatch */
            return arrow::Status::Invalid("Cannot convert msgpack type to int64");
        }
    }

    arrow::Status convert_to_float(const msgpack_object* obj, arrow::FloatBuilder* builder,
                                   const std::string& field_name) {
        if (obj->type == MSGPACK_OBJECT_FLOAT32 || obj->type == MSGPACK_OBJECT_FLOAT64) {
            return builder->Append(static_cast<float>(obj->via.f64));
        } else if (obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            return builder->Append(static_cast<float>(obj->via.u64));
        } else if (obj->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            return builder->Append(static_cast<float>(obj->via.i64));
        }
        /* Enhanced: Support string parsing to float */
        else if (obj->type == MSGPACK_OBJECT_STR) {
            try {
                std::string str(obj->via.str.ptr, obj->via.str.size);
                char* endptr;
                errno = 0;
                float val = std::strtof(str.c_str(), &endptr);

                if (endptr == str.c_str() || *endptr != '\0' || errno == ERANGE) {
                    return arrow::Status::Invalid("Cannot parse string to float");
                }

                string_parsed_to_float_by_field[field_name]++;
                return builder->Append(val);
            } catch (...) {
                return arrow::Status::Invalid("Cannot parse string to float");
            }
        }
        else if (obj->type == MSGPACK_OBJECT_BOOLEAN) {
            return builder->Append(obj->via.boolean ? 1.0f : 0.0f);
        }
        else {
            /* Return error instead of NULL for type mismatch */
            return arrow::Status::Invalid("Cannot convert msgpack type to float");
        }
    }

    arrow::Status convert_to_double(const msgpack_object* obj, arrow::DoubleBuilder* builder,
                                    const std::string& field_name) {
        if (obj->type == MSGPACK_OBJECT_FLOAT32 || obj->type == MSGPACK_OBJECT_FLOAT64) {
            return builder->Append(obj->via.f64);
        } else if (obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            return builder->Append(static_cast<double>(obj->via.u64));
        } else if (obj->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            return builder->Append(static_cast<double>(obj->via.i64));
        }
        /* Enhanced: Support string parsing to double */
        else if (obj->type == MSGPACK_OBJECT_STR) {
            try {
                std::string str(obj->via.str.ptr, obj->via.str.size);
                char* endptr;
                errno = 0;
                double val = std::strtod(str.c_str(), &endptr);

                if (endptr == str.c_str() || *endptr != '\0' || errno == ERANGE) {
                    return arrow::Status::Invalid("Cannot parse string to double");
                }

                string_parsed_to_float_by_field[field_name]++;
                return builder->Append(val);
            } catch (...) {
                return arrow::Status::Invalid("Cannot parse string to double");
            }
        }
        else if (obj->type == MSGPACK_OBJECT_BOOLEAN) {
            return builder->Append(obj->via.boolean ? 1.0 : 0.0);
        } else {
            /* Return error instead of NULL for type mismatch */
            return arrow::Status::Invalid("Cannot convert msgpack type to double");
        }
    }

    arrow::Status convert_to_string(const msgpack_object* obj, arrow::StringBuilder* builder,
                                    const std::string& field_name) {
        switch (obj->type) {
            case MSGPACK_OBJECT_STR:
                return builder->Append(obj->via.str.ptr, obj->via.str.size);
            case MSGPACK_OBJECT_BIN:
                return builder->Append(obj->via.bin.ptr, obj->via.bin.size);
            case MSGPACK_OBJECT_BOOLEAN:
                return builder->Append(obj->via.boolean ? "true" : "false");
            case MSGPACK_OBJECT_POSITIVE_INTEGER:
                return builder->Append(std::to_string(obj->via.u64));
            case MSGPACK_OBJECT_NEGATIVE_INTEGER:
                return builder->Append(std::to_string(obj->via.i64));
            case MSGPACK_OBJECT_FLOAT32:
            case MSGPACK_OBJECT_FLOAT64:
                return builder->Append(std::to_string(obj->via.f64));
            /* Enhanced: Support complex types by serializing to JSON using Fluent Bit's converter */
            case MSGPACK_OBJECT_MAP:
            case MSGPACK_OBJECT_ARRAY: {
                complex_to_string_by_field[field_name]++;
                std::string json_str = msgpack_object_to_json_string(obj);
                return builder->Append(json_str);
            }
            default:
                return arrow::Status::Invalid("Cannot convert msgpack type to string");
        }
    }

    arrow::Status convert_to_binary(const msgpack_object* obj, arrow::BinaryBuilder* builder,
                                    const std::string& field_name) {
        /* Binary fields only accept actual binary data (BIN) or strings (STR)
         * Other type conversions are rejected to maintain data semantics */
        if (obj->type == MSGPACK_OBJECT_BIN) {
            return builder->Append(reinterpret_cast<const uint8_t*>(obj->via.bin.ptr),
                                  obj->via.bin.size);
        } else if (obj->type == MSGPACK_OBJECT_STR) {
            return builder->Append(reinterpret_cast<const uint8_t*>(obj->via.str.ptr),
                                  obj->via.str.size);
        }
        else {
            /* Reject other types - binary field should contain actual binary data */
            return arrow::Status::Invalid("Binary field only accepts BIN or STR types");
        }
    }

    arrow::Status convert_to_timestamp(const msgpack_object* obj, arrow::TimestampBuilder* builder,
                                       const std::string& field_name) {
        /* Timestamp: Type conversion only, no unit conversion
         * Schema unit="s" means output is in seconds (input must already be seconds)
         * We store values as-is - user ensures input unit matches schema unit */
        if (obj->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            return builder->Append(static_cast<int64_t>(obj->via.u64));
        } else if (obj->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            return builder->Append(obj->via.i64);
        } else if (obj->type == MSGPACK_OBJECT_FLOAT32 || obj->type == MSGPACK_OBJECT_FLOAT64) {
            /* For float timestamps, truncate to integer */
            return builder->Append(static_cast<int64_t>(obj->via.f64));
        }
        /* Enhanced: Support string parsing to timestamp (Unix timestamp strings) */
        else if (obj->type == MSGPACK_OBJECT_STR) {
            try {
                std::string str(obj->via.str.ptr, obj->via.str.size);

                /* Try to parse as Unix timestamp (integer or float string) */
                char* endptr;
                errno = 0;
                double val = std::strtod(str.c_str(), &endptr);

                if (endptr != str.c_str() && *endptr == '\0' && errno != ERANGE) {
                    /* Successfully parsed as number - use directly without conversion */
                    return builder->Append(static_cast<int64_t>(val));
                }

                /* If not a number, return error (ISO 8601 parsing would require additional libraries) */
                return arrow::Status::Invalid("Cannot parse string to timestamp - only Unix timestamp strings supported");
            } catch (...) {
                return arrow::Status::Invalid("Cannot parse string to timestamp");
            }
        }
        /* Best effort: Convert boolean to timestamp (0 or 1) */
        else if (obj->type == MSGPACK_OBJECT_BOOLEAN) {
            return builder->Append(obj->via.boolean ? 1 : 0);
        }
        else {
            /* Return error instead of NULL for type mismatch */
            return arrow::Status::Invalid("Cannot convert msgpack type to timestamp");
        }
    }
};

// Helper function to parse JSON schema and create Arrow schema using yyjson
arrow::Result<std::shared_ptr<arrow::Schema>> parse_schema_from_json(const char* schema_str) {
    yyjson_doc* doc = yyjson_read(schema_str, strlen(schema_str), 0);
    if (!doc) {
        flb_error("[parquet] Failed to parse JSON schema. Schema content: '%s'\n", schema_str);
        return arrow::Status::Invalid("Failed to parse JSON schema");
    }

    yyjson_val* root = yyjson_doc_get_root(doc);
    if (!root || !yyjson_is_obj(root)) {
        flb_error("[parquet] Schema root must be an object. Received schema: '%s'\n", schema_str);
        yyjson_doc_free(doc);
        return arrow::Status::Invalid("Schema root must be an object");
    }

    yyjson_val* fields_array = yyjson_obj_get(root, "fields");
    if (!fields_array || !yyjson_is_arr(fields_array)) {
        flb_error("[parquet] Schema must contain 'fields' array. Received schema: '%s'\n", schema_str);
        yyjson_doc_free(doc);
        return arrow::Status::Invalid("Schema must contain 'fields' array");
    }

    std::vector<std::shared_ptr<arrow::Field>> arrow_fields;
    size_t num_fields = yyjson_arr_size(fields_array);

    yyjson_val* field_obj;
    yyjson_arr_iter iter;
    yyjson_arr_iter_init(fields_array, &iter);
    size_t i = 0;

    while ((field_obj = yyjson_arr_iter_next(&iter))) {
        if (!yyjson_is_obj(field_obj)) {
            i++;
            continue;
        }

        yyjson_val* name_val = yyjson_obj_get(field_obj, "name");
        yyjson_val* type_val = yyjson_obj_get(field_obj, "type");
        yyjson_val* nullable_val = yyjson_obj_get(field_obj, "nullable");

        if (!name_val || !yyjson_is_str(name_val)) {
            flb_error("[parquet] Field %zu must have 'name' string. Schema: '%s'\n", i, schema_str);
            yyjson_doc_free(doc);
            return arrow::Status::Invalid("Field must have 'name' string");
        }

        if (!type_val) {
            const char* field_name = yyjson_get_str(name_val);
            flb_error("[parquet] Field '%s' missing required 'type' attribute. Schema: '%s'\n",
                     field_name, schema_str);
            yyjson_doc_free(doc);
            return arrow::Status::Invalid("Field missing required 'type' attribute");
        }

        std::string field_name = yyjson_get_str(name_val);
        bool nullable = nullable_val ? yyjson_get_bool(nullable_val) : true;
        std::shared_ptr<arrow::DataType> data_type;

        /* Parse type - support both string and object format */
        if (yyjson_is_str(type_val)) {
            std::string type_str = yyjson_get_str(type_val);
            if (type_str == "bool" || type_str == "boolean") {
                data_type = arrow::boolean();
            } else if (type_str == "int32") {
                data_type = arrow::int32();
            } else if (type_str == "int64") {
                data_type = arrow::int64();
            } else if (type_str == "float" || type_str == "float32") {
                data_type = arrow::float32();
            } else if (type_str == "double" || type_str == "float64") {
                data_type = arrow::float64();
            } else if (type_str == "utf8" || type_str == "string") {
                data_type = arrow::utf8();
            } else if (type_str == "binary") {
                data_type = arrow::binary();
            } else {
                flb_warn("[parquet] Unsupported type '%s', defaulting to utf8\n", type_str.c_str());
                data_type = arrow::utf8();
            }
        } else if (yyjson_is_obj(type_val)) {
            yyjson_val* type_name_val = yyjson_obj_get(type_val, "name");
            if (type_name_val && yyjson_is_str(type_name_val)) {
                std::string type_name = yyjson_get_str(type_name_val);
                /* Support object format for all basic types */
                if (type_name == "bool" || type_name == "boolean") {
                    data_type = arrow::boolean();
                } else if (type_name == "int32") {
                    data_type = arrow::int32();
                } else if (type_name == "int64") {
                    data_type = arrow::int64();
                } else if (type_name == "float" || type_name == "float32") {
                    data_type = arrow::float32();
                } else if (type_name == "double" || type_name == "float64") {
                    data_type = arrow::float64();
                } else if (type_name == "utf8" || type_name == "string") {
                    data_type = arrow::utf8();
                } else if (type_name == "binary") {
                    data_type = arrow::binary();
                } else if (type_name == "timestamp") {
                    yyjson_val* unit_val = yyjson_obj_get(type_val, "unit");
                    arrow::TimeUnit::type time_unit = arrow::TimeUnit::MICRO;
                    if (unit_val && yyjson_is_str(unit_val)) {
                        std::string unit = yyjson_get_str(unit_val);
                        if (unit == "s") time_unit = arrow::TimeUnit::SECOND;
                        else if (unit == "ms") time_unit = arrow::TimeUnit::MILLI;
                        else if (unit == "us") time_unit = arrow::TimeUnit::MICRO;
                        else if (unit == "ns") time_unit = arrow::TimeUnit::NANO;
                    }
                    data_type = arrow::timestamp(time_unit);
                } else {
                    flb_warn("[parquet] Unsupported complex type '%s', defaulting to utf8\n", type_name.c_str());
                    data_type = arrow::utf8();
                }
            } else {
                data_type = arrow::utf8();
            }
        } else {
            data_type = arrow::utf8();
        }

        arrow_fields.push_back(arrow::field(field_name, data_type, nullable));
        i++;
    }

    yyjson_doc_free(doc);

    if (arrow_fields.empty()) {
        flb_error("[parquet] No valid fields found in schema\n");
        return arrow::Status::Invalid("No valid fields found in schema");
    }

    return arrow::schema(arrow_fields);
}

// Helper function to append type-specific default values for non-nullable fields
bool append_default_value(arrow::ArrayBuilder* builder, const std::shared_ptr<arrow::DataType>& type) {
    switch (type->id()) {
        case arrow::Type::BOOL:
            return static_cast<arrow::BooleanBuilder*>(builder)->Append(false).ok();

        case arrow::Type::INT32:
            return static_cast<arrow::Int32Builder*>(builder)->Append(0).ok();

        case arrow::Type::INT64:
            return static_cast<arrow::Int64Builder*>(builder)->Append(0).ok();

        case arrow::Type::FLOAT:
            return static_cast<arrow::FloatBuilder*>(builder)->Append(0.0f).ok();

        case arrow::Type::DOUBLE:
            return static_cast<arrow::DoubleBuilder*>(builder)->Append(0.0).ok();

        case arrow::Type::STRING:
            return static_cast<arrow::StringBuilder*>(builder)->Append("").ok();

        case arrow::Type::BINARY:
            return static_cast<arrow::BinaryBuilder*>(builder)->Append(static_cast<const uint8_t*>(nullptr), 0).ok();

        case arrow::Type::TIMESTAMP:
            return static_cast<arrow::TimestampBuilder*>(builder)->Append(0).ok();

        default:
            return false;
    }
}

} // anonymous namespace

extern "C" {

void *flb_msgpack_raw_to_parquet(const void *in_buf, size_t in_size,
                                  const char *schema_str,
                                  int compression,
                                  size_t *out_size)
{
    msgpack_unpacked result;
    parquet::Compression::type parquet_compression;
    void *output_buffer = NULL;

    flb_debug("[parquet] Starting msgpack to parquet conversion with user-defined schema\n");

    if (!in_buf || !out_size || !schema_str) {
        flb_error("[parquet] NULL parameter\n");
        return NULL;
    }

    /* Map Fluent Bit compression type to Parquet compression type */
    switch (compression) {
        case 0: /* FLB_AWS_COMPRESS_NONE */
            parquet_compression = parquet::Compression::UNCOMPRESSED;
            break;
        case 1: /* FLB_AWS_COMPRESS_GZIP */
            parquet_compression = parquet::Compression::GZIP;
            break;
        case 2: /* FLB_AWS_COMPRESS_SNAPPY */
            parquet_compression = parquet::Compression::SNAPPY;
            break;
        case 3: /* FLB_AWS_COMPRESS_ZSTD */
            parquet_compression = parquet::Compression::ZSTD;
            break;
        default:
            parquet_compression = parquet::Compression::UNCOMPRESSED;
            flb_warn("[parquet] Unknown compression type %d, defaulting to UNCOMPRESSED\n", compression);
            break;
    }

    try {
        /* 1. Parse user-provided JSON schema */
        auto schema_result = parse_schema_from_json(schema_str);
        if (!schema_result.ok()) {
            flb_error("[parquet] Failed to parse schema: %s\n", schema_result.status().ToString().c_str());
            return NULL;
        }
        auto schema = schema_result.ValueOrDie();
        flb_debug("[parquet] Parsed schema with %d fields\n", schema->num_fields());

        /* 2. Create Arrow builders for each field */
        std::vector<std::shared_ptr<arrow::ArrayBuilder>> field_builders;
        for (int i = 0; i < schema->num_fields(); i++) {
            auto field = schema->field(i);
            auto builder_result = arrow::MakeBuilder(field->type(), arrow::default_memory_pool());
            if (!builder_result.ok()) {
                flb_error("[parquet] Failed to create builder for field %s: %s\n",
                         field->name().c_str(), builder_result.status().ToString().c_str());
                return NULL;
            }
            field_builders.push_back(std::move(builder_result).ValueOrDie());
        }

        /* 3. Process records immediately as we unpack - avoid storing msgpack_object pointers */
        MsgpackToArrowConverter converter;

        /* Pre-allocate field lookup map to avoid repeated allocations */
        std::unordered_map<std::string_view, const msgpack_object*> field_map;
        field_map.reserve(schema->num_fields() * 2);

        /* Statistics for missing/conversion failures */
        std::unordered_map<std::string, size_t> missing_field_count;
        std::unordered_map<std::string, size_t> conversion_failure_count;

        /* Helper lambda to process a single map record immediately */
        auto process_record = [&](const msgpack_object* record) -> bool {

            if (record->type != MSGPACK_OBJECT_MAP) {
                /* Append nulls for all fields */
                for (auto& builder : field_builders) {
                    auto status = builder->AppendNull();
                    if (!status.ok()) {
                        flb_error("[parquet] Failed to append null for non-map record: %s\n",
                                 status.ToString().c_str());
                        return false;
                    }
                }
                return true;
            }

            auto& map = record->via.map;

            /* Build field lookup map using string_view to avoid string copies */
            field_map.clear();  /* Reuse the map instead of creating new one */
            for (uint32_t i = 0; i < map.size; i++) {
                auto& kv = map.ptr[i];
                if (kv.key.type == MSGPACK_OBJECT_STR) {
                    /* Use string_view to avoid string allocation/copy */
                    std::string_view key(kv.key.via.str.ptr, kv.key.via.str.size);
                    field_map[key] = &kv.val;
                }
            }

            /* Append values for each field */
            for (int field_idx = 0; field_idx < schema->num_fields(); field_idx++) {
                auto field = schema->field(field_idx);
                auto& builder = field_builders[field_idx];

                auto it = field_map.find(field->name());
                if (it != field_map.end()) {
                    auto status = converter.convert_value(it->second, builder.get(), field->type(), field->name());
                    if (!status.ok()) {
                        /* Conversion failed - check if field is nullable */
                        if (field->nullable()) {
                            auto null_status = builder->AppendNull();
                            if (!null_status.ok()) {
                                flb_error("[parquet] Failed to append null after conversion failure: %s\n",
                                         null_status.ToString().c_str());
                                return false;
                            }
                        } else {
                            /* Non-nullable field - append default value and track statistics */
                            conversion_failure_count[field->name()]++;
                            if (!append_default_value(builder.get(), field->type())) {
                                flb_error("[parquet] Failed to append default value for field '%s'\n",
                                         field->name().c_str());
                                return false;
                            }
                        }
                    }
                } else {
                    /* Field is missing from data */
                    if (field->nullable()) {
                        /* Nullable field - append null */
                        auto null_status = builder->AppendNull();
                        if (!null_status.ok()) {
                            flb_error("[parquet] Failed to append null for missing field '%s': %s\n",
                                     field->name().c_str(), null_status.ToString().c_str());
                            return false;
                        }
                    } else {
                        /* Non-nullable field - append default value and track statistics */
                        missing_field_count[field->name()]++;
                        if (!append_default_value(builder.get(), field->type())) {
                            flb_error("[parquet] Failed to append default value for field '%s'\n",
                                     field->name().c_str());
                            return false;
                        }
                    }
                }
            }
            return true;
        };

        /* Unpack and process records immediately */
        msgpack_unpacked_init(&result);
        size_t offset = 0;
        size_t record_count = 0;

        while (msgpack_unpack_next(&result, static_cast<const char*>(in_buf), in_size, &offset)
               == MSGPACK_UNPACK_SUCCESS) {
            if (result.data.type == MSGPACK_OBJECT_ARRAY) {
                /* Process each element in the array */
                auto& array = result.data.via.array;
                for (uint32_t i = 0; i < array.size; i++) {
                    if (!process_record(&array.ptr[i])) {
                        msgpack_unpacked_destroy(&result);
                        return NULL;
                    }
                    record_count++;
                }
            } else {
                /* Process single record */
                if (!process_record(&result.data)) {
                    msgpack_unpacked_destroy(&result);
                    return NULL;
                }
                record_count++;
            }
        }

        msgpack_unpacked_destroy(&result);

        if (record_count == 0) {
            flb_error("[parquet] No valid records found in msgpack data\n");
            return NULL;
        }

        flb_debug("[parquet] Processed %zu records\n", record_count);

        /* Output statistics summary - only in debug mode for detailed field info */
        bool has_issues = !missing_field_count.empty() || !conversion_failure_count.empty() ||
                         !converter.int32_overflow_by_field.empty() || !converter.int64_overflow_by_field.empty() ||
                         !converter.float_to_int_clamp_by_field.empty() ||
                         !converter.complex_to_string_by_field.empty() ||
                         !converter.string_parsed_to_int_by_field.empty() ||
                         !converter.string_parsed_to_float_by_field.empty() ||
                         !converter.string_parsed_to_bool_by_field.empty();

        if (has_issues) {
            flb_debug("[parquet] Data quality summary for %zu records:", record_count);

            if (!converter.complex_to_string_by_field.empty()) {
                flb_debug("[parquet] Complex types serialized to JSON string:");
                for (const auto& pair : converter.complex_to_string_by_field) {
                    flb_debug("[parquet]   field='%s' count=%zu",
                            pair.first.c_str(), pair.second);
                }
            }

            if (!converter.string_parsed_to_int_by_field.empty()) {
                flb_debug("[parquet] Strings parsed to integers:");
                for (const auto& pair : converter.string_parsed_to_int_by_field) {
                    flb_debug("[parquet]   field='%s' count=%zu",
                            pair.first.c_str(), pair.second);
                }
            }

            if (!converter.string_parsed_to_float_by_field.empty()) {
                flb_debug("[parquet] Strings parsed to floats:");
                for (const auto& pair : converter.string_parsed_to_float_by_field) {
                    flb_debug("[parquet]   field='%s' count=%zu",
                            pair.first.c_str(), pair.second);
                }
            }

            if (!converter.string_parsed_to_bool_by_field.empty()) {
                flb_debug("[parquet] Strings parsed to booleans:");
                for (const auto& pair : converter.string_parsed_to_bool_by_field) {
                    flb_debug("[parquet]   field='%s' count=%zu",
                            pair.first.c_str(), pair.second);
                }
            }

            if (!converter.int32_overflow_by_field.empty()) {
                flb_debug("[parquet] Integer overflow (int64/uint64 -> int32 clamped):");
                for (const auto& pair : converter.int32_overflow_by_field) {
                    flb_debug("[parquet]   field='%s' count=%zu",
                            pair.first.c_str(), pair.second);
                }
            }

            if (!converter.int64_overflow_by_field.empty()) {
                flb_debug("[parquet] Integer overflow (uint64 -> int64 clamped):");
                for (const auto& pair : converter.int64_overflow_by_field) {
                    flb_debug("[parquet]   field='%s' count=%zu",
                            pair.first.c_str(), pair.second);
                }
            }

            if (!converter.float_to_int_clamp_by_field.empty()) {
                flb_debug("[parquet] Float to int32 clamping:");
                for (const auto& pair : converter.float_to_int_clamp_by_field) {
                    flb_debug("[parquet]   field='%s' count=%zu",
                            pair.first.c_str(), pair.second);
                }
            }

            if (!missing_field_count.empty()) {
                flb_debug("[parquet] Missing non-nullable fields (defaults used):");
                for (const auto& pair : missing_field_count) {
                    flb_debug("[parquet]   field='%s' count=%zu",
                            pair.first.c_str(), pair.second);
                }
            }

            if (!conversion_failure_count.empty()) {
                flb_debug("[parquet] Type conversion failures (defaults used):");
                for (const auto& pair : conversion_failure_count) {
                    flb_debug("[parquet]   field='%s' count=%zu",
                            pair.first.c_str(), pair.second);
                }
            }
        }

        /* 4. Finish building arrays */
        std::vector<std::shared_ptr<arrow::Array>> arrays;
        for (size_t i = 0; i < field_builders.size(); i++) {
            auto array_result = field_builders[i]->Finish();
            if (!array_result.ok()) {
                flb_error("[parquet] Failed to finish array for field %d: %s\n",
                         static_cast<int>(i), array_result.status().ToString().c_str());
                return NULL;
            }
            arrays.push_back(array_result.ValueOrDie());
        }

        /* 5. Create RecordBatch */
        auto batch = arrow::RecordBatch::Make(schema, record_count, arrays);
        flb_debug("[parquet] Created RecordBatch with %lld rows and %d columns\n",
                 batch->num_rows(), batch->num_columns());

        /* 6. Let Arrow manage the buffer - it will automatically grow as needed */
        auto output_stream_result = arrow::io::BufferOutputStream::Create(
            INITIAL_PARQUET_BUFFER_SIZE,  /* Initial size hint, Arrow will auto-grow */
            arrow::default_memory_pool());

        if (!output_stream_result.ok()) {
            flb_error("[parquet] Failed to create output stream: %s\n",
                     output_stream_result.status().ToString().c_str());
            return NULL;
        }
        auto output_stream = output_stream_result.ValueOrDie();

        /* 7. Create Parquet writer properties */
        auto writer_properties = parquet::WriterProperties::Builder()
            .compression(parquet_compression)
            ->build();

        auto arrow_writer_properties = parquet::ArrowWriterProperties::Builder().build();

        /* 8. Write to Parquet - Arrow automatically manages memory growth */
        auto writer_result = parquet::arrow::FileWriter::Open(
            *schema.get(),
            arrow::default_memory_pool(),
            output_stream,
            writer_properties,
            arrow_writer_properties);

        if (!writer_result.ok()) {
            flb_error("[parquet] Failed to create Parquet writer: %s\n",
                     writer_result.status().ToString().c_str());
            return NULL;
        }
        std::unique_ptr<parquet::arrow::FileWriter> writer = std::move(writer_result).ValueOrDie();

        auto status = writer->WriteRecordBatch(*batch);
        if (!status.ok()) {
            flb_error("[parquet] Failed to write RecordBatch: %s\n",
                     status.ToString().c_str());
            return NULL;
        }

        status = writer->Close();
        if (!status.ok()) {
            flb_error("[parquet] Failed to close writer: %s\n",
                     status.ToString().c_str());
            return NULL;
        }

        /* 9. Get the final buffer from Arrow - it knows the exact size */
        auto buffer_result = output_stream->Finish();
        if (!buffer_result.ok()) {
            flb_error("[parquet] Failed to finish output stream: %s\n",
                     buffer_result.status().ToString().c_str());
            return NULL;
        }
        auto arrow_buffer = buffer_result.ValueOrDie();

        /* 10. Copy to Fluent Bit managed memory */
        size_t final_size = arrow_buffer->size();
        output_buffer = flb_malloc(final_size);
        if (!output_buffer) {
            flb_error("[parquet] Failed to allocate %zu bytes for output\n", final_size);
            return NULL;
        }

        memcpy(output_buffer, arrow_buffer->data(), final_size);
        *out_size = final_size;

        flb_debug("[parquet] Successfully converted to Parquet: %zu bytes\n", final_size);

        return output_buffer;

    } catch (const parquet::ParquetException& e) {
        flb_error("[parquet] Parquet exception: %s\n", e.what());
        if (output_buffer) {
            flb_free(output_buffer);
        }
        return NULL;
    } catch (const std::exception& e) {
        flb_error("[parquet] Exception during conversion: %s\n", e.what());
        if (output_buffer) {
            flb_free(output_buffer);
        }
        return NULL;
    }
}

} // extern "C"
