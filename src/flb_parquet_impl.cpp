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

/*
 * DESIGN PHILOSOPHY: Best Effort Data Conversion
 * ===============================================
 *
 * This implementation follows a "best effort" approach for type conversions:
 *
 * 1. NEVER FAIL ON BAD DATA
 *    - Type mismatches, overflows, unparseable strings -> use default values
 *    - Continue processing subsequent records rather than aborting entire file
 *    - Critical for production stability when processing millions of records
 *
 * 2. LOGGING DISCIPLINE
 *    - Per-record issues (type conversion, clamping) -> flb_debug() ONLY
 *    - File-level failures (I/O errors, memory allocation) -> flb_error()
 *    - Avoid logging inside tight loops to prevent log floods with large datasets
 *    - External systems handle success/progress logging
 *
 * 3. DEFAULT VALUES
 *    - bool: false, int: 0, float: 0.0, string: "", binary: empty, timestamp: 0
 *    - Overflow/underflow: clamp to type min/max bounds
 *    - Non-finite (NaN/Inf): clamp to 0 or appropriate boundary
 *
 * This ensures reliable data pipeline operation even with imperfect input data.
 */

#include <arrow/api.h>
#include <arrow/io/api.h>
#include <parquet/arrow/writer.h>
#include <parquet/arrow/reader.h>
#include <parquet/exception.h>

#include <cctype>      /* std::tolower */
#include <cerrno>      /* errno, ERANGE */
#include <cmath>       /* std::isfinite */
#include <cstdio>      /* snprintf */
#include <cstdlib>     /* std::strtoll, std::strtof, std::strtod */
#include <cstring>     /* memcpy, strlen, strerror */
#include <limits>      /* std::numeric_limits */
#include <memory>
#include <stdexcept>
#include <string>
#include <charconv>
#include <array>
#include <string_view> /* std::string_view */
#include <vector>
#include <unordered_map>
#include <optional>
#include <functional>
#include <algorithm>
#include <sys/stat.h>

/* Platform-specific headers for unlink */
#ifdef _WIN32
  #include <io.h>
  #define unlink _unlink
#else
  #include <unistd.h>
#endif

extern "C" {
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_parquet.h>
#include <fluent-bit/aws/flb_aws_compress.h>
#include <msgpack.h>
#include <yyjson.h>

char* flb_msgpack_to_json_str(size_t size, const msgpack_object *obj, int escape_unicode);
FILE *flb_chunk_file_open(const char *chunk_path);
}

/* Parquet processing constants */
namespace {
constexpr size_t IO_BUFFER_SIZE = 1024 * 1024;      /* 1MB for file I/O operations */
constexpr size_t RECORDS_PER_BATCH = 65536;         /* Arrow standard batch size (64K rows) */
constexpr int64_t MAX_ROW_GROUP_LENGTH = 524288;   /* 512K rows per row group for S3 compatibility */
}

namespace {

/* RAII Wrappers for C resources */
struct FileCloser {
    void operator()(FILE* fp) const {
        if (fp) fclose(fp);
    }
};
using ScopedFile = std::unique_ptr<FILE, FileCloser>;

class ScopedMsgpackUnpacker {
public:
    ScopedMsgpackUnpacker(size_t buffer_size) : initialized_(false) {
        if (msgpack_unpacker_init(&unpacker_, buffer_size)) {
            initialized_ = true;
        }
    }

    ~ScopedMsgpackUnpacker() {
        if (initialized_) {
            msgpack_unpacker_destroy(&unpacker_);
        }
    }

    bool isValid() const { return initialized_; }
    msgpack_unpacker* get() { return &unpacker_; }

    ScopedMsgpackUnpacker(const ScopedMsgpackUnpacker&) = delete;
    ScopedMsgpackUnpacker& operator=(const ScopedMsgpackUnpacker&) = delete;

private:
    msgpack_unpacker unpacker_;
    bool initialized_;
};

class ScopedMsgpackResult {
public:
    ScopedMsgpackResult() {
        msgpack_unpacked_init(&result_);
    }
    ~ScopedMsgpackResult() {
        msgpack_unpacked_destroy(&result_);
    }
    msgpack_unpacked* get() { return &result_; }

    /* Fix: Reset to free accumulated memory (zone) */
    void reset() {
        msgpack_unpacked_destroy(&result_);
        msgpack_unpacked_init(&result_);
    }

    ScopedMsgpackResult(const ScopedMsgpackResult&) = delete;
    ScopedMsgpackResult& operator=(const ScopedMsgpackResult&) = delete;

private:
    msgpack_unpacked result_;
};

arrow::Result<std::string> msgpack_object_to_json_string(const msgpack_object* obj) {
    char *json_str = flb_msgpack_to_json_str(1024, obj, FLB_FALSE);
    if (!json_str) {
        return arrow::Status::Invalid("Failed to convert msgpack object to JSON string");
    }
    std::string result(json_str);
    flb_free(json_str);
    return result;
}

template<typename T>
std::optional<T> parse_string_to_number(const std::string& str) {
    char* endptr;
    errno = 0;

    if constexpr (std::is_same_v<T, int32_t> || std::is_same_v<T, int64_t>) {
        long long val = std::strtoll(str.c_str(), &endptr, 10);
        if (endptr == str.c_str() || *endptr != '\0' || errno == ERANGE) {
            return std::nullopt;
        }

        // Enforce target type bounds before casting to avoid silent overflow
        const long long min_t = static_cast<long long>(std::numeric_limits<T>::min());
        const long long max_t = static_cast<long long>(std::numeric_limits<T>::max());
        if (val < min_t || val > max_t) {
            errno = ERANGE;
            return std::nullopt;
        }

        return static_cast<T>(val);
    } else if constexpr (std::is_same_v<T, float>) {
        float val = std::strtof(str.c_str(), &endptr);
        if (endptr == str.c_str() || *endptr != '\0' || errno == ERANGE) {
            return std::nullopt;
        }
        return val;
    } else if constexpr (std::is_same_v<T, double>) {
        double val = std::strtod(str.c_str(), &endptr);
        if (endptr == str.c_str() || *endptr != '\0' || errno == ERANGE) {
            return std::nullopt;
        }
        return val;
    }
    return std::nullopt;
}

std::optional<bool> parse_string_to_bool(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (lower == "true" || lower == "1" || lower == "yes" || lower == "y" || lower == "on") {
        return true;
    }
    if (lower == "false" || lower == "0" || lower == "no" || lower == "n" || lower == "off") {
        return false;
    }
    return std::nullopt;
}

struct MsgpackToArrowConverter {
    static arrow::Status convert_value(const msgpack_object* obj,
                                       arrow::ArrayBuilder* builder,
                                       const std::shared_ptr<arrow::DataType>& type) {
        if (obj->type == MSGPACK_OBJECT_NIL) {
            return arrow::Status::Invalid("Null value encountered");
        }

        switch (type->id()) {
            case arrow::Type::BOOL:
                return convert_to_bool(obj, static_cast<arrow::BooleanBuilder*>(builder));
            case arrow::Type::INT32:
                return convert_to_int32(obj, static_cast<arrow::Int32Builder*>(builder));
            case arrow::Type::INT64:
                return convert_to_int64(obj, static_cast<arrow::Int64Builder*>(builder));
            case arrow::Type::FLOAT:
                return convert_to_float(obj, static_cast<arrow::FloatBuilder*>(builder));
            case arrow::Type::DOUBLE:
                return convert_to_double(obj, static_cast<arrow::DoubleBuilder*>(builder));
            case arrow::Type::STRING:
                return convert_to_string(obj, static_cast<arrow::StringBuilder*>(builder));
            case arrow::Type::BINARY:
                return convert_to_binary(obj, static_cast<arrow::BinaryBuilder*>(builder));
            case arrow::Type::TIMESTAMP:
                return convert_to_timestamp(obj, static_cast<arrow::TimestampBuilder*>(builder), type);
            default:
                return arrow::Status::NotImplemented("Unsupported Arrow type: " + type->ToString());
        }
    }

private:
    static arrow::Status convert_to_bool(const msgpack_object* obj, arrow::BooleanBuilder* builder) {
        switch (obj->type) {
            case MSGPACK_OBJECT_BOOLEAN:
                return builder->Append(obj->via.boolean);

            case MSGPACK_OBJECT_POSITIVE_INTEGER:
                return builder->Append(obj->via.u64 != 0);

            case MSGPACK_OBJECT_NEGATIVE_INTEGER:
                return builder->Append(obj->via.i64 != 0);

            case MSGPACK_OBJECT_FLOAT32:
            case MSGPACK_OBJECT_FLOAT64:
                /* NaN != 0.0 is true, but NaN should be treated as false for robustness */
                if (!std::isfinite(obj->via.f64)) {
                    flb_debug("[parquet] Non-finite float value %f converted to false for bool type",
                            obj->via.f64);
                    return builder->Append(false);
                }
                return builder->Append(obj->via.f64 != 0.0);

            case MSGPACK_OBJECT_STR: {
                std::string str(obj->via.str.ptr, obj->via.str.size);
                if (auto result = parse_string_to_bool(str)) {
                    return builder->Append(*result);
                }
                flb_debug("[parquet] Cannot parse string '%s' to bool, using false", str.c_str());
                return builder->Append(false);
            }

            default:
                flb_debug("[parquet] Cannot convert msgpack type %d to bool, using false", obj->type);
                return builder->Append(false);
        }
    }

    template<typename T, typename BuilderT>
    static arrow::Status convert_to_integer(const msgpack_object* obj, BuilderT* builder) {
        constexpr T MIN_VAL = std::numeric_limits<T>::min();
        constexpr T MAX_VAL = std::numeric_limits<T>::max();

        switch (obj->type) {
            case MSGPACK_OBJECT_POSITIVE_INTEGER: {
                if (obj->via.u64 > static_cast<uint64_t>(MAX_VAL)) {
                    flb_debug("[parquet] Value %llu clamped to max %lld for integer type",
                            (unsigned long long)obj->via.u64, (long long)MAX_VAL);
                    return builder->Append(MAX_VAL);
                }
                return builder->Append(static_cast<T>(obj->via.u64));
            }

            case MSGPACK_OBJECT_NEGATIVE_INTEGER: {
                if (obj->via.i64 < MIN_VAL || obj->via.i64 > MAX_VAL) {
                    T clamped = (obj->via.i64 < MIN_VAL) ? MIN_VAL : MAX_VAL;
                    flb_debug("[parquet] Value %lld clamped to %lld for integer type",
                            (long long)obj->via.i64, (long long)clamped);
                    return builder->Append(clamped);
                }
                return builder->Append(static_cast<T>(obj->via.i64));
            }

            case MSGPACK_OBJECT_FLOAT32:
            case MSGPACK_OBJECT_FLOAT64: {
                /* Handle non-finite values (NaN, Inf) before any comparison/cast */
                if (!std::isfinite(obj->via.f64)) {
                    flb_debug("[parquet] Non-finite float value %f converted to 0 for integer type",
                            obj->via.f64);
                    return builder->Append(static_cast<T>(0));
                }
                if (obj->via.f64 > MAX_VAL || obj->via.f64 < MIN_VAL) {
                    T clamped = (obj->via.f64 > MAX_VAL) ? MAX_VAL : MIN_VAL;
                    flb_debug("[parquet] Float value %f clamped to %lld for integer type",
                            obj->via.f64, (long long)clamped);
                    return builder->Append(clamped);
                }
                return builder->Append(static_cast<T>(obj->via.f64));
            }

            case MSGPACK_OBJECT_STR: {
                std::string str(obj->via.str.ptr, obj->via.str.size);
                if (auto val = parse_string_to_number<T>(str)) {
                    if (*val > MAX_VAL || *val < MIN_VAL) {
                        T clamped = (*val > MAX_VAL) ? MAX_VAL : MIN_VAL;
                        flb_debug("[parquet] Parsed string value clamped to %lld for integer type (original: %s)",
                                (long long)clamped, str.c_str());
                        return builder->Append(clamped);
                    }
                    return builder->Append(*val);
                }
                flb_debug("[parquet] Cannot parse string '%s' to integer, using 0", str.c_str());
                return builder->Append(0);
            }

            case MSGPACK_OBJECT_BOOLEAN:
                return builder->Append(obj->via.boolean ? 1 : 0);

            default:
                flb_debug("[parquet] Cannot convert msgpack type %d to integer, using 0", obj->type);
                return builder->Append(0);
        }
    }

    static arrow::Status convert_to_int32(const msgpack_object* obj, arrow::Int32Builder* builder) {
        return convert_to_integer<int32_t>(obj, builder);
    }

    static arrow::Status convert_to_int64(const msgpack_object* obj, arrow::Int64Builder* builder) {
        return convert_to_integer<int64_t>(obj, builder);
    }

    template<typename T, typename BuilderT>
    static arrow::Status convert_to_floating(const msgpack_object* obj, BuilderT* builder) {
        switch (obj->type) {
            case MSGPACK_OBJECT_FLOAT32:
            case MSGPACK_OBJECT_FLOAT64: {
                /* Handle non-finite values (NaN, Inf) - clamp to 0.0 for robustness */
                if (!std::isfinite(obj->via.f64)) {
                    flb_debug("[parquet] Non-finite float value %f converted to 0.0 for float type",
                            obj->via.f64);
                    return builder->Append(static_cast<T>(0.0));
                }
                return builder->Append(static_cast<T>(obj->via.f64));
            }

            case MSGPACK_OBJECT_POSITIVE_INTEGER:
                return builder->Append(static_cast<T>(obj->via.u64));

            case MSGPACK_OBJECT_NEGATIVE_INTEGER:
                return builder->Append(static_cast<T>(obj->via.i64));

            case MSGPACK_OBJECT_STR: {
                std::string str(obj->via.str.ptr, obj->via.str.size);
                if (auto val = parse_string_to_number<T>(str)) {
                    /* Check if parsed value is finite */
                    if (!std::isfinite(*val)) {
                        flb_debug("[parquet] Parsed non-finite value from string '%s', using 0.0",
                                str.c_str());
                        return builder->Append(static_cast<T>(0.0));
                    }
                    return builder->Append(*val);
                }
                flb_debug("[parquet] Cannot parse string '%s' to float, using 0.0", str.c_str());
                return builder->Append(static_cast<T>(0.0));
            }

            case MSGPACK_OBJECT_BOOLEAN:
                return builder->Append(obj->via.boolean ? static_cast<T>(1.0) : static_cast<T>(0.0));

            default:
                flb_debug("[parquet] Cannot convert msgpack type %d to float, using 0.0", obj->type);
                return builder->Append(static_cast<T>(0.0));
        }
    }

    static arrow::Status convert_to_float(const msgpack_object* obj, arrow::FloatBuilder* builder) {
        return convert_to_floating<float>(obj, builder);
    }

    static arrow::Status convert_to_double(const msgpack_object* obj, arrow::DoubleBuilder* builder) {
        return convert_to_floating<double>(obj, builder);
    }

    static arrow::Status convert_to_string(const msgpack_object* obj, arrow::StringBuilder* builder) {
        switch (obj->type) {
            case MSGPACK_OBJECT_STR:
                return builder->Append(obj->via.str.ptr, obj->via.str.size);

            case MSGPACK_OBJECT_BIN:
                return builder->Append(obj->via.bin.ptr, obj->via.bin.size);

            case MSGPACK_OBJECT_BOOLEAN:
                return builder->Append(obj->via.boolean ? "true" : "false");

            case MSGPACK_OBJECT_POSITIVE_INTEGER:
                return append_integer_as_string(obj->via.u64, builder);

            case MSGPACK_OBJECT_NEGATIVE_INTEGER:
                return append_integer_as_string(obj->via.i64, builder);

            case MSGPACK_OBJECT_FLOAT32:
            case MSGPACK_OBJECT_FLOAT64:
                return builder->Append(std::to_string(obj->via.f64));

            case MSGPACK_OBJECT_MAP:
            case MSGPACK_OBJECT_ARRAY: {
                auto json_result = msgpack_object_to_json_string(obj);
                if (!json_result.ok()) {
                    return json_result.status();
                }
                return builder->Append(*json_result);
            }

            default:
                flb_debug("[parquet] Cannot convert msgpack type %d to string, using empty string", obj->type);
                return builder->Append("");
        }
    }

    static arrow::Status convert_to_binary(const msgpack_object* obj, arrow::BinaryBuilder* builder) {
        if (obj->type == MSGPACK_OBJECT_BIN) {
            return builder->Append(reinterpret_cast<const uint8_t*>(obj->via.bin.ptr),
                                  obj->via.bin.size);
        }
        if (obj->type == MSGPACK_OBJECT_STR) {
            return builder->Append(reinterpret_cast<const uint8_t*>(obj->via.str.ptr),
                                  obj->via.str.size);
        }
        flb_debug("[parquet] Cannot convert msgpack type %d to binary, using empty value", obj->type);
        return builder->AppendEmptyValue();
    }

    /* Helper: Append integer to StringBuilder using stack buffer (zero-allocation) */
    template<typename T>
    static arrow::Status append_integer_as_string(T value, arrow::StringBuilder* builder) {
        std::array<char, 32> buffer;
        auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
        if (result.ec == std::errc()) {
            return builder->Append(buffer.data(), static_cast<int>(result.ptr - buffer.data()));
        }
        return builder->Append(std::to_string(value));
    }

    /* Helper: Safe integer timestamp scaling */
    template <typename T>
    static arrow::Status convert_integer_timestamp(T value, int64_t scale_factor, arrow::TimestampBuilder* builder) {
        int64_t result;
        bool overflow = false;
        
        /* Check for overflow based on type T (int64_t or uint64_t) */
        if constexpr (std::is_same_v<T, uint64_t>) {
             constexpr uint64_t MAX_INT64 = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
             
             /* First check if the value itself exceeds int64 max (year 2262) */
             if (value > MAX_INT64) {
                 overflow = true;
             } else {
                 /* Now safe to cast to int64_t for multiplication check */
                 if (value > static_cast<uint64_t>(std::numeric_limits<int64_t>::max() / scale_factor)) {
                     overflow = true;
                 }
             }
             
             if (overflow) {
                 flb_debug("[parquet] Timestamp overflow (uint64): %llu * %lld", 
                          (unsigned long long)value, (long long)scale_factor);
                 return builder->Append(std::numeric_limits<int64_t>::max());
             }
             result = static_cast<int64_t>(value) * scale_factor;
        } else {
             /* int64_t logic */
             if (value > 0) {
                 if (value > std::numeric_limits<int64_t>::max() / scale_factor) {
                     overflow = true;
                     result = std::numeric_limits<int64_t>::max();
                 }
             } else if (value < 0) {
                 if (value < std::numeric_limits<int64_t>::min() / scale_factor) {
                     overflow = true;
                     result = std::numeric_limits<int64_t>::min();
                 }
             }
             
             if (overflow) {
                 flb_debug("[parquet] Timestamp overflow (int64): %lld * %lld", 
                          (long long)value, (long long)scale_factor);
             } else {
                 result = value * scale_factor;
             }
        }
        
        return builder->Append(result);
    }

    /* Helper function: safely scale timestamp with clamping on overflow (best effort) */
    static int64_t safe_scale_timestamp(double value, int64_t scale_factor, bool& clamped) {
        constexpr double INT64_MAX_D = static_cast<double>(std::numeric_limits<int64_t>::max());
        constexpr double INT64_MIN_D = static_cast<double>(std::numeric_limits<int64_t>::min());

        double scaled = value * static_cast<double>(scale_factor);

        /* Handle non-finite values (NaN, Inf) - clamp to 0 */
        if (!std::isfinite(scaled)) {
            clamped = true;
            return 0;
        }

        /* Clamp to int64_t range if overflow */
        if (scaled > INT64_MAX_D) {
            clamped = true;
            return std::numeric_limits<int64_t>::max();
        }
        if (scaled < INT64_MIN_D) {
            clamped = true;
            return std::numeric_limits<int64_t>::min();
        }

        clamped = false;
        return static_cast<int64_t>(scaled);
    }

    static arrow::Status convert_to_timestamp(const msgpack_object* obj,
                                              arrow::TimestampBuilder* builder,
                                              const std::shared_ptr<arrow::DataType>& type) {
        /* Get the timestamp type to determine the time unit */
        auto ts_type = std::static_pointer_cast<arrow::TimestampType>(type);
        arrow::TimeUnit::type time_unit = ts_type->unit();

        /* Scale factor: Assume input is in seconds, scale to target unit */
        int64_t scale_factor = 1;
        switch (time_unit) {
            case arrow::TimeUnit::SECOND: scale_factor = 1LL; break;
            case arrow::TimeUnit::MILLI:  scale_factor = 1000LL; break;
            case arrow::TimeUnit::MICRO:  scale_factor = 1000000LL; break;
            case arrow::TimeUnit::NANO:   scale_factor = 1000000000LL; break;
        }

        switch (obj->type) {
            case MSGPACK_OBJECT_POSITIVE_INTEGER:
                return convert_integer_timestamp(obj->via.u64, scale_factor, builder);

            case MSGPACK_OBJECT_NEGATIVE_INTEGER:
                return convert_integer_timestamp(obj->via.i64, scale_factor, builder);

            case MSGPACK_OBJECT_FLOAT32:
            case MSGPACK_OBJECT_FLOAT64: {
                bool clamped = false;
                int64_t result = safe_scale_timestamp(obj->via.f64, scale_factor, clamped);
                if (clamped) {
                     flb_debug("[parquet] Timestamp float value %f clamped", obj->via.f64);
                }
                return builder->Append(result);
            }

            case MSGPACK_OBJECT_STR: {
                std::string str(obj->via.str.ptr, obj->via.str.size);
                auto parsed = parse_string_to_number<double>(str);
                if (parsed) {
                    bool clamped = false;
                    int64_t result = safe_scale_timestamp(*parsed, scale_factor, clamped);
                    if (clamped) {
                        flb_debug("[parquet] Timestamp string value '%s' clamped", str.c_str());
                    }
                    return builder->Append(result);
                }
                flb_debug("[parquet] Cannot parse string '%s' to timestamp, using 0", str.c_str());
                return builder->Append(0);
            }

            case MSGPACK_OBJECT_BOOLEAN:
                return builder->Append(obj->via.boolean ? scale_factor : 0);

            default:
                flb_debug("[parquet] Cannot convert msgpack type %d to timestamp, using 0", obj->type);
                return builder->Append(0);
        }
    }
};

using TypeFactory = std::function<std::shared_ptr<arrow::DataType>()>;

const std::unordered_map<std::string, TypeFactory> TYPE_FACTORY_MAP = {
    {"bool", []() { return arrow::boolean(); }},
    {"boolean", []() { return arrow::boolean(); }},
    {"int32", []() { return arrow::int32(); }},
    {"int64", []() { return arrow::int64(); }},
    {"float", []() { return arrow::float32(); }},
    {"float32", []() { return arrow::float32(); }},
    {"double", []() { return arrow::float64(); }},
    {"float64", []() { return arrow::float64(); }},
    {"utf8", []() { return arrow::utf8(); }},
    {"string", []() { return arrow::utf8(); }},
    {"binary", []() { return arrow::binary(); }}
};

arrow::Result<std::shared_ptr<arrow::Schema>> parse_schema_from_json(const char* schema_str) {
    yyjson_doc* doc = yyjson_read(schema_str, strlen(schema_str), 0);
    if (!doc) {
        flb_error("[parquet] Failed to parse JSON schema");
        return arrow::Status::Invalid("Failed to parse JSON schema");
    }

    yyjson_val* root = yyjson_doc_get_root(doc);
    if (!root || !yyjson_is_obj(root)) {
        yyjson_doc_free(doc);
        return arrow::Status::Invalid("Schema root must be an object");
    }

    yyjson_val* fields_array = yyjson_obj_get(root, "fields");
    if (!fields_array || !yyjson_is_arr(fields_array)) {
        yyjson_doc_free(doc);
        return arrow::Status::Invalid("Schema must contain 'fields' array");
    }

    std::vector<std::shared_ptr<arrow::Field>> arrow_fields;
    yyjson_val* field_obj;
    yyjson_arr_iter iter;
    yyjson_arr_iter_init(fields_array, &iter);

    while ((field_obj = yyjson_arr_iter_next(&iter))) {
        if (!yyjson_is_obj(field_obj)) {
            continue;
        }

        yyjson_val* name_val = yyjson_obj_get(field_obj, "name");
        yyjson_val* type_val = yyjson_obj_get(field_obj, "type");
        yyjson_val* nullable_val = yyjson_obj_get(field_obj, "nullable");

        if (!name_val || !yyjson_is_str(name_val) || !type_val) {
            continue;
        }

        std::string field_name(yyjson_get_str(name_val));
        bool nullable = nullable_val ? yyjson_get_bool(nullable_val) : true;
        std::shared_ptr<arrow::DataType> data_type;

        const char* type_name_cstr = nullptr;
        yyjson_val* type_params = nullptr;

        if (yyjson_is_str(type_val)) {
            type_name_cstr = yyjson_get_str(type_val);
        } else if (yyjson_is_obj(type_val)) {
            yyjson_val* type_name_val = yyjson_obj_get(type_val, "name");
            if (type_name_val && yyjson_is_str(type_name_val)) {
                type_name_cstr = yyjson_get_str(type_name_val);
                type_params = type_val;
            }
        }

        if (!type_name_cstr) {
            continue;
        }

        std::string type_name(type_name_cstr);

        if (type_name == "timestamp") {
            arrow::TimeUnit::type time_unit = arrow::TimeUnit::MILLI;

            if (type_params) {
                yyjson_val* unit_val = yyjson_obj_get(type_params, "unit");
                if (unit_val && yyjson_is_str(unit_val)) {
                    std::string unit = yyjson_get_str(unit_val);

                    if (unit == "s") {
                        time_unit = arrow::TimeUnit::SECOND;
                    } else if (unit == "ms") {
                        time_unit = arrow::TimeUnit::MILLI;
                    } else if (unit == "us" || unit == "μs") {
                        time_unit = arrow::TimeUnit::MICRO;
                    } else if (unit == "ns") {
                        time_unit = arrow::TimeUnit::NANO;
                    } else {
                        yyjson_doc_free(doc);
                        return arrow::Status::Invalid(
                            "Invalid timestamp unit '" + unit + "'. Supported units: s, ms, us, ns");
                    }
                }
            }
            data_type = arrow::timestamp(time_unit);
        } else {
            auto it = TYPE_FACTORY_MAP.find(type_name);
            if (it == TYPE_FACTORY_MAP.end()) {
                flb_warn("[parquet] Unknown type '%s' for field '%s', falling back to string",
                         type_name.c_str(), field_name.c_str());
                data_type = arrow::utf8();
            } else {
                data_type = it->second();
            }
        }

        arrow_fields.push_back(arrow::field(field_name, data_type, nullable));
    }

    yyjson_doc_free(doc);

    if (arrow_fields.empty()) {
        return arrow::Status::Invalid("No valid fields found in schema");
    }

    return arrow::schema(arrow_fields);
}

bool append_default_value(arrow::ArrayBuilder* builder,
                         const std::shared_ptr<arrow::DataType>& type) {
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
            return static_cast<arrow::BinaryBuilder*>(builder)->AppendEmptyValue().ok();
        case arrow::Type::TIMESTAMP:
            return static_cast<arrow::TimestampBuilder*>(builder)->Append(0).ok();
        default:
            return false;
    }
}

/* Helper Class to encapsulate Streaming Logic */
class ParquetStreamingWriter {
public:
    ParquetStreamingWriter(std::shared_ptr<arrow::Schema> schema,
                           int compression,
                           const char* output_file)
        : schema_(std::move(schema)), output_file_(output_file), batch_records_(0) {
        
        /* Initialize builders */
        for (const auto& field : schema_->fields()) {
            auto builder_result = arrow::MakeBuilder(field->type(), arrow::default_memory_pool());
            if (!builder_result.ok()) {
                throw std::runtime_error("Failed to create builder for field " + field->name());
            }
            builders_.push_back(std::move(builder_result).ValueOrDie());
        }

        /* Build sorted index for fast lookups */
        for (int i = 0; i < schema_->num_fields(); ++i) {
            sorted_schema_idx_.emplace_back(schema_->field(i)->name(), i);
        }
        std::sort(sorted_schema_idx_.begin(), sorted_schema_idx_.end(),
                 [](const auto& a, const auto& b) { return a.first < b.first; });

        /* Configure compression */
        parquet::Compression::type parquet_compression;
        switch (compression) {
            case FLB_AWS_COMPRESS_GZIP: parquet_compression = parquet::Compression::GZIP; break;
            case FLB_AWS_COMPRESS_SNAPPY: parquet_compression = parquet::Compression::SNAPPY; break;
            case FLB_AWS_COMPRESS_ZSTD: parquet_compression = parquet::Compression::ZSTD; break;
            default: parquet_compression = parquet::Compression::UNCOMPRESSED; break;
        }

        parquet::WriterProperties::Builder props_builder;
        props_builder.compression(parquet_compression);
        props_builder.max_row_group_length(MAX_ROW_GROUP_LENGTH);
        writer_properties_ = props_builder.build();
    }

    void Open() {
        auto output_stream_result = arrow::io::FileOutputStream::Open(output_file_);
        if (!output_stream_result.ok()) {
            throw std::runtime_error("Failed to open output file: " + output_stream_result.status().ToString());
        }
        output_stream_ = std::move(output_stream_result).ValueOrDie();

        auto writer_result = parquet::arrow::FileWriter::Open(
            *schema_, arrow::default_memory_pool(), output_stream_, writer_properties_);
        if (!writer_result.ok()) {
            throw std::runtime_error("Failed to create parquet writer: " + writer_result.status().ToString());
        }
        writer_ = std::move(writer_result).ValueOrDie();
    }

    void ProcessRecord(const msgpack_object* map_obj) {
        if (map_obj->type != MSGPACK_OBJECT_MAP) return;

        /* Collect fields from record (linear scan, then sort) */
        record_fields_.clear();
        for (uint32_t i = 0; i < map_obj->via.map.size; i++) {
            const msgpack_object_kv* kv = &map_obj->via.map.ptr[i];
            if (kv->key.type == MSGPACK_OBJECT_STR) {
                record_fields_.emplace_back(
                    std::string_view(kv->key.via.str.ptr, kv->key.via.str.size),
                    &kv->val
                );
            }
        }
        
        /* Sort record fields by name to allow merge-join with sorted schema */
        std::sort(record_fields_.begin(), record_fields_.end());

        /* Synchronized iteration (Merge Join) */
        auto s_it = sorted_schema_idx_.begin();
        auto r_it = record_fields_.begin();

        while (s_it != sorted_schema_idx_.end()) {
            const msgpack_object* val = nullptr;
            
            /* Advance record iterator until it's >= schema iterator */
            while (r_it != record_fields_.end() && r_it->first < s_it->first) {
                r_it++;
            }

            /* Match found */
            if (r_it != record_fields_.end() && r_it->first == s_it->first) {
                val = r_it->second;
            }

            /* Convert value */
            int field_idx = s_it->second;
            auto field = schema_->field(field_idx);
            
            if (val && val->type != MSGPACK_OBJECT_NIL) {
                auto status = MsgpackToArrowConverter::convert_value(val, builders_[field_idx].get(), field->type());
                if (!status.ok()) {
                    if (field->nullable()) {
                        (void)builders_[field_idx]->AppendNull();
                    } else {
                        append_default_value(builders_[field_idx].get(), field->type());
                    }
                }
            } else {
                if (field->nullable()) {
                    (void)builders_[field_idx]->AppendNull();
                } else {
                    append_default_value(builders_[field_idx].get(), field->type());
                }
            }

            s_it++;
        }

        batch_records_++;
        if (batch_records_ >= RECORDS_PER_BATCH) {
            FlushBatch();
        }
    }

    void FlushBatch() {
        if (batch_records_ == 0) return;

        std::vector<std::shared_ptr<arrow::Array>> arrays;
        arrays.reserve(builders_.size());
        for (auto& builder : builders_) {
            auto array_result = builder->Finish();
            if (!array_result.ok()) {
                throw std::runtime_error("Failed to finish array: " + array_result.status().ToString());
            }
            arrays.push_back(std::move(array_result).ValueOrDie());
        }

        auto batch = arrow::RecordBatch::Make(schema_, batch_records_, arrays);
        if (!batch) throw std::runtime_error("Failed to create RecordBatch");

        auto write_status = writer_->WriteRecordBatch(*batch);
        if (!write_status.ok()) throw std::runtime_error("Failed to write batch: " + write_status.ToString());

        batch_records_ = 0;
    }

    void Close(size_t* out_file_size) {
        FlushBatch();

        auto close_status = writer_->Close();
        if (!close_status.ok()) {
            throw std::runtime_error("Failed to close parquet writer: " + close_status.ToString());
        }

        auto stream_close_status = output_stream_->Close();
        if (!stream_close_status.ok()) {
            throw std::runtime_error("Failed to close output stream: " + stream_close_status.ToString());
        }

        struct stat st;
        if (stat(output_file_.c_str(), &st) != 0) {
            throw std::runtime_error("Failed to stat output file");
        }
        *out_file_size = st.st_size;
    }

private:
    std::shared_ptr<arrow::Schema> schema_;
    std::string output_file_;
    int64_t batch_records_;
    
    std::shared_ptr<parquet::WriterProperties> writer_properties_;
    std::vector<std::shared_ptr<arrow::ArrayBuilder>> builders_;
    std::shared_ptr<arrow::io::FileOutputStream> output_stream_;
    std::unique_ptr<parquet::arrow::FileWriter> writer_;

    /* Optimization: Pre-sorted schema index (Name -> Field Index) */
    std::vector<std::pair<std::string, int>> sorted_schema_idx_;
    
    /* Optimization: Reusable vector for record fields */
    std::vector<std::pair<std::string_view, const msgpack_object*>> record_fields_;
};

} // anonymous namespace

extern "C" {

/* Validate parquet file: record count, field type and/or field values
 * expected_records: -1 to skip, field_name: NULL to skip field check
 * expected_type: NULL to skip type check (e.g., "int32", "string", "bool")
 */
int validate_parquet_file(const char *file_path,
                          int expected_records,
                          const char *field_name,
                          const char *expected_type,
                          const char *expected_value,
                          int row_index)
{
    if (!file_path) {
        flb_error("[parquet] NULL file path for validation");
        return -1;
    }

    try {
        /* Open parquet reader using the file path directly */
        std::unique_ptr<parquet::arrow::FileReader> reader;
        auto parquet_reader = parquet::ParquetFileReader::OpenFile(file_path);
        auto reader_result = parquet::arrow::FileReader::Make(
            arrow::default_memory_pool(), std::move(parquet_reader), &reader);
        if (!reader_result.ok()) {
            flb_error("[parquet] Failed to create parquet reader: %s",
                     reader_result.ToString().c_str());
            return -1;
        }

        /* Get file metadata */
        auto metadata = reader->parquet_reader()->metadata();
        int64_t total_rows = metadata->num_rows();

        /* Validate record count if expected value provided */
        if (expected_records >= 0) {
            if (total_rows != expected_records) {
                flb_error("[parquet] Record count mismatch: expected=%d, got=%lld",
                         expected_records, (long long)total_rows);
                return -1;
            }
        }

        /* Read all data to validate it can be read */
        std::shared_ptr<arrow::Table> table;
        auto read_result = reader->ReadTable(&table);
        if (!read_result.ok()) {
            flb_error("[parquet] Failed to read table: %s",
                     read_result.ToString().c_str());
            return -1;
        }

        /* Validate table has data */
        if (expected_records > 0 && table->num_rows() != total_rows) {
            flb_error("[parquet] Table row count mismatch: metadata=%lld, table=%lld",
                     (long long)total_rows, (long long)table->num_rows());
            return -1;
        }

        /* Validate schema and data types */
        auto schema = table->schema();

        /* If field_name is provided, validate field type and/or value */
        if (field_name) {
            int col_index = schema->GetFieldIndex(field_name);
            if (col_index < 0) {
                flb_error("[parquet] Field '%s' not found in schema", field_name);
                return -1;
            }

            auto field_type = schema->field(col_index)->type();

            /* Validate type if expected_type is provided */
            if (expected_type) {
                std::string actual_type = field_type->ToString();
                if (actual_type != expected_type) {
                    flb_error("[parquet] Type mismatch for field '%s': expected='%s', actual='%s'",
                             field_name, expected_type, actual_type.c_str());
                    return -1;
                }
            }

            /* Skip value validation if expected_value is NULL */
            if (!expected_value) {
                return 0;
            }

            /* Validate row index */
            if (row_index < 0 || row_index >= table->num_rows()) {
                flb_error("[parquet] Row index %d out of range (total rows: %lld)",
                         row_index, (long long)table->num_rows());
                return -1;
            }

            /* Get the column and combine all chunks for simpler access (test utility) */
            auto column = table->column(col_index);

            /* Combine all chunks into a single array */
            std::shared_ptr<arrow::Array> chunk;
            if (column->num_chunks() == 1) {
                chunk = column->chunk(0);
            } else {
                arrow::ArrayVector chunks_to_concat;
                for (int i = 0; i < column->num_chunks(); i++) {
                    chunks_to_concat.push_back(column->chunk(i));
                }
                auto concat_result = arrow::Concatenate(chunks_to_concat);
                if (!concat_result.ok()) {
                    flb_error("[parquet] Failed to concatenate column chunks: %s",
                             concat_result.status().ToString().c_str());
                    return -1;
                }
                chunk = std::move(concat_result).ValueOrDie();
            }

            /* Convert value to string for comparison */
            std::string actual_value;

            switch (field_type->id()) {
                case arrow::Type::STRING: {
                    auto string_array = std::static_pointer_cast<arrow::StringArray>(chunk);
                    if (!string_array->IsNull(row_index)) {
                        actual_value = string_array->GetString(row_index);
                    }
                    break;
                }
                case arrow::Type::INT32: {
                    auto int_array = std::static_pointer_cast<arrow::Int32Array>(chunk);
                    if (!int_array->IsNull(row_index)) {
                        actual_value = std::to_string(int_array->Value(row_index));
                    }
                    break;
                }
                case arrow::Type::INT64: {
                    auto int_array = std::static_pointer_cast<arrow::Int64Array>(chunk);
                    if (!int_array->IsNull(row_index)) {
                        actual_value = std::to_string(int_array->Value(row_index));
                    }
                    break;
                }
                case arrow::Type::BOOL: {
                    auto bool_array = std::static_pointer_cast<arrow::BooleanArray>(chunk);
                    if (!bool_array->IsNull(row_index)) {
                        actual_value = bool_array->Value(row_index) ? "true" : "false";
                    }
                    break;
                }
                case arrow::Type::FLOAT: {
                    auto float_array = std::static_pointer_cast<arrow::FloatArray>(chunk);
                    if (!float_array->IsNull(row_index)) {
                        actual_value = std::to_string(float_array->Value(row_index));
                    }
                    break;
                }
                case arrow::Type::DOUBLE: {
                    auto double_array = std::static_pointer_cast<arrow::DoubleArray>(chunk);
                    if (!double_array->IsNull(row_index)) {
                        actual_value = std::to_string(double_array->Value(row_index));
                    }
                    break;
                }
                case arrow::Type::TIMESTAMP: {
                    auto ts_array = std::static_pointer_cast<arrow::TimestampArray>(chunk);
                    if (!ts_array->IsNull(row_index)) {
                        actual_value = std::to_string(ts_array->Value(row_index));
                    }
                    break;
                }
                case arrow::Type::BINARY: {
                    auto binary_array = std::static_pointer_cast<arrow::BinaryArray>(chunk);
                    if (!binary_array->IsNull(row_index)) {
                        /* Convert binary data to hex string for comparison */
                        auto binary_view = binary_array->GetView(row_index);
                        actual_value = "";
                        for (int i = 0; i < binary_view.length(); i++) {
                            char hex[3];
                            snprintf(hex, sizeof(hex), "%02x", (unsigned char)binary_view.data()[i]);
                            actual_value += hex;
                        }
                    }
                    break;
                }
                default:
                    flb_warn("[parquet] Unsupported type for validation: %s",
                            field_type->ToString().c_str());
                    return 0;  /* Skip validation for unsupported types */
            }

            /* Compare values if expected value is provided */
            if (expected_value) {
                if (actual_value != expected_value) {
                    flb_error("[parquet] Value mismatch for field '%s' at row %d: expected='%s', actual='%s'",
                             field_name, row_index, expected_value, actual_value.c_str());
                    return -1;
                }
            }
        }
        /* No field validation requested - validation passed */

        return 0;
    }
    catch (const parquet::ParquetException& e) {
        flb_error("[parquet] Validation parquet exception: %s", e.what());
        return -1;
    }
    catch (const std::exception& e) {
        flb_error("[parquet] Validation exception: %s", e.what());
        return -1;
    }
    catch (...) {
        flb_error("[parquet] Unknown validation exception");
        return -1;
    }
}

int flb_parquet_validate_schema(const char *schema_str,
                                 char *error_msg,
                                 size_t error_msg_size)
{
    if (!schema_str) {
        if (error_msg && error_msg_size > 0) {
            snprintf(error_msg, error_msg_size, "NULL schema_str");
        }
        return -1;
    }

    /* Reuse parse_schema_from_json to avoid code duplication */
    auto result = parse_schema_from_json(schema_str);

    if (!result.ok()) {
        if (error_msg && error_msg_size > 0) {
            snprintf(error_msg, error_msg_size, "%s",
                    result.status().ToString().c_str());
        }
        return -1;
    }

    return 0;
}

flb_parquet_schema *flb_parquet_schema_create(const char *schema_str,
                                                   char *error_msg,
                                                   size_t error_msg_size)
{
    if (!schema_str) {
        if (error_msg && error_msg_size > 0) {
            snprintf(error_msg, error_msg_size, "NULL schema_str");
        }
        return NULL;
    }

    auto result = parse_schema_from_json(schema_str);

    if (!result.ok()) {
        if (error_msg && error_msg_size > 0) {
            snprintf(error_msg, error_msg_size, "%s",
                    result.status().ToString().c_str());
        }
        return NULL;
    }

    /* Store as heap-allocated shared_ptr to pass through C API */
    auto schema = result.ValueOrDie();
    auto cached = new std::shared_ptr<arrow::Schema>(schema);
    return reinterpret_cast<flb_parquet_schema*>(cached);
}

void flb_parquet_schema_destroy(flb_parquet_schema *schema)
{
    if (schema) {
        auto schema_ptr = reinterpret_cast<std::shared_ptr<arrow::Schema>*>(schema);
        delete schema_ptr;
    }
}

int flb_msgpack_to_parquet_streaming(const char *msgpack_file_path,
                                      flb_parquet_schema *schema,
                                      int compression,
                                      const char *output_file,
                                      size_t *out_file_size,
                                      size_t total_file_size)
{
    /* Silence unused parameter warning */
    (void)total_file_size;

    if (!msgpack_file_path || !out_file_size || !schema || !output_file) {
        flb_error("[parquet] NULL parameter");
        return -1;
    }

    auto schema_ptr = reinterpret_cast<std::shared_ptr<arrow::Schema>*>(schema);

    /* RAII: Manage input file */
    ScopedFile msgpack_fp(flb_chunk_file_open(msgpack_file_path));
    if (!msgpack_fp) {
        flb_error("[parquet] Failed to open msgpack file: %s", msgpack_file_path);
        return -1;
    }

    bool success = false;

    try {
        ParquetStreamingWriter writer(*schema_ptr, compression, output_file);
        writer.Open();

        std::vector<char> read_buffer(IO_BUFFER_SIZE);
        ScopedMsgpackUnpacker unpacker(IO_BUFFER_SIZE);
        if (!unpacker.isValid()) {
            throw std::runtime_error("Failed to initialize msgpack unpacker");
        }

        ScopedMsgpackResult result;
        size_t bytes_read;
        size_t records_processed = 0;

        while ((bytes_read = fread(read_buffer.data(), 1, read_buffer.size(), msgpack_fp.get())) > 0) {
            if (!msgpack_unpacker_reserve_buffer(unpacker.get(), bytes_read)) {
                throw std::runtime_error("msgpack unpacker buffer reserve failed");
            }

            memcpy(msgpack_unpacker_buffer(unpacker.get()), read_buffer.data(), bytes_read);
            msgpack_unpacker_buffer_consumed(unpacker.get(), bytes_read);

            msgpack_unpack_return ret;
            while ((ret = msgpack_unpacker_next(unpacker.get(), result.get())) != MSGPACK_UNPACK_CONTINUE) {
                if (ret == MSGPACK_UNPACK_SUCCESS || ret == MSGPACK_UNPACK_EXTRA_BYTES) {
                    const msgpack_object* record = &result.get()->data;
                    
                    if (record->type == MSGPACK_OBJECT_ARRAY && record->via.array.size == 2) {
                        const msgpack_object* map_obj = &record->via.array.ptr[1];
                        writer.ProcessRecord(map_obj);
                        records_processed++;
                    }
                    
                    /* Critical Fix: Reset result to prevent memory growth (unpacker zone) */
                    result.reset();
                    
                } else if (ret == MSGPACK_UNPACK_PARSE_ERROR) {
                    throw std::runtime_error("Msgpack parse error");
                } else if (ret == MSGPACK_UNPACK_NOMEM_ERROR) {
                    throw std::runtime_error("Msgpack no memory error");
                }
            }
        }

        if (ferror(msgpack_fp.get())) {
            throw std::runtime_error("Error reading msgpack file");
        }

        if (records_processed == 0) {
             throw std::runtime_error("No records processed");
        }

        writer.Close(out_file_size);
        success = true;

    } catch (const std::exception& e) {
        flb_error("[parquet] Error: %s", e.what());
    } catch (...) {
        flb_error("[parquet] Unknown error");
    }

    if (!success) {
        unlink(output_file);
        return -1;
    }

    return 0;
}

} // extern "C"
