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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-otel-proto/fluent-otel.h>

Opentelemetry__Proto__Common__V1__ArrayValue *otlp_array_value_initialize(size_t entry_count);
Opentelemetry__Proto__Common__V1__KeyValue *otlp_kvpair_value_initialize();
Opentelemetry__Proto__Common__V1__KeyValueList *otlp_kvlist_value_initialize(size_t entry_count);
Opentelemetry__Proto__Common__V1__AnyValue *otlp_any_value_initialize(int data_type, size_t entry_count);

void otlp_kvarray_destroy(Opentelemetry__Proto__Common__V1__KeyValue **kvarray, size_t entry_count);
int otlp_kvarray_append(Opentelemetry__Proto__Common__V1__KeyValue ***base,
                        size_t *base_count,
                        Opentelemetry__Proto__Common__V1__KeyValue **extra,
                        size_t extra_count);
void otlp_kvpair_destroy(Opentelemetry__Proto__Common__V1__KeyValue *kvpair);
void otlp_kvlist_destroy(Opentelemetry__Proto__Common__V1__KeyValueList *kvlist);
void otlp_array_destroy(Opentelemetry__Proto__Common__V1__ArrayValue *array);
void otlp_any_value_destroy(Opentelemetry__Proto__Common__V1__AnyValue *value);

Opentelemetry__Proto__Common__V1__AnyValue *msgpack_boolean_to_otlp_any_value(struct msgpack_object *o);
Opentelemetry__Proto__Common__V1__AnyValue *msgpack_integer_to_otlp_any_value(struct msgpack_object *o);
Opentelemetry__Proto__Common__V1__AnyValue *msgpack_float_to_otlp_any_value(struct msgpack_object *o);
Opentelemetry__Proto__Common__V1__AnyValue *msgpack_string_to_otlp_any_value(struct msgpack_object *o);
Opentelemetry__Proto__Common__V1__AnyValue *msgpack_nil_to_otlp_any_value(struct msgpack_object *o);
Opentelemetry__Proto__Common__V1__AnyValue *msgpack_bin_to_otlp_any_value(struct msgpack_object *o);
Opentelemetry__Proto__Common__V1__AnyValue *msgpack_array_to_otlp_any_value(struct msgpack_object *o);

Opentelemetry__Proto__Common__V1__KeyValue *msgpack_kv_to_otlp_any_value(struct msgpack_object_kv *input_pair);
Opentelemetry__Proto__Common__V1__KeyValue **msgpack_map_to_otlp_kvarray(struct msgpack_object *o, size_t *entry_count);
Opentelemetry__Proto__Common__V1__AnyValue *msgpack_map_to_otlp_any_value(struct msgpack_object *o);
Opentelemetry__Proto__Common__V1__AnyValue *msgpack_object_to_otlp_any_value(struct msgpack_object *o);

