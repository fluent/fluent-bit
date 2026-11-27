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

/*
 * OTLP protobuf logs in, attribute edits, OTLP protobuf out.
 *
 *   view-*      CFL map views over the wire format
 *   protobuf-c  full object graph: unpack, edit, pack
 *   pipeline    the conversions a Fluent Bit OTLP pipeline runs today:
 *               protobuf -> CFL -> edit -> MessagePack chunk -> protobuf
 *
 * Usage: flb-bench-otlp_log_views [records per request] [attributes] [seconds per case]
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_opentelemetry.h>
#include <fluent-bit/flb_log_view.h>
#include <fluent-bit/flb_opentelemetry_view.h>
#include <fluent-otel-proto/fluent-otel.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOGS(name) opentelemetry__proto__collector__logs__v1__export_logs_service_request__##name
#define SOURCE_KEY "exception.type"
#define RENAMED_KEY "exception.kind"
#define INSERT_KEY "benchmark.enriched"

/* Allocation accounting: glibc lets an executable interpose these symbols. */
#ifdef __GLIBC__
#define ALLOCATION_ACCOUNTING 1

extern void *__libc_malloc(size_t size);
extern void *__libc_calloc(size_t count, size_t size);
extern void *__libc_realloc(void *pointer, size_t size);
extern void __libc_free(void *pointer);

static size_t allocation_count;
static size_t allocation_bytes;

void *malloc(size_t size)
{
    allocation_count++;
    allocation_bytes += size;
    return __libc_malloc(size);
}

void *calloc(size_t count, size_t size)
{
    allocation_count++;
    allocation_bytes += count * size;
    return __libc_calloc(count, size);
}

void *realloc(void *pointer, size_t size)
{
    allocation_count++;
    allocation_bytes += size;
    return __libc_realloc(pointer, size);
}

void free(void *pointer)
{
    __libc_free(pointer);
}
#else
/* not available: the allocation columns are reported as 'nan' */
#define ALLOCATION_ACCOUNTING 0

static size_t allocation_count;
static size_t allocation_bytes;
#endif

static double seconds_now(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double) now.tv_sec + (double) now.tv_nsec / 1e9;
}

/* A benchmark has nothing to measure without memory. */
static void *checked(void *memory)
{
    if (memory == NULL) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }

    return memory;
}

/* Every other record carries the key the rename looks for. */
static void *payload_create(size_t records, size_t attributes, size_t *size)
{
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest request;
    Opentelemetry__Proto__Logs__V1__ResourceLogs resource_logs;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_list[1];
    Opentelemetry__Proto__Logs__V1__ScopeLogs scope_logs;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_list[1];
    Opentelemetry__Proto__Resource__V1__Resource resource;
    Opentelemetry__Proto__Common__V1__InstrumentationScope scope;
    Opentelemetry__Proto__Common__V1__AnyValue body;
    Opentelemetry__Proto__Logs__V1__LogRecord *record;
    Opentelemetry__Proto__Logs__V1__LogRecord **record_list;
    Opentelemetry__Proto__Common__V1__KeyValue *pairs;
    Opentelemetry__Proto__Common__V1__KeyValue **pair_list;
    Opentelemetry__Proto__Common__V1__AnyValue *values;
    char (*keys)[48];
    size_t index;
    size_t attribute;
    size_t slot;
    void *buffer;

    record = checked(calloc(records, sizeof(*record)));
    record_list = checked(calloc(records, sizeof(*record_list)));
    pairs = checked(calloc(records * attributes, sizeof(*pairs)));
    pair_list = checked(calloc(records * attributes, sizeof(*pair_list)));
    values = checked(calloc(records * attributes, sizeof(*values)));
    keys = checked(calloc(attributes, sizeof(*keys)));
    for (attribute = 0; attribute < attributes; attribute++) {
        snprintf(keys[attribute], sizeof(keys[attribute]), "attribute.name.%zu", attribute);
    }

    opentelemetry__proto__common__v1__any_value__init(&body);
    body.value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    body.string_value = "GET /api/v1/items/42 HTTP/1.1 200 1532 0.012";
    for (index = 0; index < records; index++) {
        opentelemetry__proto__logs__v1__log_record__init(&record[index]);
        record[index].time_unix_nano = 1700000000000000000ULL + index;
        record[index].observed_time_unix_nano = 1700000000000000000ULL + index;
        record[index].severity_number = 9;
        record[index].severity_text = "INFO";
        record[index].body = &body;
        record[index].n_attributes = attributes;
        record[index].attributes = &pair_list[index * attributes];
        record_list[index] = &record[index];
        for (attribute = 0; attribute < attributes; attribute++) {
            slot = index * attributes + attribute;
            opentelemetry__proto__common__v1__key_value__init(&pairs[slot]);
            opentelemetry__proto__common__v1__any_value__init(&values[slot]);
            pairs[slot].key = keys[attribute];
            if (attribute == attributes / 2 && index % 2 == 0) {
                pairs[slot].key = SOURCE_KEY;
            }
            pairs[slot].value = &values[slot];
            if (attribute % 3 == 2) {
                values[slot].value_case =
                    OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE;
                values[slot].int_value = (int64_t) (index * 31 + attribute);
            }
            else {
                values[slot].value_case =
                    OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
                values[slot].string_value = "a-typical-attribute-value";
            }
            pair_list[slot] = &pairs[slot];
        }
    }

    opentelemetry__proto__resource__v1__resource__init(&resource);
    opentelemetry__proto__common__v1__instrumentation_scope__init(&scope);
    scope.name = "bench";
    opentelemetry__proto__logs__v1__scope_logs__init(&scope_logs);
    scope_logs.scope = &scope;
    scope_logs.n_log_records = records;
    scope_logs.log_records = record_list;
    scope_list[0] = &scope_logs;
    opentelemetry__proto__logs__v1__resource_logs__init(&resource_logs);
    resource_logs.resource = &resource;
    resource_logs.n_scope_logs = 1;
    resource_logs.scope_logs = scope_list;
    resource_list[0] = &resource_logs;
    LOGS(init)(&request);
    request.n_resource_logs = 1;
    request.resource_logs = resource_list;

    *size = LOGS(get_packed_size)(&request);
    buffer = checked(malloc(*size));
    LOGS(pack)(&request, buffer);

    free(record);
    free(record_list);
    free(pairs);
    free(pair_list);
    free(values);
    free(keys);

    return buffer;
}

/* The same three edits for every implementation. */
enum edit {
    EDIT_NONE,
    EDIT_LOOKUP,
    EDIT_RENAME,
    EDIT_BOTH
};

static size_t lookup_hits;

static int cb_view(void *data, struct flb_log_view *record)
{
    enum edit edit = *(enum edit *) data;
    struct cfl_view *view = record->otel_log_attributes;
    struct cfl_view_value value;
    int64_t index;

    if (edit == EDIT_LOOKUP) {
        if (cfl_view_get(view, SOURCE_KEY, sizeof(SOURCE_KEY) - 1, &value) == 1) {
            lookup_hits++;
        }
        return 0;
    }
    if (edit >= EDIT_RENAME) {
        index = cfl_view_find(view, SOURCE_KEY, sizeof(SOURCE_KEY) - 1);
        if (index >= 0) {
            cfl_view_rename_at(view, (size_t) index, RENAMED_KEY, sizeof(RENAMED_KEY) - 1);
        }
    }
    if (edit == EDIT_BOTH &&
        cfl_view_find(view, INSERT_KEY, sizeof(INSERT_KEY) - 1) < 0) {
        return cfl_view_append_string(view, INSERT_KEY, sizeof(INSERT_KEY) - 1, "true", 4);
    }

    return 0;
}

static size_t run_view(const void *payload, size_t size, enum edit edit)
{
    struct flb_log_view_editor editor = {cb_view, &edit};
    size_t out_size = 0;
    size_t records = 0;
    void *out;

    if (edit == EDIT_LOOKUP) {
        if (flb_opentelemetry_logs_proto_view_scan(payload, size, &editor, &records) != 0) {
            abort();
        }
        return size;
    }
    if (flb_opentelemetry_logs_proto_view_transform(payload, size, &editor, &out, &out_size,
                                                    &records, NULL) != 0) {
        abort();
    }
    flb_free(out);

    return out_size;
}

static size_t run_protobuf_c(const void *payload, size_t size, enum edit edit)
{
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *request;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope;
    Opentelemetry__Proto__Logs__V1__LogRecord *record;
    Opentelemetry__Proto__Common__V1__KeyValue **original;
    Opentelemetry__Proto__Common__V1__KeyValue **grown;
    Opentelemetry__Proto__Common__V1__KeyValue inserted;
    Opentelemetry__Proto__Common__V1__AnyValue inserted_value;
    size_t out_size;
    size_t index;
    size_t attribute;
    size_t resource;
    size_t resources;
    size_t scope_index;
    char **renamed;
    size_t renamed_count = 0;
    void **grown_list;
    size_t grown_count = 0;
    void *out;
    int present;

    request = LOGS(unpack)(NULL, size, payload);
    if (request == NULL) {
        abort();
    }

    opentelemetry__proto__common__v1__key_value__init(&inserted);
    opentelemetry__proto__common__v1__any_value__init(&inserted_value);
    inserted.key = INSERT_KEY;
    inserted.value = &inserted_value;
    inserted_value.value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    inserted_value.string_value = "true";

    /* undo list: the unpacked tree must be freed with its own pointers */
    index = 0;
    for (resource = 0; resource < request->n_resource_logs; resource++) {
        for (scope_index = 0; scope_index < request->resource_logs[resource]->n_scope_logs;
             scope_index++) {
            index += request->resource_logs[resource]->scope_logs[scope_index]->n_log_records;
        }
    }
    renamed = NULL;
    grown_list = NULL;
    if (edit >= EDIT_RENAME) {
        renamed = checked(malloc(index * 2 * sizeof(char *) + 1));
    }
    if (edit == EDIT_BOTH) {
        grown_list = checked(malloc(index * 3 * sizeof(void *) + 1));
    }

    /* without a transformation the records are not visited at all */
    resources = edit == EDIT_NONE ? 0 : request->n_resource_logs;
    for (resource = 0; resource < resources; resource++) {
        for (scope_index = 0; scope_index < request->resource_logs[resource]->n_scope_logs;
             scope_index++) {
            scope = request->resource_logs[resource]->scope_logs[scope_index];
            for (index = 0; index < scope->n_log_records; index++) {
                record = scope->log_records[index];
                present = FLB_FALSE;
                for (attribute = 0; attribute < record->n_attributes; attribute++) {
                    if (edit == EDIT_LOOKUP &&
                        strcmp(record->attributes[attribute]->key, SOURCE_KEY) == 0) {
                        lookup_hits++;
                        break;
                    }
                    if (edit >= EDIT_RENAME && renamed_count % 2 == 0 &&
                        strcmp(record->attributes[attribute]->key, SOURCE_KEY) == 0) {
                        renamed[renamed_count++] = (char *) &record->attributes[attribute]->key;
                        renamed[renamed_count++] = record->attributes[attribute]->key;
                        record->attributes[attribute]->key = RENAMED_KEY;
                    }
                    if (edit == EDIT_BOTH &&
                        strcmp(record->attributes[attribute]->key, INSERT_KEY) == 0) {
                        present = FLB_TRUE;
                    }
                }
                if (edit == EDIT_BOTH && !present) {
                    original = record->attributes;
                    grown = checked(malloc((record->n_attributes + 1) * sizeof(*grown)));
                    memcpy(grown, original, record->n_attributes * sizeof(*grown));
                    grown[record->n_attributes] = &inserted;
                    grown_list[grown_count++] = record;
                    grown_list[grown_count++] = original;
                    grown_list[grown_count++] = grown;
                    record->attributes = grown;
                    record->n_attributes++;
                }
            }
        }
    }

    out_size = size;
    if (edit != EDIT_LOOKUP) {
        out_size = LOGS(get_packed_size)(request);
        out = checked(malloc(out_size));
        LOGS(pack)(request, out);
        free(out);
    }

    for (index = 0; index < grown_count; index += 3) {
        record = grown_list[index];
        record->attributes = grown_list[index + 1];
        record->n_attributes--;
        free(grown_list[index + 2]);
    }
    for (index = 0; index < renamed_count; index += 2) {
        *(char **) renamed[index] = renamed[index + 1];
    }
    free(grown_list);
    free(renamed);
    LOGS(free_unpacked)(request, NULL);

    return out_size;
}

static struct cfl_kvpair *kvlist_pair(struct cfl_kvlist *kvlist, const char *key, size_t size)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;

    cfl_list_foreach(head, &kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (cfl_sds_len(pair->key) == size && memcmp(pair->key, key, size) == 0) {
            return pair;
        }
    }

    return NULL;
}

/* What content_modifier does to otel_log_attributes on a CFL record. */
static void cfl_edit(struct flb_mp_chunk_record *record, enum edit edit)
{
    struct cfl_kvlist *metadata;
    struct cfl_kvlist *attributes;
    struct cfl_variant *value;
    struct cfl_kvpair *pair;
    cfl_sds_t key;

    if (record->cobj_metadata == NULL ||
        record->cobj_metadata->variant->type != CFL_VARIANT_KVLIST) {
        return;
    }
    metadata = record->cobj_metadata->variant->data.as_kvlist;
    value = cfl_kvlist_fetch(metadata, "otlp");
    if (value == NULL || value->type != CFL_VARIANT_KVLIST) {
        return;
    }
    value = cfl_kvlist_fetch(value->data.as_kvlist, "attributes");
    if (value == NULL || value->type != CFL_VARIANT_KVLIST) {
        return;
    }
    attributes = value->data.as_kvlist;

    if (edit == EDIT_LOOKUP) {
        lookup_hits += kvlist_pair(attributes, SOURCE_KEY, sizeof(SOURCE_KEY) - 1) != NULL;
        return;
    }
    if (edit >= EDIT_RENAME) {
        pair = kvlist_pair(attributes, SOURCE_KEY, sizeof(SOURCE_KEY) - 1);
        if (pair != NULL) {
            key = checked(cfl_sds_create_len_in(pair->arena, RENAMED_KEY,
                                                sizeof(RENAMED_KEY) - 1));
            cfl_sds_destroy(pair->key);
            pair->key = key;
        }
    }
    if (edit == EDIT_BOTH &&
        kvlist_pair(attributes, INSERT_KEY, sizeof(INSERT_KEY) - 1) == NULL) {
        cfl_kvlist_insert_string_s(attributes, INSERT_KEY, sizeof(INSERT_KEY) - 1, "true", 4,
                                   CFL_FALSE);
    }
}

static size_t run_pipeline(const void *payload, size_t size, enum edit edit)
{
    struct flb_opentelemetry_logs_decode_options options;
    struct flb_opentelemetry_otlp_logs_options otlp = {0};
    struct flb_opentelemetry_logs_protobuf_cfl *decoded = NULL;
    struct flb_log_event_encoder encoder;
    struct flb_mp_chunk_record *record;
    struct flb_mp_chunk_cobj *chunk;
    struct cfl_list *head;
    size_t out_size;
    flb_sds_t out;
    int result;

    memset(&options, 0, sizeof(options));
    options.metadata_key = "otlp";
    options.output_limit = SIZE_MAX;
    if (flb_opentelemetry_logs_protobuf_to_cfl(payload, size, &options, &decoded) != 0) {
        abort();
    }
    chunk = flb_opentelemetry_logs_protobuf_cfl_take_chunk(decoded);
    if (edit != EDIT_NONE) {
        cfl_list_foreach(head, &chunk->records) {
            record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
            cfl_edit(record, edit);
        }
    }

    flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
    chunk->log_encoder = &encoder;
    if (flb_mp_chunk_cobj_encode_append(chunk) != 0) {
        abort();
    }
    chunk->log_encoder = NULL;
    flb_mp_chunk_cobj_destroy(chunk);
    flb_opentelemetry_logs_protobuf_cfl_destroy(decoded);

    out_size = size;
    if (edit != EDIT_LOOKUP) {
        otlp.logs_require_otel_metadata = FLB_TRUE;
        out = flb_opentelemetry_logs_to_otlp_proto(encoder.output_buffer, encoder.output_length,
                                                   &otlp, &result);
        if (out == NULL) {
            abort();
        }
        out_size = flb_sds_len(out);
        flb_opentelemetry_logs_proto_destroy(out);
    }
    flb_log_event_encoder_destroy(&encoder);

    return out_size;
}

struct bench_case {
    const char *implementation;
    const char *scenario;
    size_t (*run) (const void *, size_t, enum edit);
    enum edit edit;
};

static int compare_double(const void *first, const void *second)
{
    double a = *(const double *) first;
    double b = *(const double *) second;

    return (a > b) - (a < b);
}

int main(int argc, char **argv)
{
    static const struct bench_case cases[] = {
        {"view", "no transformation", run_view, EDIT_NONE},
        {"view", "one attribute lookup", run_view, EDIT_LOOKUP},
        {"view", "attribute rename", run_view, EDIT_RENAME},
        {"view", "rename + insert", run_view, EDIT_BOTH},
        {"protobuf-c", "no transformation", run_protobuf_c, EDIT_NONE},
        {"protobuf-c", "one attribute lookup", run_protobuf_c, EDIT_LOOKUP},
        {"protobuf-c", "attribute rename", run_protobuf_c, EDIT_RENAME},
        {"protobuf-c", "rename + insert", run_protobuf_c, EDIT_BOTH},
        {"pipeline", "no transformation", run_pipeline, EDIT_NONE},
        {"pipeline", "one attribute lookup", run_pipeline, EDIT_LOOKUP},
        {"pipeline", "attribute rename", run_pipeline, EDIT_RENAME},
        {"pipeline", "rename + insert", run_pipeline, EDIT_BOTH},
    };
    size_t records = argc > 1 ? strtoul(argv[1], NULL, 10) : 1000;
    size_t attributes = argc > 2 ? strtoul(argv[2], NULL, 10) : 8;
    double budget = argc > 3 ? strtod(argv[3], NULL) : 2.0;
    double *samples;
    double started;
    double begin;
    double total;
    size_t capacity = 1 << 20;
    size_t count;
    size_t index;
    size_t size;
    size_t out_size;
    size_t allocations;
    size_t bytes;
    void *payload;

    if (records == 0 || attributes == 0 || !(budget >= 0)) {
        fprintf(stderr, "records and attributes must be positive, seconds not negative\n");
        return 1;
    }

    payload = payload_create(records, attributes, &size);
    samples = checked(malloc(capacity * sizeof(double)));
    printf("# records=%zu attributes=%zu request_bytes=%zu seconds_per_case=%.1f\n",
           records, attributes, size, budget);
    printf("implementation,scenario,records_per_second,ns_per_record,"
           "p50_us_per_request,p95_us_per_request,p99_us_per_request,"
           "allocations_per_record,allocated_bytes_per_record,output_bytes\n");

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        /* warm up, then count allocations on one request */
        out_size = cases[index].run(payload, size, cases[index].edit);
        allocations = allocation_count;
        bytes = allocation_bytes;
        cases[index].run(payload, size, cases[index].edit);
        allocations = allocation_count - allocations;
        bytes = allocation_bytes - bytes;

        count = 0;
        total = 0;
        started = seconds_now();
        /* one request at least, whatever the time allowed */
        do {
            begin = seconds_now();
            cases[index].run(payload, size, cases[index].edit);
            samples[count] = seconds_now() - begin;
            total += samples[count++];
        } while (count < capacity && seconds_now() - started < budget);
        qsort(samples, count, sizeof(double), compare_double);
        printf("%s,%s,%.0f,%.1f,%.1f,%.1f,%.1f,",
               cases[index].implementation, cases[index].scenario,
               (double) (count * records) / total, total * 1e9 / (double) (count * records),
               samples[count / 2] * 1e6, samples[count * 95 / 100] * 1e6,
               samples[count * 99 / 100] * 1e6);
        if (ALLOCATION_ACCOUNTING) {
            printf("%.2f,%.1f,", (double) allocations / (double) records,
                   (double) bytes / (double) records);
        }
        else {
            printf("nan,nan,");
        }
        printf("%zu\n", out_size);
    }

    /* the lookups are part of what is timed: their result is used */
    printf("# lookup_hits=%zu\n", lookup_hits);

    free(samples);
    free(payload);

    return 0;
}
