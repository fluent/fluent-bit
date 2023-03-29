/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <ctraces/ctraces.h>
#include <unistd.h>
#include <curl/curl.h>

int main()
{
    cfl_sds_t buf;
    struct ctrace *ctx;
    struct ctrace_opts opts;
    struct ctrace_span *span_root;
    struct ctrace_span *span_child;
    struct ctrace_span_event *event;
    struct ctrace_resource_span *resource_span;
    struct ctrace_resource *resource;
    struct ctrace_scope_span *scope_span;
    struct ctrace_instrumentation_scope *instrumentation_scope;
    struct ctrace_link *link;
    struct ctrace_id *span_id;
    struct ctrace_id *trace_id;
    struct cfl_array *array;
    struct cfl_array *sub_array;
    struct cfl_kvlist *kv;

    struct curl_slist *headers;
    CURL *curl;
    CURLcode res;

    /*
     * create an options context: this is used to initialize a CTrace context only,
     * it's not mandatory and you can pass a NULL instead on context creation.
     *
     * note: not used.
     */
    ctr_opts_init(&opts);

    /* ctrace context */
    ctx = ctr_create(&opts);
    if (!ctx) {
        ctr_opts_exit(&opts);
        exit(EXIT_FAILURE);
    }

    /* resource span */
    resource_span = ctr_resource_span_create(ctx);
    ctr_resource_span_set_schema_url(resource_span, "https://ctraces/resource_span_schema_url");

    /* create a 'resource' for the 'resource span' in question */
    resource = ctr_resource_span_get_resource(resource_span);
    ctr_resource_set_dropped_attr_count(resource, 5);

    /* scope span */
    scope_span = ctr_scope_span_create(resource_span);
    ctr_scope_span_set_schema_url(scope_span, "https://ctraces/scope_span_schema_url");

    /* create an optional instrumentation scope */
    instrumentation_scope = ctr_instrumentation_scope_create("ctrace", "a.b.c", 3, NULL);
    ctr_scope_span_set_instrumentation_scope(scope_span, instrumentation_scope);

    /* generate a random trace_id */
    trace_id = ctr_id_create_random(CTR_ID_OTEL_TRACE_SIZE);

    /* generate a random ID for the new span */
    span_id = ctr_id_create_random(CTR_ID_OTEL_SPAN_SIZE);

    /* Create a root span */
    span_root = ctr_span_create(ctx, scope_span, "main", NULL);
    if (!span_root) {
        ctr_destroy(ctx);
        ctr_opts_exit(&opts);
        exit(EXIT_FAILURE);
    }

    /* assign the random ID */
    ctr_span_set_span_id_with_cid(span_root, span_id);

    /* set random trace_id */
    ctr_span_set_trace_id_with_cid(span_root, trace_id);

    /* add some attributes to the span */
    ctr_span_set_attribute_string(span_root, "agent", "Fluent Bit");
    ctr_span_set_attribute_int64(span_root, "year", 2022);
    ctr_span_set_attribute_bool(span_root, "open_source", CTR_TRUE);
    ctr_span_set_attribute_double(span_root, "temperature", 25.5);

    /* pack an array: create an array context by using the CFL api */
    array = cfl_array_create(4);
    cfl_array_append_string(array, "first");
    cfl_array_append_double(array, 2.0);
    cfl_array_append_bool(array, CFL_FALSE);

    sub_array = cfl_array_create(3);
    cfl_array_append_double(sub_array, 3.1);
    cfl_array_append_double(sub_array, 5.2);
    cfl_array_append_double(sub_array, 6.3);
    cfl_array_append_array(array, sub_array);

    /* add array to the attribute list */
    ctr_span_set_attribute_array(span_root, "my_array", array);

    /* event: add one event and set attributes to it */
    event = ctr_span_event_add(span_root, "connect to remote server");

    ctr_span_event_set_attribute_string(event, "syscall 1", "open()");
    ctr_span_event_set_attribute_string(event, "syscall 2", "connect()");
    ctr_span_event_set_attribute_string(event, "syscall 3", "write()");

    /* add a key/value pair list */
    kv = cfl_kvlist_create(1);
    cfl_kvlist_insert_string(kv, "language", "c");

    ctr_span_set_attribute_kvlist(span_root, "my-list", kv);

    /* create a child span */
    span_child = ctr_span_create(ctx, scope_span, "do-work", span_root);
    if (!span_child) {
        ctr_destroy(ctx);
        ctr_opts_exit(&opts);
        exit(EXIT_FAILURE);
    }

    /* set trace_id */
    ctr_span_set_trace_id_with_cid(span_child, trace_id);

    /* use span_root ID as parent_span_id */
    ctr_span_set_parent_span_id_with_cid(span_child, span_id);

    /* delete old span id and generate a new one */
    ctr_id_destroy(span_id);
    span_id = ctr_id_create_random(CTR_ID_OTEL_SPAN_SIZE);
    ctr_span_set_span_id_with_cid(span_child, span_id);

    /* destroy the IDs since is not longer needed */
    ctr_id_destroy(span_id);
    ctr_id_destroy(trace_id);

    /* change span kind to client */
    ctr_span_kind_set(span_child, CTRACE_SPAN_CLIENT);

    /* create a Link (no valid IDs of course) */
    trace_id = ctr_id_create_random(CTR_ID_OTEL_TRACE_SIZE);
    span_id = ctr_id_create_random(CTR_ID_OTEL_SPAN_SIZE);

    link = ctr_link_create_with_cid(span_child, trace_id, span_id);
    ctr_link_set_trace_state(link, "aaabbbccc");
    ctr_link_set_dropped_attr_count(link, 2);

    /* delete IDs */
    ctr_id_destroy(span_id);
    ctr_id_destroy(trace_id);

    /* Encode Trace as otlp buffer */
    buf = ctr_encode_opentelemetry_create(ctx);
    if (!buf) {
        ctr_destroy(ctx);
        ctr_encode_opentelemetry_destroy(buf);
        ctr_opts_exit(&opts);
        exit(EXIT_FAILURE);
    }

    curl = curl_easy_init();

    if (curl){
        headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/x-protobuf");
        curl_easy_setopt(curl, CURLOPT_URL, "0.0.0.0:4318/v1/traces");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, cfl_sds_len(buf));
        res = curl_easy_perform(curl);
        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();

    /* destroy the context */
    ctr_destroy(ctx);
    ctr_encode_opentelemetry_destroy(buf);

    /* exit options (it release resources allocated) */
    ctr_opts_exit(&opts);

    return 0;
}
