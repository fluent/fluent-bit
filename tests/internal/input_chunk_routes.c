#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_chunk.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_routes_mask.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_kv.h>
#include <monkey/mk_core.h>
#include <chunkio/chunkio.h>
#include <chunkio/cio_utils.h>
#include <string.h>
#include <cmetrics/cmetrics.h>

#include "flb_tests_internal.h"

#define TEST_STREAM_PATH "/tmp/flb-chunk-direct-test"
#define TEST_STREAM_PATH_MATCH "/tmp/flb-chunk-direct-test-match"
#define TEST_STREAM_PATH_NULL  "/tmp/flb-chunk-direct-test-null"

static int write_test_log_payload(struct cio_chunk *chunk)
{
    msgpack_sbuffer sbuf;
    msgpack_packer pck;
    int ret;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    /*
     * Compose a single Fluent Bit log record: [timestamp, map]
     * Using a simple positive integer timestamp keeps validation minimal.
     */
    msgpack_pack_array(&pck, 2);
    msgpack_pack_uint64(&pck, 0);
    msgpack_pack_map(&pck, 1);
    msgpack_pack_str(&pck, 3);
    msgpack_pack_str_body(&pck, "key", 3);
    msgpack_pack_str(&pck, 5);
    msgpack_pack_str_body(&pck, "value", 5);

    ret = cio_chunk_write(chunk, sbuf.data, sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);

    return ret;
}

static int init_test_config(struct flb_config *config,
                            struct flb_input_instance *in,
                            struct flb_input_plugin *plugin)
{
    int ret;

    memset(config, 0, sizeof(*config));
    mk_list_init(&config->outputs);
    mk_list_init(&config->inputs);

    /* Initialize environment (required by flb_input_instance_init) */
    config->env = flb_env_create();
    if (config->env == NULL) {
        return -1;
    }

    /* Create router context */
    config->router = flb_router_create(config);
    if (config->router == NULL) {
        flb_env_destroy(config->env);
        config->env = NULL;
        return -1;
    }

    ret = flb_routes_mask_set_size(64, config->router);
    if (ret != 0) {
        flb_router_destroy(config->router);
        config->router = NULL;
        flb_env_destroy(config->env);
        config->env = NULL;
        return -1;
    }

    memset(in, 0, sizeof(*in));
    in->config = config;
    in->p = plugin;
    in->log_level = FLB_LOG_OFF;
    snprintf(in->name, sizeof(in->name), "dummy.0");
    in->routable = FLB_TRUE;
    mk_list_init(&in->_head);
    mk_list_init(&in->chunks);
    mk_list_init(&in->chunks_up);
    mk_list_init(&in->chunks_down);
    mk_list_init(&in->tasks);
    mk_list_init(&in->collectors);
    cfl_list_init(&in->routes_direct);
    cfl_list_init(&in->routes);

    /* Add instance to config inputs list (required by flb_input_instance_destroy) */
    mk_list_add(&in->_head, &config->inputs);

    /* Initialize properties list (required by flb_input_instance_init) */
    mk_list_init(&in->properties);
    mk_list_init(&in->net_properties);

    /* Initialize hash tables for chunks (required by flb_input_chunk_destroy) */
    in->ht_log_chunks = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 512, 0);
    if (!in->ht_log_chunks) {
        return -1;
    }

    in->ht_metric_chunks = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 512, 0);
    if (!in->ht_metric_chunks) {
        flb_hash_table_destroy(in->ht_log_chunks);
        in->ht_log_chunks = NULL;
        return -1;
    }

    in->ht_trace_chunks = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 512, 0);
    if (!in->ht_trace_chunks) {
        flb_hash_table_destroy(in->ht_log_chunks);
        flb_hash_table_destroy(in->ht_metric_chunks);
        in->ht_log_chunks = NULL;
        in->ht_metric_chunks = NULL;
        return -1;
    }

    in->ht_profile_chunks = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE, 512, 0);
    if (!in->ht_profile_chunks) {
        flb_hash_table_destroy(in->ht_log_chunks);
        flb_hash_table_destroy(in->ht_metric_chunks);
        flb_hash_table_destroy(in->ht_trace_chunks);
        in->ht_log_chunks = NULL;
        in->ht_metric_chunks = NULL;
        in->ht_trace_chunks = NULL;
        return -1;
    }

    return 0;
}

static int add_test_output(struct flb_config *config,
                           struct flb_output_instance *out,
                           struct flb_output_plugin *plugin,
                           int id,
                           const char *alias)
{
    memset(out, 0, sizeof(*out));
    out->config = config;
    out->p = plugin;
    out->log_level = FLB_LOG_OFF;
    out->id = id;
    snprintf(out->name, sizeof(out->name), "%s.%d",
             plugin->name ? plugin->name : "out", id);

    if (alias) {
        out->alias = flb_strdup(alias);
        if (!out->alias) {
            return -1;
        }
    }

    mk_list_init(&out->_head);
    mk_list_init(&out->properties);
    mk_list_init(&out->net_properties);
    mk_list_init(&out->upstreams);
    mk_list_init(&out->flush_list);
    mk_list_init(&out->flush_list_destroy);

    mk_list_add(&out->_head, &config->outputs);

    return 0;
}

static void cleanup_test_output(struct flb_output_instance *out)
{
    if (out->alias) {
        flb_free(out->alias);
        out->alias = NULL;
    }
}

static void cleanup_test_routing_scenario(struct flb_input_chunk *ic,
                                          struct flb_output_instance *stdout_one,
                                          struct flb_output_instance *stdout_two,
                                          struct flb_output_instance *http_out,
                                          struct flb_input_instance *in,
                                          struct flb_config *config,
                                          struct cio_chunk *chunk,
                                          struct cio_ctx *ctx,
                                          int config_ready,
                                          const char *stream_path)
{
    if (ic) {
        flb_input_chunk_destroy(ic, FLB_TRUE);
    }

    cleanup_test_output(stdout_one);
    cleanup_test_output(stdout_two);
    cleanup_test_output(http_out);

    if (config_ready == FLB_TRUE) {
        flb_input_instance_exit(in, config);

        /* Manual cleanup for stack-allocated instance */
        /* Remove from list first (before destroying hash tables) */
        mk_list_del(&in->_head);

        /* Destroy hash tables */
        if (in->ht_log_chunks) {
            flb_hash_table_destroy(in->ht_log_chunks);
            in->ht_log_chunks = NULL;
        }
        if (in->ht_metric_chunks) {
            flb_hash_table_destroy(in->ht_metric_chunks);
            in->ht_metric_chunks = NULL;
        }
        if (in->ht_trace_chunks) {
            flb_hash_table_destroy(in->ht_trace_chunks);
            in->ht_trace_chunks = NULL;
        }
        if (in->ht_profile_chunks) {
            flb_hash_table_destroy(in->ht_profile_chunks);
            in->ht_profile_chunks = NULL;
        }

        /* Release properties */
        flb_kv_release(&in->properties);
        flb_kv_release(&in->net_properties);

        /* Destroy metrics (created by flb_input_instance_init) */
#ifdef FLB_HAVE_METRICS
        if (in->cmt) {
            cmt_destroy(in->cmt);
            in->cmt = NULL;
        }
        if (in->metrics) {
            flb_metrics_destroy(in->metrics);
            in->metrics = NULL;
        }
#endif

        /* Destroy config map if created */
        if (in->tls_config_map) {
            flb_config_map_destroy(in->tls_config_map);
            in->tls_config_map = NULL;
        }
        if (in->net_config_map) {
            flb_config_map_destroy(in->net_config_map);
            in->net_config_map = NULL;
        }

        if (config->router) {
            flb_router_destroy(config->router);
            config->router = NULL;
        }
        if (config->env) {
            flb_env_destroy(config->env);
            config->env = NULL;
        }
    }

    if (chunk) {
        cio_chunk_close(chunk, CIO_TRUE);
    }

    if (ctx) {
        cio_destroy(ctx);
    }

    cio_utils_recursive_delete(stream_path);
}

static int write_legacy_chunk_metadata(struct cio_chunk *chunk,
                                       int event_type,
                                       const char *tag,
                                       int tag_len)
{
    int ret;
    int meta_size;
    char *meta;

    meta_size = FLB_INPUT_CHUNK_META_HEADER + tag_len;
    meta = flb_malloc(meta_size);
    if (!meta) {
        flb_errno();
        return -1;
    }

    meta[0] = FLB_INPUT_CHUNK_MAGIC_BYTE_0;
    meta[1] = FLB_INPUT_CHUNK_MAGIC_BYTE_1;

    if (event_type == FLB_INPUT_LOGS) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_LOGS;
    }
    else if (event_type == FLB_INPUT_METRICS) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_METRICS;
    }
    else if (event_type == FLB_INPUT_TRACES) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_TRACES;
    }
    else if (event_type == FLB_INPUT_PROFILES) {
        meta[2] = FLB_INPUT_CHUNK_TYPE_PROFILES;
    }
    else {
        meta[2] = FLB_INPUT_CHUNK_TYPE_LOGS;
    }

    meta[3] = 0;

    memcpy(meta + FLB_INPUT_CHUNK_META_HEADER, tag, tag_len);

    ret = cio_meta_write(chunk, meta, meta_size);

    flb_free(meta);

    return ret;
}

static void test_chunk_metadata_direct_routes()
{
    struct cio_options opts;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct flb_input_chunk ic;
    struct flb_chunk_direct_route output_routes[2];
    struct flb_chunk_direct_route *loaded_routes;
    char *content_buf;
    const char *tag_buf;
    const char *tag_string;
    const char payload[] = "direct route payload validation string";
    int tag_len;
    int route_count;
    int ret;
    int err;
    int expected_tag_len;
    size_t content_size;
    size_t payload_size;

    payload_size = sizeof(payload) - 1;
    tag_string = "test.tag";
    expected_tag_len = strlen(tag_string);

    cio_utils_recursive_delete(TEST_STREAM_PATH);
    memset(&opts, 0, sizeof(opts));
    cio_options_init(&opts);
    opts.root_path = TEST_STREAM_PATH;
    opts.flags = CIO_OPEN;
    ctx = cio_create(&opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        return;
    }

    stream = cio_stream_create(ctx, "direct", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);
    if (!stream) {
        cio_destroy(ctx);
        return;
    }

    chunk = cio_chunk_open(ctx, stream, "meta", CIO_OPEN, 1024, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        cio_destroy(ctx);
        return;
    }

    ret = cio_chunk_is_up(chunk);
    if (ret == CIO_FALSE) {
        ret = cio_chunk_up_force(chunk);
        TEST_CHECK(ret == CIO_OK);
    }

    tag_len = expected_tag_len;
    ret = write_legacy_chunk_metadata(chunk, FLB_INPUT_LOGS,
                                      tag_string, tag_len);
    TEST_CHECK(ret == 0);

    ret = cio_chunk_write(chunk, payload, payload_size);
    TEST_CHECK(ret == 0);

    ret = cio_chunk_get_content(chunk, &content_buf, &content_size);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        TEST_CHECK(content_buf != NULL);
        TEST_CHECK(content_size == payload_size);
        if (content_size == payload_size) {
            TEST_CHECK(memcmp(content_buf, payload, payload_size) == 0);
        }
    }

    memset(output_routes, 0, sizeof(output_routes));

    output_routes[0].id = 511;
    output_routes[0].label = "alpha";
    output_routes[0].label_length = 5;
    output_routes[0].label_is_alias = FLB_TRUE;
    output_routes[0].plugin_name = "stdout";
    output_routes[0].plugin_name_length = 6;
    output_routes[1].id = 70000;
    output_routes[1].label = "beta";
    output_routes[1].label_length = 4;
    output_routes[1].label_is_alias = FLB_FALSE;
    output_routes[1].plugin_name = "http";
    output_routes[1].plugin_name_length = 4;
    ret = flb_input_chunk_write_header_v2(chunk,
                                          FLB_INPUT_LOGS,
                                          (char *) tag_string,
                                          tag_len,
                                          output_routes,
                                          2);
    TEST_CHECK(ret == 0);

    memset(&ic, 0, sizeof(ic));
    ic.chunk = chunk;

    TEST_CHECK(flb_input_chunk_has_direct_routes(&ic) == FLB_TRUE);

    ret = cio_chunk_get_content(chunk, &content_buf, &content_size);
    TEST_CHECK(ret == 0);
    if (ret == 0) {
        TEST_CHECK(content_buf != NULL);
        TEST_CHECK(content_size == payload_size);
        if (content_size == payload_size) {
            TEST_CHECK(memcmp(content_buf, payload, payload_size) == 0);
        }
    }

    ret = flb_input_chunk_get_direct_routes(&ic, &loaded_routes, &route_count);
    TEST_CHECK(ret == 0);
    TEST_CHECK(route_count == 2);
    if (ret == 0 && route_count == 2) {
        TEST_CHECK(loaded_routes != NULL);
        if (loaded_routes) {
            TEST_CHECK(loaded_routes[0].id == 511);
            TEST_CHECK(loaded_routes[1].id == 70000);
            TEST_CHECK(loaded_routes[0].label != NULL);
            TEST_CHECK(loaded_routes[1].label != NULL);
            if (loaded_routes[0].label && loaded_routes[1].label) {
                TEST_CHECK(strcmp(loaded_routes[0].label, "alpha") == 0);
                TEST_CHECK(strcmp(loaded_routes[1].label, "beta") == 0);
            }
            TEST_CHECK(loaded_routes[0].label_is_alias != 0);
            TEST_CHECK(loaded_routes[1].label_is_alias == 0);
            TEST_CHECK(loaded_routes[0].plugin_name != NULL);
            TEST_CHECK(loaded_routes[1].plugin_name != NULL);
            if (loaded_routes[0].plugin_name && loaded_routes[1].plugin_name) {
                TEST_CHECK(strcmp(loaded_routes[0].plugin_name, "stdout") == 0);
                TEST_CHECK(strcmp(loaded_routes[1].plugin_name, "http") == 0);
            }
            flb_input_chunk_destroy_direct_routes(loaded_routes, route_count);
        }
    }

    ret = flb_input_chunk_get_tag(&ic, &tag_buf, &tag_len);
    TEST_CHECK(ret == 0);
    TEST_CHECK(tag_len == expected_tag_len);
    if (ret == 0 && tag_len == expected_tag_len) {
        TEST_CHECK(memcmp(tag_buf, tag_string, expected_tag_len) == 0);
    }

    cio_chunk_close(chunk, CIO_TRUE);
    cio_destroy(ctx);
    cio_utils_recursive_delete(TEST_STREAM_PATH);
}

static void test_chunk_restore_alias_plugin_match_multiple()
{
    struct cio_options opts;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct flb_input_chunk *ic;
    struct flb_config config;
    struct flb_input_instance in;
    struct flb_input_plugin input_plugin;
    struct flb_output_instance stdout_one;
    struct flb_output_instance stdout_two;
    struct flb_output_instance http_out;
    struct flb_output_plugin stdout_plugin;
    struct flb_output_plugin http_plugin;
    struct flb_chunk_direct_route route;
    const char *tag_string;
    int tag_len;
    int ret;
    int err;
    int config_ready;

    ctx = NULL;
    stream = NULL;
    chunk = NULL;
    ic = NULL;
    config_ready = FLB_FALSE;
    tag_string = "test.tag";
    tag_len = (int) strlen(tag_string);

    cio_utils_recursive_delete(TEST_STREAM_PATH_MATCH);
    memset(&opts, 0, sizeof(opts));
    cio_options_init(&opts);
    opts.root_path = TEST_STREAM_PATH_MATCH;
    opts.flags = CIO_OPEN;

    ctx = cio_create(&opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        return;
    }

    stream = cio_stream_create(ctx, "direct", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);
    if (!stream) {
        goto cleanup;
    }

    chunk = cio_chunk_open(ctx, stream, "meta", CIO_OPEN, 1024, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        goto cleanup;
    }

    ret = cio_chunk_is_up(chunk);
    if (ret == CIO_FALSE) {
        ret = cio_chunk_up_force(chunk);
        TEST_CHECK(ret == CIO_OK);
        if (ret != CIO_OK) {
            goto cleanup;
        }
    }

    ret = write_legacy_chunk_metadata(chunk, FLB_INPUT_LOGS,
                                      tag_string, tag_len);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }

    ret = write_test_log_payload(chunk);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }

    memset(&route, 0, sizeof(route));
    route.id = 25;
    route.label = "shared";
    route.label_length = 6;
    route.label_is_alias = FLB_TRUE;
    route.plugin_name = "stdout";
    route.plugin_name_length = 6;

    ret = flb_input_chunk_write_header_v2(chunk,
                                          FLB_INPUT_LOGS,
                                          (char *) tag_string,
                                          tag_len,
                                          &route,
                                          1);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }

    memset(&input_plugin, 0, sizeof(input_plugin));
    input_plugin.name = (char *) "dummy";
    memset(&stdout_plugin, 0, sizeof(stdout_plugin));
    stdout_plugin.name = (char *) "stdout";
    memset(&http_plugin, 0, sizeof(http_plugin));
    http_plugin.name = (char *) "http";

    ret = init_test_config(&config, &in, &input_plugin);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }
    config_ready = FLB_TRUE;

#ifdef FLB_HAVE_METRICS
    cmt_initialize();
#endif

    ret = flb_input_instance_init(&in, &config);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }

    ret = add_test_output(&config, &stdout_one, &stdout_plugin, 1, "shared");
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }

    ret = add_test_output(&config, &stdout_two, &stdout_plugin, 2, "shared");
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }

    ret = add_test_output(&config, &http_out, &http_plugin, 3, "shared");
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }

    ic = flb_input_chunk_map(&in, FLB_INPUT_LOGS, chunk);
    TEST_CHECK(ic != NULL);
    if (!ic) {
        goto cleanup;
    }

    chunk = NULL;

    TEST_CHECK(flb_routes_mask_get_bit(ic->routes_mask,
                                       stdout_one.id,
                                       config.router) == 1);
    TEST_CHECK(flb_routes_mask_get_bit(ic->routes_mask,
                                       stdout_two.id,
                                       config.router) == 1);
    TEST_CHECK(flb_routes_mask_get_bit(ic->routes_mask,
                                       http_out.id,
                                       config.router) == 0);

cleanup:
    cleanup_test_routing_scenario(ic, &stdout_one, &stdout_two, &http_out,
                                  &in, &config, chunk, ctx, config_ready,
                                  TEST_STREAM_PATH_MATCH);
}

static void test_chunk_restore_alias_plugin_null_matches_all()
{
    struct cio_options opts;
    struct cio_ctx *ctx;
    struct cio_stream *stream;
    struct cio_chunk *chunk;
    struct flb_input_chunk *ic;
    struct flb_config config;
    struct flb_input_instance in;
    struct flb_input_plugin input_plugin;
    struct flb_output_instance stdout_one;
    struct flb_output_instance stdout_two;
    struct flb_output_instance http_out;
    struct flb_output_plugin stdout_plugin;
    struct flb_output_plugin http_plugin;
    struct flb_chunk_direct_route route;
    const char *tag_string;
    int tag_len;
    int ret;
    int err;
    int config_ready;

    ctx = NULL;
    stream = NULL;
    chunk = NULL;
    ic = NULL;
    config_ready = FLB_FALSE;
    tag_string = "test.tag";
    tag_len = (int) strlen(tag_string);

    cio_utils_recursive_delete(TEST_STREAM_PATH_NULL);
    memset(&opts, 0, sizeof(opts));
    cio_options_init(&opts);
    opts.root_path = TEST_STREAM_PATH_NULL;
    opts.flags = CIO_OPEN;

    ctx = cio_create(&opts);
    TEST_CHECK(ctx != NULL);
    if (!ctx) {
        return;
    }

    stream = cio_stream_create(ctx, "direct", CIO_STORE_FS);
    TEST_CHECK(stream != NULL);
    if (!stream) {
        goto cleanup;
    }

    chunk = cio_chunk_open(ctx, stream, "meta", CIO_OPEN, 1024, &err);
    TEST_CHECK(chunk != NULL);
    if (!chunk) {
        goto cleanup;
    }

    ret = cio_chunk_is_up(chunk);
    if (ret == CIO_FALSE) {
        ret = cio_chunk_up_force(chunk);
        TEST_CHECK(ret == CIO_OK);
        if (ret != CIO_OK) {
            goto cleanup;
        }
    }

    ret = write_legacy_chunk_metadata(chunk, FLB_INPUT_LOGS,
                                      tag_string, tag_len);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }

    ret = write_test_log_payload(chunk);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }

    memset(&route, 0, sizeof(route));
    route.id = 30;
    route.label = "shared";
    route.label_length = 6;
    route.label_is_alias = FLB_TRUE;
    route.plugin_name = NULL;
    route.plugin_name_length = 0;

    ret = flb_input_chunk_write_header_v2(chunk,
                                          FLB_INPUT_LOGS,
                                          (char *) tag_string,
                                          tag_len,
                                          &route,
                                          1);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }

    memset(&input_plugin, 0, sizeof(input_plugin));
    input_plugin.name = (char *) "dummy";
    memset(&stdout_plugin, 0, sizeof(stdout_plugin));
    stdout_plugin.name = (char *) "stdout";
    memset(&http_plugin, 0, sizeof(http_plugin));
    http_plugin.name = (char *) "http";

    ret = init_test_config(&config, &in, &input_plugin);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }
    config_ready = FLB_TRUE;

#ifdef FLB_HAVE_METRICS
    cmt_initialize();
#endif

    ret = flb_input_instance_init(&in, &config);
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }

    ret = add_test_output(&config, &stdout_one, &stdout_plugin, 4, "shared");
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }

    ret = add_test_output(&config, &stdout_two, &stdout_plugin, 5, "shared");
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }

    ret = add_test_output(&config, &http_out, &http_plugin, 6, "shared");
    TEST_CHECK(ret == 0);
    if (ret != 0) {
        goto cleanup;
    }

    ic = flb_input_chunk_map(&in, FLB_INPUT_LOGS, chunk);
    TEST_CHECK(ic != NULL);
    if (!ic) {
        goto cleanup;
    }

    chunk = NULL;

    TEST_CHECK(flb_routes_mask_get_bit(ic->routes_mask,
                                       stdout_one.id,
                                       config.router) == 1);
    TEST_CHECK(flb_routes_mask_get_bit(ic->routes_mask,
                                       stdout_two.id,
                                       config.router) == 1);
    TEST_CHECK(flb_routes_mask_get_bit(ic->routes_mask,
                                       http_out.id,
                                       config.router) == 1);

cleanup:
    cleanup_test_routing_scenario(ic, &stdout_one, &stdout_two, &http_out,
                                  &in, &config, chunk, ctx, config_ready,
                                  TEST_STREAM_PATH_NULL);
}

TEST_LIST = {
    { "chunk_metadata_direct_routes", test_chunk_metadata_direct_routes },
    { "chunk_restore_alias_plugin_match_multiple", test_chunk_restore_alias_plugin_match_multiple },
    { "chunk_restore_alias_plugin_null_matches_all", test_chunk_restore_alias_plugin_null_matches_all },
    { 0 }
};
