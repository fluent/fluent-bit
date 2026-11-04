/* Fluent Bit - SPDX-License-Identifier: Apache-2.0 */

#include <fluent-bit.h>
#include <fluent-bit/flb_jsmn.h>
#include <fluent-bit/flb_oauth2.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_upstream_ha.h>
#include <fluent-bit/flb_utils.h>
#include "flb_tests_runtime.h"

static int fail_allocation;
static int allocation_count;
static int fail_tls;
static int contexts_created;
static int contexts_destroyed;
static int response_mode;
static int fail_metadata;
static int metadata_count;
static int fail_upstream;
static struct flb_config *resource_test_config;

static flb_sds_t resource_test_sds_create(const char *text)
{
    metadata_count++;
    if (metadata_count == fail_metadata) {
        return NULL;
    }
    return flb_sds_create(text);
}

static flb_sds_t resource_test_sds_create_size(size_t size)
{
    metadata_count++;
    if (metadata_count == fail_metadata) {
        return NULL;
    }
    return flb_sds_create_size(size);
}

static struct flb_upstream *resource_test_upstream_create(struct flb_config *config,
                                                          const char *host, int port,
                                                          int flags, struct flb_tls *tls)
{
    if (fail_upstream) {
        return NULL;
    }
    return flb_upstream_create(config, host, port, flags, tls);
}

static void *resource_test_calloc(size_t count, size_t size)
{
    allocation_count++;
    if (fail_allocation == allocation_count) {
        return NULL;
    }
    return flb_calloc(count, size);
}

static struct flb_tls *resource_test_tls_create(int mode, int verify, int debug,
                                               const char *vhost, const char *ca_path,
                                               const char *ca_file, const char *crt_file,
                                               const char *key_file, const char *key_passwd)
{
    struct flb_tls *tls;

    if (fail_tls) {
        return NULL;
    }
    tls = flb_tls_create(mode, verify, debug, vhost, ca_path, ca_file,
                         crt_file, key_file, key_passwd);
    if (tls) {
        contexts_created++;
    }
    return tls;
}

static int resource_test_tls_destroy(struct flb_tls *tls)
{
    struct mk_list *head;
    struct flb_stream *stream;

    mk_list_foreach(head, &resource_test_config->upstreams) {
        stream = mk_list_entry(head, struct flb_stream, _head);
        TEST_CHECK(stream->tls_context != tls);
    }
    contexts_destroyed++;
    return flb_tls_destroy(tls);
}

/*
 * Exercise the real private resource lifecycle without network or production
 * test hooks. Rename public symbols to keep the linked plugin unmodified.
 */
#define execute_ingest_csl_command resource_test_command
#define azure_kusto_generate_random_integer resource_test_random
#define azure_kusto_load_ingestion_resources resource_test_load
#define flb_azure_kusto_conf_create resource_test_conf_create
#define flb_azure_kusto_conf_destroy resource_test_conf_destroy
#define flb_calloc resource_test_calloc
#define flb_tls_create resource_test_tls_create
#define flb_tls_destroy resource_test_tls_destroy
#define flb_sds_create resource_test_sds_create
#define flb_sds_create_size resource_test_sds_create_size
#define flb_upstream_create resource_test_upstream_create
#include "../../plugins/out_azure_kusto/azure_kusto_conf.c"
#undef execute_ingest_csl_command
#undef azure_kusto_generate_random_integer
#undef azure_kusto_load_ingestion_resources
#undef flb_azure_kusto_conf_create
#undef flb_azure_kusto_conf_destroy
#undef flb_calloc
#undef flb_tls_create
#undef flb_tls_destroy
#undef flb_sds_create
#undef flb_sds_create_size
#undef flb_upstream_create

flb_sds_t resource_test_command(struct flb_azure_kusto *ctx, const char *command)
{
    if (strcmp(command, ".get ingestion resources") == 0) {
        if (response_mode == 2) {
            return flb_sds_create("{\"Tables\":[{\"Rows\":[]}]}");
        }
        if (response_mode == 3) {
            return flb_sds_create("{\"Tables\":[{\"Rows\":["
                "[\"TempStorage\",\"https://blob.local/blob?sig=local\"],"
                "[\"SecuredReadyForAggregationQueue\",\"https://queue.local/no-query\"]]}]}");
        }
        return flb_sds_create("{\"Tables\":[{\"Rows\":["
            "[\"TempStorage\",\"https://blob.local/blob0?sig=local\"],"
            "[\"TempStorage\",\"https://blob.local/blob1?sig=local\"],"
            "[\"SecuredReadyForAggregationQueue\",\"https://queue.local/queue?sig=local\"]]}]}");
    }
    if (response_mode == 1) {
        return NULL;
    }
    return flb_sds_create("{\"Tables\":[{\"TableName\":\"Table_0\","
        "\"Columns\":[{\"ColumnName\":\"AuthorizationContext\","
        "\"DataType\":\"String\",\"ColumnType\":\"string\"}],\"Rows\":[[\"local\"]]}]}");
}

static void check_nodes(struct flb_upstream_ha *ha, struct flb_tls *tls)
{
    struct mk_list *head;
    struct flb_upstream_node *node;

    TEST_CHECK(ha != NULL);
    if (!ha) {
        return;
    }
    mk_list_foreach(head, &ha->nodes) {
        node = mk_list_entry(head, struct flb_upstream_node, _head);
        TEST_CHECK(node->tls == NULL);
        TEST_CHECK(node->tls_enabled == FLB_TRUE);
        TEST_CHECK(node->u->base.tls_context == tls);
        TEST_CHECK(flb_upstream_node_get_property("sas", node) != NULL);
    }
}

static flb_ctx_t *resource_test_init(struct flb_azure_kusto *ctx,
                                    struct flb_azure_kusto_resources *resources)
{
    flb_ctx_t *flb;
    int id;

    flb = flb_create();
    TEST_ASSERT(flb != NULL);
    id = flb_output(flb, "azure_kusto", NULL);
    TEST_ASSERT(id >= 0);
    memset(ctx, 0, sizeof(*ctx));
    memset(resources, 0, sizeof(*resources));
    ctx->config = flb->config;
    resource_test_config = flb->config;
    ctx->ins = flb_output_get_instance(flb->config, id);
    ctx->resources = resources;
    /* Keep jitter-adjusted intervals positive; load_time=0 then forces reload. */
    ctx->ingestion_resources_refresh_interval = 601;
    ctx->ins->tls = flb_tls_create(FLB_TLS_CLIENT_MODE, FLB_TRUE, 0,
                                  NULL, NULL, NULL, NULL, NULL, NULL);
    TEST_ASSERT(ctx->ins->tls != NULL);
    flb_tls_set_verify_hostname(ctx->ins->tls, FLB_TRUE);
    pthread_mutex_init(&ctx->resources_mutex, NULL);
    contexts_created = 0;
    contexts_destroyed = 0;
    fail_allocation = 0;
    allocation_count = 0;
    fail_tls = 0;
    response_mode = 0;
    fail_metadata = 0;
    metadata_count = 0;
    fail_upstream = 0;
    return flb;
}

static void resource_test_exit(flb_ctx_t *flb, struct flb_azure_kusto *ctx)
{
    flb_azure_kusto_resources_clear(ctx->resources);
    TEST_CHECK(contexts_created == contexts_destroyed);
    pthread_mutex_destroy(&ctx->resources_mutex);
    flb_tls_destroy(ctx->ins->tls);
    ctx->ins->tls = NULL;
    resource_test_config = NULL;
    flb_destroy(flb);
}

static void test_resource_tls_rotation(void)
{
    struct flb_azure_kusto ctx;
    struct flb_azure_kusto_resources resources;
    struct flb_tls *first;
    struct flb_tls *second;
    flb_ctx_t *flb;
    int ret;

    flb = resource_test_init(&ctx, &resources);
    ret = resource_test_load(&ctx, ctx.config);
    TEST_ASSERT(ret == 0);
    first = resources.tls;
    TEST_CHECK(first != ctx.ins->tls);
    TEST_CHECK(first->verify == FLB_TRUE);
    TEST_CHECK(first->verify_hostname == FLB_TRUE);
    check_nodes(resources.blob_ha, first);
    check_nodes(resources.queue_ha, first);
    TEST_CHECK(contexts_created == 1);
    TEST_CHECK(contexts_destroyed == 0);

    resources.load_time = 0;
    TEST_ASSERT(resource_test_load(&ctx, ctx.config) == 0);
    second = resources.tls;
    TEST_CHECK(second != first);
    TEST_CHECK(resources.old_tls == first);
    check_nodes(resources.old_blob_ha, first);
    check_nodes(resources.old_queue_ha, first);
    TEST_CHECK(contexts_destroyed == 0);

    resources.load_time = 0;
    TEST_ASSERT(resource_test_load(&ctx, ctx.config) == 0);
    TEST_CHECK(resources.old_tls == second);
    TEST_CHECK(contexts_created == 3);
    TEST_CHECK(contexts_destroyed == 1);
    check_nodes(resources.blob_ha, resources.tls);
    check_nodes(resources.queue_ha, resources.tls);
    resource_test_exit(flb, &ctx);
}

static void test_resource_tls_failure(void)
{
    struct flb_azure_kusto ctx;
    struct flb_azure_kusto_resources resources;
    struct flb_tls *first;
    flb_ctx_t *flb;
    int mode;
    int allocation;

    flb = resource_test_init(&ctx, &resources);
    TEST_ASSERT(resource_test_load(&ctx, ctx.config) == 0);
    first = resources.tls;
    resources.load_time = 0;
    resources.loading_in_progress = FLB_TRUE;
    TEST_CHECK(resource_test_load(&ctx, ctx.config) == -1);
    TEST_CHECK(resources.loading_in_progress == FLB_TRUE);
    TEST_CHECK(contexts_created == 1);
    resources.loading_in_progress = FLB_FALSE;
    for (mode = 1; mode <= 3; mode++) {
        response_mode = mode;
        resources.load_time = 0;
        TEST_CHECK(resource_test_load(&ctx, ctx.config) == -1);
        TEST_CHECK(resources.tls == first);
        TEST_CHECK(resources.loading_in_progress == FLB_FALSE);
        TEST_CHECK(contexts_created - contexts_destroyed == 1);
        check_nodes(resources.blob_ha, first);
    }
    response_mode = 0;
    fail_tls = 1;
    TEST_CHECK(resource_test_load(&ctx, ctx.config) == -1);
    TEST_CHECK(resources.tls == first);
    fail_tls = 0;

    /* Resource tokens, three node wrappers, then identity-token parsing. */
    for (allocation = 1; allocation <= 5; allocation++) {
        allocation_count = 0;
        fail_allocation = allocation;
        TEST_CHECK(resource_test_load(&ctx, ctx.config) == -1);
        TEST_CHECK(resources.tls == first);
        TEST_CHECK(contexts_created - contexts_destroyed == 1);
    }
    fail_allocation = 0;
    /* Resource URI plus host, port and name for each node. */
    for (allocation = 1; allocation <= 10; allocation++) {
        metadata_count = 0;
        fail_metadata = allocation;
        TEST_CHECK(resource_test_load(&ctx, ctx.config) == -1);
        TEST_CHECK(resources.tls == first);
        TEST_CHECK(contexts_created - contexts_destroyed == 1);
    }
    fail_metadata = 0;
    fail_upstream = 1;
    TEST_CHECK(resource_test_load(&ctx, ctx.config) == -1);
    TEST_CHECK(contexts_created - contexts_destroyed == 1);
    fail_upstream = 0;
    TEST_CHECK(resource_test_load(&ctx, ctx.config) == 0);
    TEST_CHECK(resources.old_tls == first);
    resource_test_exit(flb, &ctx);
}

static void test_resource_tls_policy(void)
{
    struct flb_azure_kusto ctx;
    struct flb_azure_kusto_resources resources;
    struct flb_tls *other;
    flb_ctx_t *flb;

    flb = resource_test_init(&ctx, &resources);
    TEST_ASSERT(resource_test_load(&ctx, ctx.config) == 0);
    ctx.ins->tls->verify = FLB_FALSE;
    flb_tls_set_verify_hostname(ctx.ins->tls, FLB_FALSE);
    ctx.ins->tls->vhost = flb_strdup("override.local");
    ctx.ins->tls->ca_file = flb_strdup("not-a-resource-ca.pem");
    ctx.ins->tls->crt_file = flb_strdup("not-a-resource-client.pem");
    ctx.ins->tls->key_file = flb_strdup("not-a-resource-key.pem");
    other = resource_tls_create(&ctx);
    TEST_ASSERT(other != NULL);
    TEST_CHECK(other != resources.tls);
    TEST_CHECK(other->verify == FLB_FALSE);
    TEST_CHECK(other->verify_hostname == FLB_FALSE);
    TEST_CHECK(resources.tls->verify == FLB_TRUE);
    TEST_CHECK(resources.tls->verify_hostname == FLB_TRUE);
    TEST_CHECK(resources.tls->vhost == NULL);
    TEST_CHECK(strcmp(other->vhost, "override.local") == 0);
    TEST_CHECK(other->ca_path == NULL);
    TEST_CHECK(other->ca_file == NULL);
    TEST_CHECK(other->crt_file == NULL);
    TEST_CHECK(other->key_file == NULL);
    resource_test_tls_destroy(other);
    resource_test_exit(flb, &ctx);
}

TEST_LIST = {
    {"resource_tls_rotation", test_resource_tls_rotation},
    {"resource_tls_failure", test_resource_tls_failure},
    {"resource_tls_policy", test_resource_tls_policy},
    {NULL, NULL}
};
