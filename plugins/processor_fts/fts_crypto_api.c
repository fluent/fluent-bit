/* Fluent Bit: HMAC with opaque configuration key references, Apache-2.0. */
#include <string.h>
#include <fluent-bit/flb_env.h>
#include <fluent-bit/flb_hmac.h>
#include "fts.h"
#include "fts_crypto_api.h"

struct fts_secret {
    struct fts_secret *next;
    size_t length;
    char id[129];
    unsigned char bytes[];
};

static void zero_bytes(unsigned char *bytes, size_t length)
{
    volatile unsigned char *cursor;
    size_t i;

    cursor = bytes;
    for (i = 0; i < length; i++) {
        cursor[i] = 0;
    }
}

static int identifier(const char *text, size_t length, int environment)
{
    size_t i;
    unsigned char c;

    if (length == 0 || length > 128) {
        return 0;
    }
    for (i = 0; i < length; i++) {
        c = (unsigned char) text[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
            continue;
        }
        if (c >= '0' && c <= '9' && (!environment || i > 0)) {
            continue;
        }
        if (!environment && (c == '.' || c == '-')) {
            continue;
        }
        return 0;
    }
    return 1;
}

static struct fts_secret *lookup(struct fts_runtime *ctx, const char *name, size_t length)
{
    struct fts_secret *secret;

    for (secret = ctx->secret_keys; secret != NULL; secret = secret->next) {
        if (strlen(secret->id) == length && memcmp(secret->id, name, length) == 0) {
            return secret;
        }
    }
    return NULL;
}

int fts_crypto_initialize(lua_State *l, struct fts_runtime *ctx)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    struct fts_secret *secret;
    const char *key;
    size_t key_length;
    size_t id_length;
    size_t cost;
    size_t count;

    if (ctx->secret_refs == NULL) {
        return 0;
    }
    if (ctx->secret_refs->type != CFL_VARIANT_KVLIST || ctx->env == NULL) {
        return luaL_error(l, "invalid_configuration");
    }
    count = 0;
    cfl_list_foreach(head, &ctx->secret_refs->data.as_kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        id_length = cfl_sds_len(pair->key);
        if (++count > 16 || !identifier(pair->key, id_length, 0) ||
            pair->val->type != CFL_VARIANT_STRING ||
            !identifier(pair->val->data.as_string, cfl_sds_len(pair->val->data.as_string), 1) ||
            lookup(ctx, pair->key, id_length) != NULL) {
            return luaL_error(l, "invalid_configuration");
        }
        key = flb_env_get(ctx->env, pair->val->data.as_string);
        if (key == NULL) {
            return luaL_error(l, "invalid_configuration");
        }
        for (key_length = 0; key_length <= 4096 && key[key_length] != '\0'; key_length++) {
        }
        if (key_length == 0 || key_length > 4096) {
            return luaL_error(l, "invalid_configuration");
        }
        cost = sizeof(*secret) + key_length;
        if (cost > ctx->memory_limit || ctx->native_bytes > ctx->memory_limit - cost ||
            ctx->lua_bytes > ctx->memory_limit - cost - ctx->native_bytes) {
            return luaL_error(l, "budget_exceeded");
        }
        secret = flb_calloc(1, cost);
        if (secret == NULL) {
            return luaL_error(l, "budget_exceeded");
        }
        memcpy(secret->id, pair->key, id_length);
        secret->length = key_length;
        memcpy(secret->bytes, key, key_length);
        secret->next = ctx->secret_keys;
        ctx->secret_keys = secret;
        ctx->native_bytes += cost;
        ctx->native_allocated += cost;
    }
    return 0;
}

void fts_crypto_destroy(struct fts_runtime *ctx)
{
    struct fts_secret *secret;
    struct fts_secret *next;
    size_t cost;

    for (secret = ctx->secret_keys; secret != NULL; secret = next) {
        next = secret->next;
        cost = sizeof(*secret) + secret->length;
        zero_bytes(secret->bytes, secret->length);
        ctx->native_bytes -= cost;
        flb_free(secret);
    }
    ctx->secret_keys = NULL;
}

static int hmac_sha256(lua_State *l)
{
    struct fts_runtime *ctx;
    struct fts_secret *secret;
    void *allocator_data;
    const char *reference;
    const char *message;
    size_t reference_length;
    size_t message_length;
    size_t work;
    size_t i;
    unsigned char digest[32];
    char result[64];
    const char *hex;
    int ret;

    if (lua_type(l, 1) != LUA_TSTRING || lua_type(l, 2) != LUA_TSTRING) {
        return luaL_error(l, "wrong_type");
    }
    reference = luaL_checklstring(l, 1, &reference_length);
    message = luaL_checklstring(l, 2, &message_length);
    if (message_length > 1048576 || reference_length > 128) {
        return luaL_error(l, "invalid_parameter");
    }
    lua_getallocf(l, &allocator_data);
    ctx = allocator_data;
    secret = lookup(ctx, reference, reference_length);
    if (secret == NULL) {
        return luaL_error(l, "invalid_parameter");
    }
    work = message_length / 8 + 64;
    if (!ctx->jit) {
        if (ctx->instructions_left < 0 || work > (size_t) ctx->instructions_left) {
            ctx->instructions_left = 0;
            return luaL_error(l, "budget_exceeded");
        }
        ctx->instructions_left -= (int) work;
    }
    ret = flb_hmac_simple(FLB_HASH_SHA256, secret->bytes, secret->length,
                         (unsigned char *) message, message_length, digest, sizeof(digest));
    if (ret != FLB_CRYPTO_SUCCESS) {
        zero_bytes(digest, sizeof(digest));
        return luaL_error(l, "operation_failed");
    }
    hex = "0123456789abcdef";
    for (i = 0; i < sizeof(digest); i++) {
        result[i * 2] = hex[digest[i] >> 4];
        result[i * 2 + 1] = hex[digest[i] & 15];
    }
    zero_bytes(digest, sizeof(digest));
    lua_pushlstring(l, result, sizeof(result));
    zero_bytes((unsigned char *) result, sizeof(result));
    return 1;
}

void fts_crypto_register(lua_State *l)
{
    lua_pushcfunction(l, hmac_sha256);
    lua_setfield(l, -2, "hmac_sha256");
}
