/* Fluent Bit: deterministic typed-script hashing, Apache-2.0. */
#include <inttypes.h>
#include <stdio.h>
#include <math.h>
#include <cfl/cfl_hash.h>
#include "fts.h"

/* Algorithm contract: XXH3-64, seed zero, 16 lowercase hexadecimal digits.
 * This is a noncryptographic fingerprint, never a pseudonymization primitive. */
static uint64_t digest_value(lua_State *l)
{
    struct fts_runtime *ctx;
    void *allocator_data;
    const char *input;
    size_t length;
    size_t work;
    uint64_t digest;

    if (lua_type(l, 1) != LUA_TSTRING) {
        luaL_error(l, "wrong_type");
        return 0;
    }
    input = luaL_checklstring(l, 1, &length);
    if (length > 1048576) {
        luaL_error(l, "invalid_parameter");
        return 0;
    }
    lua_getallocf(l, &allocator_data);
    ctx = allocator_data;
    work = length / 8 + 1;
    if (!ctx->jit) {
        if (ctx->instructions_left < 0 || work > (size_t) ctx->instructions_left) {
            ctx->instructions_left = 0;
            luaL_error(l, "budget_exceeded");
            return 0;
        }
        ctx->instructions_left -= (int) work;
    }
    digest = XXH3_64bits_withSeed(input, length, 0);
    return digest;
}

static int hash64(lua_State *l)
{
    uint64_t digest;
    char result[17];

    digest = digest_value(l);
    snprintf(result, sizeof(result), "%016" PRIx64, digest);
    lua_pushlstring(l, result, 16);
    return 1;
}

static int hash64_mod(lua_State *l)
{
    lua_Number modulus;
    uint64_t digest;
    uint64_t remainder;

    if (lua_type(l, 2) != LUA_TNUMBER) {
        return luaL_error(l, "wrong_type");
    }
    modulus = lua_tonumber(l, 2);
    if (!isfinite(modulus) || modulus < 1 || modulus > 1000000000 || floor(modulus) != modulus) {
        return luaL_error(l, "invalid_parameter");
    }
    digest = digest_value(l);
    remainder = digest % (uint64_t) modulus;
    lua_pushnumber(l, (lua_Number) remainder);
    return 1;
}

/* The private fluentbit module is on the stack. */
void fts_hash_register(lua_State *l)
{
    lua_pushcfunction(l, hash64);
    lua_setfield(l, -2, "hash64");
    lua_pushcfunction(l, hash64_mod);
    lua_setfield(l, -2, "hash64_mod");
    lua_pushliteral(l, "xxh3-64-v1-seed0");
    lua_setfield(l, -2, "hash64_algorithm");
}
