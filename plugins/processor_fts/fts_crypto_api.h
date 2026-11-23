/* Fluent Bit: opaque script key references, Apache-2.0. */
#ifndef FLB_FTS_CRYPTO_API_H
#define FLB_FTS_CRYPTO_API_H

#include <fluent-bit/flb_luajit.h>

struct fts_runtime;
struct fts_secret;

/* Runtime integration adds to fts_runtime:
 * struct cfl_variant *secret_refs;
 * struct fts_secret *secret_keys;
 * struct flb_env *env;
 * Call initialize within protected initialize_policy; destroy after closing VM.
 * Config secret_refs maps opaque reference IDs to environment variable names.
 */
int fts_crypto_initialize(lua_State *l, struct fts_runtime *ctx);
void fts_crypto_destroy(struct fts_runtime *ctx);
void fts_crypto_register(lua_State *l);
#endif
